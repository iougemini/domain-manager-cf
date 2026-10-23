// 免费域名实时查询
//
// 背景：内置白名单里原先只用 'Auto-Renewal' 占位，拿不到真实到期日，
// 于是所有免费域名都被排除在到期告警之外。实际上两家服务商都提供公开查询接口：
//
//   DigitalPlat（us.kg / dpdns.org / xx.kg / qzz.io / qd.je）
//     RDAP over HTTPS，返回结构化 JSON
//     GET https://rdap.digitalplat.org/domain/{domain}
//
//   DNSHE（us.ci / cc.cd / new.tg / de5.net / ...）
//     GET https://api005.dnshe.com/index.php?m=domain_hub&endpoint=whois&domain={domain}
//     公共模式无需 Key（按 IP 限速 30 次/分钟）；强制校验时需 X-API-Key / X-API-Secret
//
//   pp.ua
//     WHOIS over TCP，whois.pp.ua:43，发送 "domain\r\n" 读纯文本
//     Workers 侧通道由 cloudflare:sockets 提供，见 services/tcp-whois.js
//
// 设计约束：
// 1. 解析逻辑做成纯函数导出，单测直接喂样例 JSON，不需要 mock fetch
// 2. 查询失败一律返回 { error }，绝不抛异常——免费域名查询失败必须能降级回
//    注册表元数据，否则一个第三方接口挂掉就会拖垮整页刷新
// 3. 只有拿到真实到期日才算成功；拿不到就返回 null，让调用方回退

/**
 * 统一成 YYYY-MM-DD。
 * 兼容 '2024-05-30T00:00:00Z'、'2025-01-10 08:30:00' 两种格式。
 *
 * 年份上限放到 9999 是有意为之：DNSHE 把子域名升级为永久后，接口返回的到期日
 * 是 2999-12-31 这类"哨兵日期"。原来的 2100 上限会把它当成非法值丢掉，
 * 结果永久域名在页面上显示成「待设置」——比显示错误日期更误导人。
 */
export function toYmd(value) {
  if (!value) return null;
  const m = String(value).match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return null;

  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
  if (y < 1985 || y > 9999) return null;

  return `${m[1]}-${m[2]}-${m[3]}`;
}

/**
 * 永久域名的判定阈值。
 * 2900 是个宽松的哨兵线：DNSHE 用 2999，也有注册局用 9999，
 * 正常续期的域名不可能超过这个年份。
 */
export const PERMANENT_YEAR = 2900;

export function isPermanentDate(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(value || ''));
  if (!m) return false;
  return Number(m[1]) >= PERMANENT_YEAR;
}

/** 把到期日字段拆成 { expirationDate, isPermanent } */
function expiryOf(value) {
  const expirationDate = toYmd(value) || 'Unknown';
  return {
    expirationDate,
    isPermanent: expirationDate !== 'Unknown' && isPermanentDate(expirationDate)
  };
}

/** 从 RDAP 的 entities 里取 registrar 的显示名 */
export function findRegistrar(entities) {
  for (const ent of entities || []) {
    if (!ent || !Array.isArray(ent.roles) || !ent.roles.includes('registrar')) continue;

    // vcardArray 形如 ['vcard', [['fn', {}, 'text', 'DigitalPlat One'], ...]]
    const vcard = ent.vcardArray && ent.vcardArray[1];
    if (!Array.isArray(vcard)) continue;

    for (const field of vcard) {
      if (Array.isArray(field) && field[0] === 'fn' && field[3]) {
        return String(field[3]).trim();
      }
    }

    // 没有 fn 时退回 handle
    if (ent.handle) return String(ent.handle);
  }
  return null;
}

/**
 * 解析 DigitalPlat RDAP 响应。
 * 样例见 docs：events 里含 registration / expiration，nameservers 是 { ldhName } 数组。
 */
export function parseRdap(data) {
  if (!data || typeof data !== 'object') return null;

  // RDAP 的 404 在 HTTP 层已处理；这里兜底 ldhName 缺失的情况
  if (data.errorCode === 404) {
    return { registered: false, status: 'not-registered', source: 'rdap' };
  }

  const events = Array.isArray(data.events) ? data.events : [];
  const eventDate = action => {
    const hit = events.find(e => e && e.eventAction === action);
    return hit ? toYmd(hit.eventDate) : null;
  };

  const nameServers = (Array.isArray(data.nameservers) ? data.nameservers : [])
    .map(ns => (ns && (ns.ldhName || ns.unicodeName)) || null)
    .filter(Boolean)
    .map(ns => String(ns).toLowerCase());

  return {
    registered: true,
    registrar: findRegistrar(data.entities) || 'Unknown',
    registrationDate: eventDate('registration') || 'Unknown',
    ...expiryOf(eventDate('expiration')),
    nameServers,
    status: Array.isArray(data.status) ? data.status.join(', ') : (data.status || 'active'),
    source: 'rdap'
  };
}

/**
 * 解析 DNSHE 的 whois 端点响应。
 * 注意：未注册时返回 { success: true, registered: false }，不是错误。
 *
 * @param {object} data
 * @param {string} [expectedDomain] 我们实际请求的域名。DNSHE 会在响应里回显
 *        `domain`，对不上就说明这条数据不是这个域名的——宁可丢弃也不能把
 *        别人的到期日挂到当前域名上（到期日错了，续费提醒就是错的）。
 */
export function parseDnshe(data, expectedDomain) {
  if (!data || typeof data !== 'object') return null;

  if (data.success === false) {
    return { error: String(data.message || 'DNSHE 查询失败') };
  }

  const echoed = data.domain || data.full_domain || data.subdomain_domain;
  if (expectedDomain && echoed) {
    const norm = value => String(value).trim().toLowerCase().replace(/\.$/, '');
    if (norm(echoed) !== norm(expectedDomain)) {
      return {
        error: `DNSHE 返回了另一个域名的数据（请求 ${expectedDomain}，返回 ${echoed}），已丢弃`
      };
    }
  }

  if (data.registered === false) {
    return { registered: false, status: data.status || 'unregistered', source: 'dnshe' };
  }

  return {
    registered: true,
    registrar: data.registrar || 'DNSHE',
    registrationDate: toYmd(data.registered_at) || 'Unknown',
    // DNSHE 升级为永久域名后，expires_at 会是 2999-12-31 这类哨兵日期
    ...expiryOf(data.expires_at),
    nameServers: (Array.isArray(data.nameservers) ? data.nameservers : [])
      .filter(Boolean)
      .map(ns => String(ns).toLowerCase()),
    status: data.status || 'active',
    source: 'dnshe'
  };
}

const MONTHS = {
  jan: '01', feb: '02', mar: '03', apr: '04', may: '05', jun: '06',
  jul: '07', aug: '08', sep: '09', oct: '10', nov: '11', dec: '12'
};

/**
 * WHOIS 文本里的日期。常见两种：
 *   '10-Oct-2022 06:55:49 UTC'（pp.ua / NIC.UA）
 *   '2022-10-10T00:00:00Z'
 */
export function parseWhoisDate(value) {
  if (!value) return null;
  const text = String(value).trim();
  if (!text || /^unknown$/i.test(text)) return null;

  const named = text.match(/^(\d{1,2})-([A-Za-z]{3})-(\d{4})/);
  if (named) {
    const mm = MONTHS[named[2].toLowerCase()];
    if (mm) return `${named[3]}-${mm}-${named[1].padStart(2, '0')}`;
  }

  return toYmd(text);
}

/**
 * 解析纯文本 WHOIS 响应（pp.ua 这类 registry 的 43 端口输出）。
 *
 * 实际样例（whois.pp.ua）字段是 `Key:Value`，冒号后没有空格：
 *   Domain Name:YUEDU.PP.UA
 *   Created On:10-Oct-2022 06:55:49 UTC
 *   Expiration Date:10-Oct-2027 06:55:49 UTC
 *   Sponsoring Registrar:NIC.UA LLC (nic-mnt-cunic)
 *   Status:serverDeleteProhibited
 *   Name Server:JACK.NS.CLOUDFLARE.COM
 *
 * 未注册时返回 "No entries found."，必须识别成"未注册"而不是解析失败。
 */
export function parseWhoisText(text) {
  if (!text || typeof text !== 'string') return null;

  const body = text.replace(/\r\n?/g, '\n');
  if (/no entries found|no match|not found|no such domain|domain not registered/i.test(body)) {
    return { registered: false, status: 'not-registered', source: 'whois' };
  }

  const fields = new Map();
  const nameServers = [];
  const statuses = [];

  for (const line of body.split('\n')) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;

    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (!value) continue;

    if (key === 'name server' || key === 'nameserver' || key === 'nserver') {
      nameServers.push(value.toLowerCase());
      continue;
    }
    if (key === 'status' || key === 'domain status') {
      statuses.push(value);
      continue;
    }
    // 同一个 key 可能出现多次（Registrar / Registrant），只认第一个
    if (!fields.has(key)) fields.set(key, value);
  }

  const pick = keys => {
    for (const k of keys) {
      if (fields.has(k)) return fields.get(k);
    }
    return null;
  };

  const domain = pick(['domain name', 'domain']);
  if (!domain) return null;

  // 'NIC.UA LLC (nic-mnt-cunic)' → 'NIC.UA LLC'
  const registrar = (pick(['sponsoring registrar', 'registrar', 'registrar name']) || '')
    .replace(/\s*\([^)]*\)\s*$/, '')
    .trim();

  return {
    registered: true,
    registrar: registrar || 'Unknown',
    registrationDate: parseWhoisDate(pick(['created on', 'created', 'creation date', 'registered on', 'registered'])) || 'Unknown',
    ...expiryOf(parseWhoisDate(pick(['expiration date', 'expires', 'expiry date', 'registry expiry date', 'paid-till']))),
    nameServers: nameServers.slice(0, 12),
    status: statuses.length ? statuses.join(', ') : 'active',
    source: 'whois'
  };
}

const PARSERS = {
  rdap: parseRdap,
  dnshe: parseDnshe,
  whois: parseWhoisText
};

// DigitalPlat 的 RDAP 前置了 Cloudflare WAF：用 curl 默认 UA 会拿到 403 Challenge Page，
// 换成浏览器 UA 才返回 JSON。Workers 的默认 UA 是 'Cloudflare-Workers'，同样会被拦，
// 因此这里必须显式声明 UA。
export const DEFAULT_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

/**
 * 从错误响应里取出服务端原话。
 * DNSHE 的 401 body 形如
 *   { error: 'Invalid API key', error_code: 'auth_invalid_credentials', message: '...' }
 * 这句话是排查的关键，不能因为状态码就够了就丢掉。
 */
async function readErrorDetail(res) {
  try {
    const text = await res.text();
    if (!text) return '';
    try {
      const data = JSON.parse(text);
      const detail = data.message || data.error || data.error_code || '';
      return String(detail).slice(0, 120);
    } catch (e) {
      return text.slice(0, 100).replace(/\s+/g, ' ').trim();
    }
  } catch (e) {
    return '';
  }
}

export class FreeDomainLookup {
  /**
   * @param {object} [options]
   * @param {boolean} [options.enabled=true] 总开关，关闭后一律回退注册表元数据
   * @param {number}  [options.timeout=8000] 单次查询超时（毫秒）
   * @param {string}  [options.dnsheKey]     DNSHE X-API-Key（单凭证简写）
   * @param {string}  [options.dnsheSecret]  DNSHE X-API-Secret
   * @param {Array}   [options.dnsheCredentials] 多凭证 [{key, secret}]，按顺序尝试
   *        一把 Key 能查平台全部 DNSHE 域名的 whois，但不同账户的 Key 会各自过期，
   *        所以 401 时自动换下一把，不让一个账户的 Key 失效拖垮所有 DNSHE 域名
   * @param {string}  [options.userAgent]    覆盖默认 UA（WAF 拦截时用）
   * @param {Function} [options.fetchImpl]   注入 fetch，便于测试
   * @param {Function} [options.whoisTransport] 注入 TCP WHOIS 通道
   *        (host, port, query, timeoutMs) => Promise<string>；未注入时 whois 类型直接降级
   */
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.timeout = Number(options.timeout) > 0 ? Number(options.timeout) : 8000;
    this.userAgent = options.userAgent || DEFAULT_USER_AGENT;
    this.fetchImpl = options.fetchImpl || (typeof fetch === 'function' ? fetch.bind(globalThis) : null);
    this.whoisTransport = options.whoisTransport || null;

    const list = Array.isArray(options.dnsheCredentials) ? options.dnsheCredentials : [];
    const usable = list.filter(c => c && c.key);
    if (usable.length) {
      this.dnsheCredentials = usable;
    } else if (options.dnsheKey) {
      this.dnsheCredentials = [{ key: options.dnsheKey, secret: options.dnsheSecret || '' }];
    } else {
      this.dnsheCredentials = [];
    }

    // 兼容旧字段（有外部代码/测试直接读这两个属性）
    this.dnsheKey = this.dnsheCredentials.length ? this.dnsheCredentials[0].key : (options.dnsheKey || '');
    this.dnsheSecret = this.dnsheCredentials.length ? (this.dnsheCredentials[0].secret || '') : (options.dnsheSecret || '');
  }

  /** 支持的查询类型，用于配置校验 */
  static get supportedTypes() {
    return Object.keys(PARSERS);
  }

  /**
   * 按 spec 查询一个免费域名。
   * @param {string} domain
   * @param {{type: string, endpoint: string}} spec
   * @returns {Promise<object|null>} 成功返回解析结果，失败返回 { error }，无 spec 返回 null
   */
  async lookup(domain, spec) {
    if (!this.enabled || !spec || !spec.type || !spec.endpoint) return null;

    const parser = PARSERS[spec.type];
    if (!parser) return { error: `不支持的查询类型: ${spec.type}` };

    // TCP WHOIS 走独立通道（Workers 用 cloudflare:sockets，Node 测试用 net 注入）
    if (spec.type === 'whois') {
      return this.lookupWhoisTcp(domain, spec);
    }

    if (!this.fetchImpl) return { error: '当前运行环境不支持 fetch' };

    // DNSHE 的鉴权是 Key + Secret **成对**的：只发 X-API-Key 时服务端返回
    // "Missing API credentials (use X-API-Key and X-API-Secret headers)"，
    // 看起来像"根本没配凭证"，实际是"配了一半"。先筛掉缺 Secret 的条目，
    // 把话说清楚，别让用户对着"请检查 Key 是否正确"反复试。
    if (spec.type === 'dnshe') {
      const complete = this.dnsheCredentials.filter(c => c && c.key && c.secret);

      if (this.dnsheCredentials.length && !complete.length) {
        return {
          error: 'DNSHE 凭证不完整：缺少 API Secret（X-API-Key 与 X-API-Secret 必须成对发送）',
          authFailed: true
        };
      }

      // 有完整凭证就逐把尝试；完全没有则走公开模式（不带任何头）
      if (complete.length) {
        return this.tryDnsheCredentials(domain, spec, parser, complete);
      }
    }

    return this.requestOnce(domain, spec, parser, null);
  }

  /** 逐把凭证尝试，401/403 换下一把 */
  async tryDnsheCredentials(domain, spec, parser, credentials) {
    let lastAuthError = null;

    for (const credential of credentials) {
      const result = await this.requestOnce(domain, spec, parser, credential);

      // 凭证被拒时换下一把；其余结果（成功/网络错误/未注册）直接返回
      if (result && result.authFailed) {
        lastAuthError = result;
        continue;
      }
      return result;
    }

    return lastAuthError || { error: 'DNSHE 凭证均不可用' };
  }

  /**
   * 401/403 的可操作提示。
   * 把"没配凭证"、"配了一半"、"配了但被拒"三种情况分开说——
   * 它们的修复动作完全不同，混成一句"请检查 Key"等于没说。
   */
  authMessage(type, status, detail, hasCredential) {
    const tag = String(type || '').toUpperCase();
    const tail = detail ? `（服务端：${detail}）` : '';

    if (status === 403) {
      return `${tag} 请求被拒绝（403）：可能是 Key 权限不足，或请求 UA 被 WAF 识别${tail}`;
    }

    if (!hasCredential) {
      return `${tag} 认证失败（401）：接口要求 API Key + Secret，当前没有可用凭证。` +
        '请在「DNSHE」页面添加，或配置环境变量 DNSHE_API_KEY / DNSHE_API_SECRET' + tail;
    }
    if (/missing/i.test(detail)) {
      return `${tag} 认证失败（401）：Key 与 Secret 必须成对发送，当前凭证缺少其中一项${tail}`;
    }
    return `${tag} 认证失败（401）：Key / Secret 被服务端拒绝，可能填错或已失效${tail}`;
  }

  /**
   * 单次 HTTP 查询。
   * 401/403 额外标记 authFailed，让上层决定是否换凭证。
   */
  async requestOnce(domain, spec, parser, credential) {
    const url = String(spec.endpoint).replace('{domain}', encodeURIComponent(domain));
    const tag = spec.type.toUpperCase();

    try {
      const headers = {
        Accept: 'application/rdap+json, application/json',
        'User-Agent': this.userAgent
      };
      if (spec.type === 'dnshe' && credential) {
        if (credential.key) headers['X-API-Key'] = credential.key;
        if (credential.secret) headers['X-API-Secret'] = credential.secret;
      }

      const res = await this.fetchImpl(url, {
        method: 'GET',
        headers,
        signal: AbortSignal.timeout(this.timeout)
      });

      // 404 在 RDAP 里表示"该域名未注册"，是有效信息而非故障
      if (res.status === 404) {
        return { registered: false, status: 'not-registered', source: spec.type };
      }

      // 这两个状态码有明确的处置动作，单独给可操作的提示。
      // 必须把服务端的原话带上：DNSHE 在 401 里区分了
      //   "Missing API credentials"（没发/只发了一个头）
      //   "Invalid API key"（成对发了但 Key 不对）
      // 丢掉 body 就只剩一句含糊的"认证失败"，没法定位。
      if (res.status === 401 || res.status === 403) {
        const detail = await readErrorDetail(res);
        return {
          error: this.authMessage(spec.type, res.status, detail, Boolean(credential)),
          authFailed: true
        };
      }

      if (!res.ok) {
        return { error: `${tag} HTTP ${res.status}` };
      }

      // 用 text() 再手动解析：WAF 挑战页是 HTML，直接 json() 的报错信息没有诊断价值
      const text = await res.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch (e) {
        const preview = text.slice(0, 60).replace(/\s+/g, ' ');
        return { error: `${tag} 响应不是 JSON（可能被 WAF 拦截）: ${preview}` };
      }

      const parsed = parser(data, domain);

      return parsed || { error: `${tag} 响应无法解析` };
    } catch (error) {
      const reason = error && error.name === 'AbortError'
        ? `${tag} 查询超时`
        : (error && error.message) || '未知错误';
      return { error: reason };
    }
  }

  /**
   * TCP WHOIS（43 端口）。
   * endpoint 写法是 host:port，省略端口时用 43。
   * 运行环境不提供 TCP 通道时（例如 Node 单测没注入 transport）直接降级，
   * 不抛异常——免费域名查询只是增强，不能阻断整页刷新。
   */
  async lookupWhoisTcp(domain, spec) {
    if (!this.whoisTransport) {
      return { error: 'WHOIS/TCP 通道不可用（当前运行环境不支持出站 TCP）' };
    }

    const raw = String(spec.endpoint).trim();
    const at = raw.lastIndexOf(':');
    const host = at > 0 ? raw.slice(0, at) : raw;
    const port = at > 0 ? Number(raw.slice(at + 1)) || 43 : 43;

    if (!host) return { error: 'WHOIS/TCP 未配置主机名' };

    try {
      const text = await this.whoisTransport(host, port, domain, this.timeout);
      const parsed = parseWhoisText(text);
      return parsed || { error: `WHOIS/TCP 响应无法解析（${host}）` };
    } catch (error) {
      return { error: (error && error.message) || `WHOIS/TCP 查询 ${host} 失败` };
    }
  }
}
