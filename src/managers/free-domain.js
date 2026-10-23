// 免费 / 公益域名注册表
//
// 设计要点：
// 1. 单一真相源：所有"这是不是免费域名""是不是永久域名""续期模式"的判断都从这里出，
//    不再允许调用方自己写 endsWith / includes / 正则（历史上 handlers.js 与 ui/data.js
//    各写了一遍 eu.org 判断，已经踩过坑）。
// 2. 三层配置优先级：内置 DEFAULT_SUFFIXES < 环境变量 FREE_DOMAIN_SUFFIXES < KV
//    config:free-domains。KV 层可以在管理页面直接改，改完 60 秒内生效，不需要重新部署。
// 3. 数据模型显式化：用 renew 字段表达续期语义（permanent / auto / manual），
//    而不是把 'Auto-Renewal' 这种字符串塞进 expirationDate 冒充日期。
//    对外 getInfo() 仍输出旧的 expirationDate 形态，保持向后兼容。
// 4. 匹配用最长后缀优先：预先按长度降序排序，未来同时存在 'org' 与 'eu.org'
//    这类父子后缀时不会误判。
// 5. disabled 条目不参与匹配，但保留在表里，方便管理页面"重新启用"。

/**
 * 各家服务商的公开查询端点。
 * HTTP 类型用 {domain} 占位；whois 类型写 host:port，由 TCP 通道查询。
 * 集中定义，便于后续换域名或加镜像时只改一处。
 */
export const LOOKUP_ENDPOINTS = {
  digitalplat: 'https://rdap.digitalplat.org/domain/{domain}',
  dnshe: 'https://api005.dnshe.com/index.php?m=domain_hub&endpoint=whois&domain={domain}',
  ppua: 'whois.pp.ua:43',
  // ip6.arpa 的反向解析区没有逐区 WHOIS：IANA RDAP 只覆盖 arpa 本身与 RIR 级委派
  // （ip6.arpa / d.f.ip6.arpa 这类），用户自己的 /48、/64 反向区一律 404。
  // 见 DEFAULT_SUFFIXES 里 ip6.arpa 条目的注释，这里保留端点仅作排查用。
  iana: 'https://rdap.iana.org/domain/{domain}'
};

/** 查询方式的展示名，UI 与文档共用 */
export const LOOKUP_LABELS = {
  rdap: 'RDAP',
  dnshe: 'DNSHE API',
  whois: 'WHOIS / TCP'
};

/** 配置来源的展示名 */
export const SOURCE_LABELS = {
  builtin: '内置',
  env: '环境变量',
  kv: 'KV 配置'
};

/**
 * 内置默认表。
 * renew 语义：
 *   permanent — 长期有效，不需要关注到期（eu.org / is-a.dev / js.org 这类公益域名）
 *   auto      — 查询不到真实到期日时的兜底：视为服务商自动续期，不进入临期告警
 *   manual    — 查不到到期日时按"待完善"处理，提示人工补充（pp.ua 属于这类）
 * parentRegistered 是"父域"的注册日，仅用于展示来源，不是子域名的注册日。
 * category：public = 公益/社区域名（理论上永久），free = 免费注册但会到期。
 *
 * 数据来源：
 *   DigitalPlat FreeDomain — RDAP  https://rdap.digitalplat.org
 *   DNSHE                   — WHOIS https://api005.dnshe.com（限速 30 次/分钟）
 *   pp.ua                   — WHOIS over TCP whois.pp.ua:43
 */
export const DEFAULT_SUFFIXES = [
  // ── 公益 / 社区域名：理论上永久，按 eu.org 的逻辑处理 ────────────
  {
    suffix: 'eu.org',
    category: 'public',
    registrar: 'NIC.EU.ORG',
    renew: 'permanent',
    parentRegistered: '1996-04-29',
    provider: 'eu.org',
    note: '欧洲免费域名服务'
  },
  {
    suffix: 'is-a.dev',
    category: 'public',
    registrar: 'is-a.dev',
    renew: 'permanent',
    parentRegistered: null,
    provider: 'is-a.dev',
    note: '开发者社区公益域名（GitHub PR 申请）'
  },
  {
    suffix: 'js.org',
    category: 'public',
    registrar: 'JS.ORG',
    renew: 'permanent',
    parentRegistered: null,
    provider: 'JS.ORG',
    note: 'JavaScript 社区公益域名'
  },

  // ── ip6.arpa：IPv6 反向解析区 ───────────────────────────────────
  //
  // 谁在用：Hurricane Electric（HE.net）的免费 DNS（dns.he.net）给隧道 / 独立
  // 前缀免费委派 IPv6 反向解析区，区名形如
  //   x.x.x.x.…(32 段 nibble)….ip6.arpa
  // 这属于"多级子域名"，父区 ip6.arpa 由 IANA 维护（2001-11-10 建）。
  //
  // 为什么不挂 lookup：
  //   实测 2026-10，IANA RDAP（rdap.iana.org）能查到 ip6.arpa 本身和 RIR 级委派
  //   （如 d.f.ip6.arpa → RIPE），但**查不到任何用户自己的反向区**——这些都是
  //   直接 404，因为 IANA 只登记到 RIR 那一层。RIR 侧（ARIN/RIPE/APNIC）的
  //   RDAP 只按 IP 前缀查，不认反向区名。
  //   反向解析区本身不注册、不续费、不过期，所以 renew: 'permanent' 才是准确语义；
  //   挂一个必然 404 的查询只会把界面刷成"未注册"。
  {
    suffix: 'ip6.arpa',
    category: 'public',
    registrar: 'IANA',
    renew: 'permanent',
    parentRegistered: '2001-11-10',
    provider: 'Hurricane Electric',
    note: 'IPv6 反向解析区（HE.net 免费委派）'
  },

  // ── pp.ua：可查 WHOIS，查不到时按人工维护处理 ────────────────────
  {
    suffix: 'pp.ua',
    category: 'free',
    registrar: 'NIC.UA',
    renew: 'manual',
    parentRegistered: '2002-03-15',
    provider: 'pp.ua',
    note: '乌克兰免费域名服务（需每年续期）',
    lookup: { type: 'whois', endpoint: LOOKUP_ENDPOINTS.ppua }
  },

  // ── DigitalPlat FreeDomain：RDAP 可查真实注册/到期日 ────────────
  {
    suffix: 'us.kg',
    category: 'free',
    registrar: 'DIGITALPLAT.ORG',
    renew: 'auto',
    parentRegistered: '2020-05-20',
    provider: 'DigitalPlat',
    note: '免费 KG 域名服务',
    lookup: { type: 'rdap', endpoint: LOOKUP_ENDPOINTS.digitalplat }
  },
  {
    suffix: 'dpdns.org',
    category: 'free',
    registrar: 'DIGITALPLAT.ORG',
    renew: 'auto',
    parentRegistered: '2010-06-01',
    provider: 'DigitalPlat',
    note: '免费 DNS 域名服务',
    lookup: { type: 'rdap', endpoint: LOOKUP_ENDPOINTS.digitalplat }
  },
  {
    suffix: 'xx.kg',
    category: 'free',
    registrar: 'DIGITALPLAT.ORG',
    renew: 'auto',
    parentRegistered: '2021-03-10',
    provider: 'DigitalPlat',
    note: '免费 KG 域名服务',
    lookup: { type: 'rdap', endpoint: LOOKUP_ENDPOINTS.digitalplat }
  },
  {
    suffix: 'qzz.io',
    category: 'free',
    registrar: 'DIGITALPLAT.ORG',
    renew: 'auto',
    parentRegistered: '2018-10-12',
    provider: 'DigitalPlat',
    note: '免费 IO 子域名服务',
    lookup: { type: 'rdap', endpoint: LOOKUP_ENDPOINTS.digitalplat }
  },
  {
    suffix: 'qd.je',
    category: 'free',
    registrar: 'DIGITALPLAT.ORG',
    renew: 'auto',
    parentRegistered: null,
    provider: 'DigitalPlat',
    note: '免费 JE 域名服务',
    lookup: { type: 'rdap', endpoint: LOOKUP_ENDPOINTS.digitalplat }
  },

  // ── DNSHE：自有 WHOIS 接口 ───────────────────────────────────────
  {
    suffix: 'us.ci',
    category: 'free',
    registrar: 'DNSHE',
    renew: 'auto',
    parentRegistered: null,
    provider: 'DNSHE',
    note: '免费 CI 子域名服务',
    lookup: { type: 'dnshe', endpoint: LOOKUP_ENDPOINTS.dnshe }
  },
  {
    suffix: 'cc.cd',
    category: 'free',
    registrar: 'DNSHE',
    renew: 'auto',
    parentRegistered: null,
    provider: 'DNSHE',
    note: '免费 CD 子域名服务',
    lookup: { type: 'dnshe', endpoint: LOOKUP_ENDPOINTS.dnshe }
  },
  {
    suffix: 'new.tg',
    category: 'free',
    registrar: 'DNSHE',
    renew: 'auto',
    parentRegistered: null,
    provider: 'DNSHE',
    note: '免费 TG 子域名服务',
    lookup: { type: 'dnshe', endpoint: LOOKUP_ENDPOINTS.dnshe }
  },
  {
    suffix: 'de5.net',
    category: 'free',
    registrar: 'DNSHE',
    renew: 'auto',
    parentRegistered: null,
    provider: 'DNSHE',
    note: '免费 NET 子域名服务',
    lookup: { type: 'dnshe', endpoint: LOOKUP_ENDPOINTS.dnshe }
  },
  {
    suffix: 'ccwu.cc',
    category: 'free',
    registrar: 'DNSHE',
    renew: 'auto',
    parentRegistered: null,
    provider: 'DNSHE',
    note: '免费 CC 子域名服务',
    lookup: { type: 'dnshe', endpoint: LOOKUP_ENDPOINTS.dnshe }
  },
  {
    suffix: 'bbroot.com',
    category: 'free',
    registrar: 'DNSHE',
    renew: 'auto',
    parentRegistered: null,
    provider: 'DNSHE',
    note: '免费 COM 子域名服务',
    lookup: { type: 'dnshe', endpoint: LOOKUP_ENDPOINTS.dnshe }
  },
  {
    suffix: 'kz.ci',
    category: 'free',
    registrar: 'DNSHE',
    renew: 'auto',
    parentRegistered: null,
    provider: 'DNSHE',
    note: '免费 CI 子域名服务',
    lookup: { type: 'dnshe', endpoint: LOOKUP_ENDPOINTS.dnshe }
  },
  {
    suffix: 'xyz.ci',
    category: 'free',
    registrar: 'DNSHE',
    renew: 'auto',
    parentRegistered: null,
    provider: 'DNSHE',
    note: '免费 CI 子域名服务',
    lookup: { type: 'dnshe', endpoint: LOOKUP_ENDPOINTS.dnshe }
  },
  {
    suffix: 'pc.ci',
    category: 'free',
    registrar: 'DNSHE',
    renew: 'auto',
    parentRegistered: null,
    provider: 'DNSHE',
    note: '免费 CI 子域名服务',
    lookup: { type: 'dnshe', endpoint: LOOKUP_ENDPOINTS.dnshe }
  },
  {
    suffix: 'cn.mt',
    category: 'free',
    registrar: 'DNSHE',
    renew: 'auto',
    parentRegistered: null,
    provider: 'DNSHE',
    note: '免费 MT 子域名服务',
    lookup: { type: 'dnshe', endpoint: LOOKUP_ENDPOINTS.dnshe }
  }
];

const RENEW_MODES = new Set(['permanent', 'auto', 'manual']);
const CATEGORIES = new Set(['public', 'free']);

/**
 * 把各种写法的配置项规范成内部条目。
 * 支持两种输入：
 *   - 字符串：'eu.org'（等价于 renew: 'auto'）
 *   - 对象：{ suffix, registrar, renew, provider, note, lookup, disabled }
 */
function normalizeEntry(input) {
  const raw = typeof input === 'string' ? { suffix: input } : (input || {});
  const suffix = String(raw.suffix || raw.domain || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');

  // 只做格式校验，不限制层级：Freenom 的 .tk/.ml/.ga 这类免费 TLD 是一级后缀，
  // 而 eu.org / us.kg 是二级。非法字符与空段必须拒绝，否则会污染匹配表。
  if (!suffix || suffix.length < 2 || !/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(suffix)) {
    return null;
  }

  const renew = RENEW_MODES.has(raw.renew) ? raw.renew : 'auto';
  const category = CATEGORIES.has(raw.category) ? raw.category : (renew === 'permanent' ? 'public' : 'free');

  // lookup 是可选的服务商查询接口；缺 type 或 endpoint 一律视为未配置
  const lookup = raw.lookup && raw.lookup.type && raw.lookup.endpoint
    ? { type: String(raw.lookup.type).toLowerCase(), endpoint: String(raw.lookup.endpoint) }
    : null;

  return {
    suffix,
    category,
    registrar: raw.registrar || 'Unknown',
    renew,
    parentRegistered: raw.parentRegistered || null,
    provider: raw.provider || raw.registrar || 'Unknown',
    note: raw.note || raw.description || '',
    lookup,
    disabled: raw.disabled === true
  };
}

/**
 * 解析环境变量 FREE_DOMAIN_SUFFIXES / KV 配置。
 * 接受 JSON 数组，或逗号分隔的字符串；解析失败返回空数组而不是抛错，
 * 保证配置写错时系统仍能用内置表启动。
 */
export function parseSuffixConfig(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;

  const text = String(raw).trim();
  if (!text) return [];

  // JSON 形态（数组或对象）必须先走 JSON.parse，否则会被逗号分割成垃圾后缀
  if (text.startsWith('[') || text.startsWith('{')) {
    try {
      const parsed = JSON.parse(text);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      return [];
    }
  }

  return text.split(',').map(s => s.trim()).filter(Boolean);
}

export class FreeDomainManager {
  /**
   * @param {object} [options]
   * @param {Array|string} [options.overrides] 追加/覆盖的配置（来自环境变量）
   * @param {Array|string} [options.kvEntries] 追加/覆盖的配置（来自 KV，优先级最高）
   * @param {Array} [options.entries] 完全替换内置表（测试用）
   */
  constructor(options = {}) {
    /** @type {Map<string, object>} */
    this.domains = new Map();
    /** @type {string[]} 按后缀长度降序，保证最长匹配优先 */
    this.order = [];

    const base = Array.isArray(options.entries) ? options.entries : DEFAULT_SUFFIXES;
    this.load(base, 'builtin');

    const overrides = parseSuffixConfig(options.overrides);
    if (overrides.length) this.load(overrides, 'env');

    // KV 层最后载入，优先级最高：管理页面的改动能覆盖内置表与环境变量
    const kv = parseSuffixConfig(options.kvEntries);
    if (kv.length) this.load(kv, 'kv');
  }

  /**
   * 载入条目（同后缀覆盖）。每次载入后重建匹配顺序。
   * @param {Array} list
   * @param {'builtin'|'env'|'kv'} [source] 记录来源，供管理页面展示
   * @returns {number} 实际生效的条目数
   */
  load(list, source = 'builtin') {
    let added = 0;

    for (const item of list || []) {
      const entry = normalizeEntry(item);
      if (!entry) continue;
      const prev = this.domains.get(entry.suffix);
      // KV 里的禁用标记不应该把内置的元数据（注册商、说明）冲掉
      if (entry.disabled && prev) {
        this.domains.set(entry.suffix, { ...prev, disabled: true, source });
      } else {
        this.domains.set(entry.suffix, { ...entry, source });
      }
      added++;
    }

    this.order = Array.from(this.domains.keys()).sort((a, b) => b.length - a.length);
    return added;
  }

  /**
   * 匹配域名归属的免费后缀（跳过已禁用条目）。
   * @returns {{entry: object, isApex: boolean}|null}
   */
  match(domain) {
    if (!domain) return null;

    const name = String(domain).trim().toLowerCase().replace(/\.$/, '');
    if (!name) return null;

    for (const suffix of this.order) {
      const entry = this.domains.get(suffix);
      if (!entry || entry.disabled) continue;

      // 先判等再判后缀：'eu.org' 本身是 apex，'a.eu.org' 才是子域
      if (name === suffix) {
        return { entry, isApex: true };
      }
      if (name.endsWith('.' + suffix)) {
        return { entry, isApex: false };
      }
    }

    return null;
  }

  isFree(domain) {
    return this.match(domain) !== null;
  }

  /** 是否为免维护的永久域名（替代历史上散落的 includes('eu.org') / /eu\.org$/） */
  isPermanent(domain) {
    const m = this.match(domain);
    return Boolean(m && m.entry.renew === 'permanent');
  }

  /** 是否由服务商自动续期 */
  isAutoRenew(domain) {
    const m = this.match(domain);
    return Boolean(m && m.entry.renew === 'auto');
  }

  /** 当前生效的后缀列表（不含禁用项），供管理页面/诊断接口使用 */
  list() {
    return this.order
      .map(suffix => this.domains.get(suffix))
      .filter(entry => entry && !entry.disabled)
      .map(entry => ({ ...entry }))
      .sort((a, b) => a.suffix.localeCompare(b.suffix));
  }

  /** 含禁用项的全量表，管理页面用 */
  listAll() {
    return this.order
      .map(suffix => this.domains.get(suffix))
      .filter(Boolean)
      .map(entry => ({ ...entry }))
      .sort((a, b) => a.suffix.localeCompare(b.suffix));
  }

  /** 生效条目数（不含禁用项） */
  get size() {
    return this.list().length;
  }

  /**
   * 兼容旧调用方的元数据输出。
   * 注意 registrationDate：子域名没有独立的注册日，返回 'N/A' 而不是伪造父域日期。
   * expirationDate 保留 'Auto-Renewal' 字符串是为了兼容 ui/data.js 的既有判定，
   * 新代码请直接用 isPermanent() / isAutoRenew()。
   */
  getInfo(domain) {
    const m = this.match(domain);
    if (!m) return null;

    const { entry, isApex } = m;

    return {
      registrar: entry.registrar,
      registrationDate: isApex ? (entry.parentRegistered || 'N/A') : 'N/A',
      expirationDate: entry.renew === 'auto' ? 'Auto-Renewal' : null,
      renewMode: entry.renew,
      isPermanent: entry.renew === 'permanent',
      isFreeSubdomain: !isApex,
      level: isApex ? 'apex' : 'subdomain',
      parent: isApex ? null : entry.suffix,
      provider: entry.provider,
      category: entry.category,
      source: entry.source,
      description: isApex ? entry.note : `${entry.note} - 子域名`,
      // 服务商公开查询接口，供 WhoisService 决定是否拉取真实到期日
      lookup: entry.lookup || null
    };
  }
}
