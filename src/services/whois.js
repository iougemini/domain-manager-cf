// WHOIS 查询服务

import { CONFIG } from '../config.js';
import { isPermanentDate } from './free-domain-lookup.js';

/**
 * 失败结果只缓存很短时间。
 * 把 401 / 第三方接口故障按正常结果缓存 7 天，会出现"补好 Key 依然报错"的
 * 死循环——用户改完配置刷新，读到的还是那条旧失败记录。
 */
function cacheTtlFor(result) {
  if (!result) return undefined;
  if (result.lookupError || result.whoisError) return CONFIG.CACHE_FAILURE_TTL;
  return undefined;
}

export class WhoisService {
  /**
   * @param {string} proxyUrl 通用 WHOIS 代理（未配置时普通域名返回 N/A）
   * @param {object} cacheManager
   * @param {object} freeDomainManager
   * @param {object} [options]
   * @param {object} [options.freeLookup] FreeDomainLookup 实例，用于查免费域名真实到期日
   */
  constructor(proxyUrl, cacheManager, freeDomainManager, options = {}) {
    this.proxyUrl = proxyUrl;
    this.cache = cacheManager;
    this.freeDomains = freeDomainManager;
    this.freeLookup = options.freeLookup || null;
  }

  /**
   * @param {string} domain
   * @param {{cacheOnly?: boolean, forceRefresh?: boolean}} [options]
   *        cacheOnly=true 表示"只读缓存，不要发网络请求"。页面渲染超出时间
   *        预算后会切成这个模式：还能把已缓存的域名渲染出来，没缓存的留空，
   *        由后台任务补。返回值带 pending=true，UI 显示成「查询中」。
   *        forceRefresh=true 跳过缓存读取，直接查一次并覆盖缓存。新增域名时用：
   *        库里可能躺着一条早前的失败记录（比如凭证还没配），不跳过的话
   *        用户刚加完就看到"查不到"，以为功能坏了。
   */
  async query(domain, options = {}) {
    if (!domain) {
      throw new Error('域名不能为空');
    }

    console.log('查询域名: ' + domain);

    // 缓存优先。免费域名也必须走缓存，否则每次刷新都会打第三方接口
    // （DNSHE 公共模式按 IP 限速 30 次/分钟，68 个域名一次刷新就会超）
    if (!options.forceRefresh) {
      const cached = await this.cache.get(domain);
      if (cached) {
        console.log('缓存命中: ' + domain);
        return cached;
      }
    }

    if (options.cacheOnly) {
      // 免费域名的注册表元数据是本地常量，不花钱也不慢，照常返回；
      // 普通域名没有缓存就只能占位，等后台补
      const freeInfo = this.freeDomains.getInfo(domain);
      if (freeInfo) {
        return { ...freeInfo, dataSource: 'registry', pending: true };
      }
      return {
        registrar: 'Unknown',
        registrationDate: 'Unknown',
        expirationDate: 'Unknown',
        dataSource: null,
        pending: true
      };
    }

    // 免费域名：配置了 lookup 就拉真实到期日，失败回退注册表元数据
    const freeInfo = this.freeDomains.getInfo(domain);
    if (freeInfo) {
      console.log('免费域名: ' + domain + (freeInfo.lookup ? '（实时查询 ' + freeInfo.lookup.type + '）' : '（元数据）'));
      const result = await this.resolveFreeDomain(domain, freeInfo);
      await this.cache.set(domain, result, cacheTtlFor(result));
      return result;
    }

    // WHOIS 查询
    if (!this.proxyUrl) {
      console.log('WHOIS代理未配置: ' + domain);
      return {
        registrar: 'N/A',
        registrationDate: 'N/A',
        expirationDate: 'N/A',
        whoisError: 'WHOIS proxy not configured',
        dataSource: null
      };
    }

    console.log('查询WHOIS: ' + domain);
    const result = await this.fetchWhoisWithRetry(domain);
    // 标记数据来源，抽屉里据此显示「WHOIS 代理 / 内置注册表 / 实时接口」徽标
    result.dataSource = result.whoisError ? null : 'whois-proxy';

    // 缓存结果（包括错误结果，避免重复查询）
    await this.cache.set(domain, result, cacheTtlFor(result));

    return result;
  }

  /**
   * 合并免费域名的实时查询结果与注册表元数据。
   * 实时查询失败时**不设置 whoisError**——第三方接口故障不该让域名显示成
   * 「查询异常」，而是静默回退到元数据（Auto-Renewal / 永久），保持界面稳定。
   */
  async resolveFreeDomain(domain, freeInfo) {
    if (!this.freeLookup || !freeInfo.lookup) {
      return freeInfo;
    }

    const live = await this.freeLookup.lookup(domain, freeInfo.lookup);

    // 未配置查询器、查询报错、域名未注册：一律回退
    if (!live || live.error || live.registered === false) {
      return {
        ...freeInfo,
        lookupError: live && live.error ? live.error : null,
        lookupSkipped: Boolean(live && live.registered === false),
        dataSource: 'registry'
      };
    }

    const merged = {
      ...freeInfo,
      registrar: live.registrar && live.registrar !== 'Unknown' ? live.registrar : freeInfo.registrar,
      registrationDate: live.registrationDate && live.registrationDate !== 'Unknown'
        ? live.registrationDate
        : freeInfo.registrationDate,
      expirationDate: live.expirationDate && live.expirationDate !== 'Unknown'
        ? live.expirationDate
        : freeInfo.expirationDate,
      // 永久域名：DNSHE 升级后接口返回 2999 这类哨兵日期，解析层已经标记，
      // 这里要显式透传，否则 UI 会按"35 万天后到期"显示
      isPermanent: Boolean(live.isPermanent || freeInfo.isPermanent),
      status: live.status || 'active',
      // 只有真的拿到实时到期日才算"实时来源"，否则徽标会骗人
      dataSource: live.expirationDate && live.expirationDate !== 'Unknown' ? live.source : 'registry',
      liveLookup: true
    };

    if (Array.isArray(live.nameServers) && live.nameServers.length) {
      merged.nameServers = live.nameServers;
    }

    return merged;
  }

  async fetchWhoisWithRetry(domain) {
    let lastError;

    for (let attempt = 1; attempt <= CONFIG.MAX_RETRIES; attempt++) {
      try {
        console.log('第' + attempt + '次尝试: ' + domain);

        const response = await fetch(`${this.proxyUrl}/api/lookup?query=${domain}`, {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            'User-Agent': `DSMC/${CONFIG.VERSION}`,
            'Cache-Control': 'no-cache'
          },
          signal: AbortSignal.timeout(CONFIG.TIMEOUT)
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log(`收到WHOIS响应: ${domain}`, data);

        if (data.error === true || data.status === 'error' || data.status === false) {
          throw new Error(data.message || data.error_message || '未知WHOIS错误');
        }

        const parsed = this.parseWhoisData(data);
        console.log(`WHOIS解析成功: ${domain}`, parsed);
        return parsed;

      } catch (error) {
        lastError = error;
        console.warn('第' + attempt + '次失败: ' + domain + ' - ' + error.message);

        if (attempt < CONFIG.MAX_RETRIES) {
          const delay = attempt * 1000;
          console.log('⏳ 等待' + delay + 'ms后重试...');
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    console.error('所有重试失败: ' + domain, lastError.message);
    return {
      registrar: 'Unknown',
      registrationDate: 'Unknown',
      expirationDate: 'Unknown',
      whoisError: this.formatError(lastError)
    };
  }

  parseWhoisData(data) {
    const source = data.result || data;

    const extractors = {
      registrar: ['registrar', 'registrarName', 'registrar_name', 'sponsoringRegistrar', 'sponsoring_registrar'],
      registrationDate: ['creationDate', 'created', 'registrationDate', 'registration_date', 'creation_date'],
      expirationDate: ['expirationDate', 'expires', 'expiry', 'expiration_date', 'registry_expiry_date'],
      // 注册局状态（EPP）。RDAP 返回数组，WHOIS 文本可能是多行，这里统一原样带出来，
      // 分级交给 services/registry-status.js —— clientHold / pendingDelete 这类状态
      // 比"还有多少天到期"更紧急，但以前这条字段根本没被解析，白白丢掉了
      status: ['status', 'domainStatus', 'domain_status', 'eppStatus', 'epp_status']
    };

    const result = {};

    for (const [field, candidates] of Object.entries(extractors)) {
      let found = false;
      for (const candidate of candidates) {
        if (source[candidate] && !found) {
          if (field.includes('Date')) {
            result[field] = this.parseDate(source[candidate]);
          } else {
            result[field] = source[candidate].toString().trim();
          }
          found = true;
          console.log('提取' + field + ': ' + candidate + ' = ' + result[field]);
        }
      }
      if (!result[field]) {
        // status 缺失时留空而不是 'Unknown'：下游会把 'Unknown' 当成一个真实状态码，
        // 归进"未识别状态"里，日志与详情页都会出现一个并不存在的状态
        if (field !== 'status') result[field] = 'Unknown';
      }
    }

    // 如果关键信息缺失，尝试从原始数据解析
    if (result.registrar === 'Unknown' && result.registrationDate === 'Unknown' && result.expirationDate === 'Unknown') {
      const rawContent = source.rawWhoisContent || source.rawData || source.raw_data;
      if (rawContent && typeof rawContent === 'string') {
        console.log('尝试从原始数据解析...');
        const rawParsed = this.parseRawWhoisData(rawContent);
        return this.withPermanentFlag({ ...result, ...rawParsed });
      }
    }

    return this.withPermanentFlag(result);
  }

  /** 到期日落在 2900 年以后 = 永久域名，显式打标，避免 UI 算成几十万天 */
  withPermanentFlag(result) {
    if (result && isPermanentDate(result.expirationDate)) {
      result.isPermanent = true;
    }
    return result;
  }

  parseRawWhoisData(rawData) {
    if (!rawData || typeof rawData !== 'string') {
      return {};
    }

    console.log('解析原始WHOIS数据，长度: ' + rawData.length);

    const lines = rawData.split(/[\r\n]+/);
    const result = {};

    const patterns = {
      registrar: /^(?:registrar|sponsoring registrar|registrar name|registrant organization):\s*(.+)$/i,
      registrationDate: /^(?:creation date|created|registered|registration date|domain created):\s*(.+)$/i,
      expirationDate: /^(?:expiry date|expires|expiration date|registry expiry date|renewal date):\s*(.+)$/i
    };

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      for (const [field, pattern] of Object.entries(patterns)) {
        if (!result[field] || result[field] === 'Unknown') {
          const match = trimmed.match(pattern);
          if (match && match[1].trim()) {
            if (field.includes('Date')) {
              result[field] = this.parseDate(match[1].trim());
            } else {
              result[field] = match[1].trim();
            }
            console.log('从原始数据提取' + field + ': ' + result[field]);
          }
        }
      }
    }

    return result;
  }

  parseDate(dateString) {
    if (!dateString || dateString === 'Unknown' || dateString === 'N/A' || dateString === '') {
      return 'Unknown';
    }

    try {
      let cleanDate = dateString.toString().trim();

      // 清理时间戳格式
      cleanDate = cleanDate
        .replace(/\s+\(.+\)$/, '') // 移除括号
        .replace(/\s+[A-Z]{3,4}$/, '') // 移除时区
        .replace(/T\d{2}:\d{2}:\d{2}.*$/, '') // 移除时间
        .split(' ')[0]; // 只取日期部分

      let date = new Date(cleanDate);

      // 如果直接解析失败，尝试其他格式
      if (isNaN(date.getTime())) {
        // 处理 DD/MM/YYYY 或 MM/DD/YYYY
        if (cleanDate.includes('/')) {
          const parts = cleanDate.split('/');
          if (parts.length === 3) {
            date = new Date(`${parts[2]}-${parts[1].padStart(2, '0')}-${parts[0].padStart(2, '0')}`);
          }
        }
        // 处理 DD-MM-YYYY
        else if (cleanDate.includes('-') && cleanDate.split('-')[0].length === 2) {
          const parts = cleanDate.split('-');
          if (parts.length === 3) {
            date = new Date(`${parts[2]}-${parts[1]}-${parts[0]}`);
          }
        }
      }

      if (isNaN(date.getTime())) {
        console.warn('无效日期格式: ' + dateString);
        return 'Unknown';
      }

      const year = date.getFullYear();
      // 上限放到 9999：永久域名的哨兵日期（2999-12-31）不能当异常丢掉，
      // 否则永久域名会退化成「未知到期日」，比显示错日期更容易误导人
      if (year < 1985 || year > 9999) {
        console.warn('日期年份异常: ' + year);
        return 'Unknown';
      }

      return date.toISOString().split('T')[0];
    } catch (error) {
      console.error('日期解析错误:', error);
      return 'Unknown';
    }
  }

  formatError(error) {
    if (error.name === 'AbortError') {
      return 'WHOIS 查询超时';
    } else if (error.message.includes('fetch') || error.message.includes('network')) {
      return '网络连接错误';
    } else if (error.message.includes('JSON')) {
      return 'API 响应格式错误';
    }
    return error.message;
  }
}