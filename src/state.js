// 状态编排层 - 初始化配置/管理器, 以及跨模块编排函数

import { appState } from './app-state.js';
import {
  CONFIG,
  PROJECT,
  CF_API_KEYS_FALLBACK,
  USERNAMES_FALLBACK,
  ACCESS_PASSWORD_FALLBACK,
  ADMIN_PASSWORD_FALLBACK,
  validateConfig
} from './config.js';
import { logger } from './logger.js';
import { ApiKeyManager } from './managers/api-key.js';
import { CacheManager } from './managers/cache.js';
import { FreeDomainManager } from './managers/free-domain.js';
import { loadFreeDomainEntries } from './managers/free-domain-store.js';
import { CustomDomainManager } from './managers/custom-domain.js';
import { resolveAccounts } from './managers/accounts-store.js';
import { loadDnsheCredentials } from './managers/dnshe-store.js';
import { loadSettingsWithMeta, applySettings } from './managers/settings-store.js';
import { loadNotifyConfig, loadNotifyState } from './managers/notify-store.js';
import { WhoisService } from './services/whois.js';
import { FreeDomainLookup, isPermanentDate } from './services/free-domain-lookup.js';
import { mergeCustomDomainRecord } from './services/domain-merge.js';
import { CloudflareFetcher } from './services/cloudflare.js';
import { readHealthBatch } from './managers/health-store.js';

/**
 * 初始化运行时配置
 * 每个请求都会调用, 从环境变量 + KV 重新加载配置, 避免跨请求状态污染 (P2)
 *
 * 是 async 的：设置、账户、DNSHE 凭证都存在 KV 里（带 60 秒内存缓存），
 * 调用方必须 await，否则页面会用上一份配置渲染。
 */
export async function initConfig(env) {
  appState.env = env;
  const kv = env ? env.DOMAIN_INFO : null;

  // ── 1. 设置（密码 / 代理 / 查询节奏）────────────────────────────
  // KV 明确写过的字段优先，其次环境变量，最后代码默认值
  //
  // 这五份配置互不依赖（都只读 KV / env），串行读等于把 KV 的往返延迟
  // 叠加五次。并行读之后冷启动少几十毫秒，而这几毫秒是页面首字节的一部分。
  const [settingsResult, accountsResult, dnsheAll, notifyConfig, notifyState] = await Promise.all([
    loadSettingsWithMeta(kv),
    resolveAccounts(kv, env),
    loadDnsheCredentials(kv),
    loadNotifyConfig(kv),
    loadNotifyState(kv)
  ]);

  const { settings, explicit } = settingsResult;
  appState.settings = settings;
  applySettings(settings, env, explicit);

  // ── 2. Cloudflare 账户（KV 优先，环境变量兜底）──────────────────
  const { accounts, source } = accountsResult;
  appState.accounts = accounts;
  appState.accountSource = source;

  // 兼容老代码里直接读这两个数组的地方（validateConfig / ApiKeyManager）
  appState.CF_API_KEYS = accounts.map(a => a.token).filter(Boolean);
  appState.USERNAMES = accounts.map(a => a.username || '未命名账户');

  if (!accounts.length) {
    // 完全没配置时保留旧行为：用硬编码 fallback（生产不该走到这里）
    appState.CF_API_KEYS = CF_API_KEYS_FALLBACK;
    appState.USERNAMES = USERNAMES_FALLBACK;
  }

  // ── 3. DNSHE 查询凭证 ─────────────────────────────────────────
  // 全量给页面展示（含停用），生效的给查询器用
  appState.dnsheAll = dnsheAll;
  appState.dnsheCredentials = dnsheAll.filter(item => item.enabled !== false);

  // 环境变量兜底：老部署用的是 DNSHE_API_KEY / DNSHE_API_SECRET，
  // 不能在升级后突然失效。KV 里一条都没有时才用环境变量——
  // 只要用户在页面里建过凭证，就以页面为准（包括"全部停用"的意图）。
  appState.dnsheEnv = {
    hasKey: Boolean(env && env.DNSHE_API_KEY),
    hasSecret: Boolean(env && env.DNSHE_API_SECRET)
  };
  if (!dnsheAll.length && appState.dnsheEnv.hasKey) {
    appState.dnsheCredentials = [{
      id: 'env',
      label: '环境变量',
      key: String(env.DNSHE_API_KEY).trim(),
      secret: String(env.DNSHE_API_SECRET || '').trim(),
      enabled: true,
      source: 'env'
    }];
  }

  // ── 4. 通知配置与发送状态（页面渲染要用）──────────────────────
  appState.notifyConfig = notifyConfig;
  appState.notifyState = notifyState;

  // 加载 TOKEN_SECRET 的兜底逻辑已由 applySettings 处理；
  // 这里只处理"完全没配置密码"的老部署
  if (!appState.ACCESS_PASSWORD && !appState.ACCESS_PASSWORD_HASH) {
    logger.warn('未设置访问密码,使用硬编码值(不安全!)');
    appState.ACCESS_PASSWORD = ACCESS_PASSWORD_FALLBACK;
  }
  if (!appState.ADMIN_PASSWORD && !appState.ADMIN_PASSWORD_HASH) {
    logger.warn('未设置管理员密码,使用硬编码值(不安全!)');
    appState.ADMIN_PASSWORD = ADMIN_PASSWORD_FALLBACK;
  }

  // 项目身份可覆盖，方便 fork 后换成自己的仓库与社群
  if (env && env.PROJECT_GITHUB_URL) PROJECT.GITHUB = String(env.PROJECT_GITHUB_URL).trim();
  if (env && env.PROJECT_COMMUNITY_URL) PROJECT.COMMUNITY = String(env.PROJECT_COMMUNITY_URL).trim();
  if (env && env.PROJECT_WECHAT_ID) PROJECT.WECHAT = String(env.PROJECT_WECHAT_ID).trim();

  // 配置验证
  const configErrors = validateConfig();
  if (configErrors.length > 0) {
    logger.error('配置错误', { errors: configErrors });
  }

  logger.info('配置加载完成', {
    accounts: accounts.length,
    accountSource: source,
    dnsheCredentials: appState.dnsheCredentials.length,
    settingsFromKV: explicit.size
  });
}

/**
 * 初始化管理器实例
 * 每个请求都重建实例, 彻底消除同 isolate 跨请求的状态污染 (P2)
 *
 * 注意是 async：免费域名白名单要读 KV 的 config:free-domains（带 60s 内存缓存），
 * 所以调用方必须 await，否则页面会用旧白名单渲染。
 */
/**
 * WHOIS 缓存实例。**跨请求复用**，这是它内存层能不能起作用的关键。
 *
 * 早先每个请求都 new 一个 CacheManager，构造出来的 memCache 是空的、
 * 请求结束就丢，等于每次渲染都把全部域名重新读一遍 KV（几十次读）。
 * 现在按 KV 命名空间做单例：同一个 isolate 内 60 秒内的重复读直接命中内存。
 */
let sharedCacheManager = null;

export async function initManagers() {
  appState.apiKeyManager = new ApiKeyManager();
  // 账户已经在 initConfig 里从 KV/环境变量解析好了，这里直接灌进去，
  // 不再让 ApiKeyManager 自己去猜数据从哪来
  appState.apiKeyManager.initFromAccounts(appState.accounts);

  const kv = appState.env ? appState.env.DOMAIN_INFO : null;
  if (kv) {
    if (!sharedCacheManager || sharedCacheManager.kv !== kv) {
      sharedCacheManager = new CacheManager(kv);
    }
    appState.cacheManager = sharedCacheManager;
  } else {
    appState.cacheManager = null;
  }

  // 免费域名白名单：内置表 < 环境变量 FREE_DOMAIN_SUFFIXES < KV config:free-domains
  // KV 层可以在「免费域名」页面直接改，60 秒内生效，不需要重新部署
  const kvEntries = await loadFreeDomainEntries(appState.env ? appState.env.DOMAIN_INFO : null);
  appState.freeDomainManager = new FreeDomainManager({
    overrides: appState.env ? appState.env.FREE_DOMAIN_SUFFIXES : undefined,
    kvEntries
  });
  appState.customDomainManager = new CustomDomainManager();

  // 重置依赖上述管理器的服务单例
  appState.whoisService = null;
  appState.cloudflareFetcher = null;
  appState.rateLimiter = null;
  appState.auditLogger = null;
}

export async function cleanupKV() {
  logger.info('开始清理KV错误数据...');

  if (!appState.env || !appState.env.DOMAIN_INFO) {
    logger.error('DOMAIN_INFO KV命名空间未初始化');
    return;
  }

  try {
    const list = await appState.env.DOMAIN_INFO.list({ prefix: 'whois_' });
    let cleanedCount = 0;

    for (const key of list.keys) {
      const value = await appState.env.DOMAIN_INFO.get(key.name);
      if (value) {
        try {
          const parsed = JSON.parse(value);
          const { data } = parsed;

          // 清理有错误的缓存数据
          if (data && data.whoisError && data.whoisError.includes('网络连接错误')) {
            await appState.env.DOMAIN_INFO.delete(key.name);
            cleanedCount++;
            logger.info('清理错误缓存', { key: key.name });
          }
        } catch (error) {
          // 清理损坏的缓存数据
          await appState.env.DOMAIN_INFO.delete(key.name);
          cleanedCount++;
          logger.info('清理损坏缓存', { key: key.name });
        }
      }
    }

    if (cleanedCount > 0) {
      logger.info('KV清理完成', { cleanedCount });
    } else {
      logger.info('KV数据正常，无需清理');
    }
  } catch (error) {
    logger.error('KV清理过程出错', { error: error.message });
  }
}

export function getWhoisService() {
  if (!appState.whoisService && appState.cacheManager && appState.freeDomainManager) {
    // 免费域名查询器：DigitalPlat 走 RDAP，DNSHE 走自有 WHOIS 接口。
    // DNSHE 的凭证存在 KV 里（可能多条），查询时按顺序尝试、401 自动换下一把。
    const credentials = (appState.dnsheCredentials || []).map(item => ({
      key: item.key,
      secret: item.secret,
      id: item.id
    }));

    const freeLookup = new FreeDomainLookup({
      enabled: CONFIG.FREE_DOMAIN_LIVE_LOOKUP,
      timeout: CONFIG.FREE_DOMAIN_LOOKUP_TIMEOUT,
      userAgent: CONFIG.FREE_DOMAIN_LOOKUP_UA || undefined,
      dnsheCredentials: credentials,
      // pp.ua 这类没有 HTTP 接口的服务走 43 端口，通道由入口注入
      // （Workers 用 cloudflare:sockets；Node 测试环境没有，查询会自然降级）
      whoisTransport: appState.whoisTransport || null
    });

    appState.whoisService = new WhoisService(
      CONFIG.WHOIS_PROXY,
      appState.cacheManager,
      appState.freeDomainManager,
      { freeLookup }
    );
    logger.info('WhoisService初始化完成', {
      freeLookup: CONFIG.FREE_DOMAIN_LIVE_LOOKUP,
      dnsheCredentials: credentials.length
    });
  }
  return appState.whoisService;
}

export async function fetchCloudflareDomainsInfo(options = {}) {
  try {
    if (!appState.cloudflareFetcher && appState.apiKeyManager) {
      appState.cloudflareFetcher = new CloudflareFetcher(
        appState.apiKeyManager,
        appState.env ? appState.env.DOMAIN_INFO : null
      );
      logger.info('CloudflareFetcher初始化完成');
    }

    if (!appState.cloudflareFetcher) {
      logger.error('CloudflareFetcher未初始化');
      return [];
    }

    return await appState.cloudflareFetcher.fetchAllDomains(options);
  } catch (error) {
    logger.error('获取Cloudflare域名失败', { error: error.message });
    return [];
  }
}

/**
 * 补齐域名详情。
 *
 * @param {Array} domains Cloudflare / 自定义域名列表
 * @param {{budgetMs?: number}} [options]
 *        budgetMs 是"允许花在实时查询上的时间"。超过之后切到只读缓存模式，
 *        未命中的域名标 pending，由调用方安排后台补全。
 *        不传则不限时（刷新按钮、定时任务走这条路）。
 * @returns {Promise<{domains: Array, pending: number}>}
 */
export async function fetchDomainInfo(domains, options = {}) {
  if (!domains || domains.length === 0) {
    logger.info('没有域名需要处理');
    return { domains: [], pending: 0 };
  }

  const budgetMs = Number.isFinite(options.budgetMs) && options.budgetMs > 0
    ? options.budgetMs
    : Infinity;
  const deadline = budgetMs === Infinity ? Infinity : Date.now() + budgetMs;
  const overBudget = () => Date.now() > deadline;

  logger.info('开始处理域名信息', { count: domains.length, budgetMs });

  // 加载自定义域名
  await appState.customDomainManager.loadFromKV();
  const customDomains = appState.customDomainManager.getAllDomains();

  // 合并Cloudflare域名和自定义域名 - 自定义域名优先用于覆盖修正
  const customDomainsMap = new Map(customDomains.map(d => [d.domain, d]));

  const allDomainsToProcess = [
    ...domains.map(domain => {
      const customOverride = customDomainsMap.get(domain.name);
      if (customOverride) {
        return {
          ...domain,
          hasCustomOverride: true,
          customInfo: customOverride
        };
      }
      return domain;
    }),
    ...customDomains
      .filter(domain => !domains.some(d => d.name === domain.domain))
      .map(domain => ({
        name: domain.domain,
        account: 'custom',
        username: '自定义域名',
        isCustomDomain: true,
        customInfo: domain
      }))
  ];

  logger.info('域名统计', {
    cloudflare: domains.length,
    custom: customDomains.length,
    total: allDomainsToProcess.length
  });

  const results = [];
  const batchSize = CONFIG.BATCH_SIZE;

  // 巡检结论一次批量读出来挂到域名上。这里**只读 KV，不发网络请求** ——
  // DNS 探测跑在 Cron 里（managers/health-store.js），渲染路径塞不进几十个域名的探测，
  // 而且用户打开页面的时刻本来也不该决定"要不要探测"
  const healthMap = await readHealthBatch(
    appState.env ? appState.env.DOMAIN_INFO : null,
    allDomainsToProcess.map(item => item.name)
  );

  /**
   * 单个域名的处理（原批次循环里的内联逻辑，抽出来给不同限流策略复用）
   */
  /**
   * 自定义域名（含 Cloudflare 域名的本地覆盖记录）取值。
   *
   * 关键点：**除非用户手工改过（autoUpdateWhois === false），否则照常查一次**。
   * 以前这里直接用 KV 里那条记录，等于新增域名只查了添加那一刻，
   * 之后到期日永远不变——用户只能靠「标记已续费」硬改。
   */
  const resolveCustom = async (domain, info) => {
    const manualOnly = info.autoUpdateWhois === false;
    let live = null;

    if (!manualOnly) {
      try {
        live = await getWhoisService().query(domain.name, { cacheOnly: overBudget() });
      } catch (error) {
        logger.warn('自定义域名查询失败', { domain: domain.name, error: error.message });
      }
    }

    const merged = mergeCustomDomainRecord(info, live);
    // 免费后缀的永久属性来自注册表，merge 里看不到，这里补上
    merged.isPermanent = merged.isPermanent
      || appState.freeDomainManager.isPermanent(domain.name);

    return {
      ...domain,
      ...merged,
      status: info.status || 'Active',
      notes: info.notes || '',
      serviceProvider: info.serviceProvider,
      isFree: appState.freeDomainManager.isFree(domain.name),
      lastUpdated: info.lastUpdated || new Date().toISOString()
    };
  };

  const processDomainCore = async (domain) => {
    try {
      let processedDomain;

      if (domain.isCustomDomain) {
        processedDomain = await resolveCustom(domain, domain.customInfo);
      } else if (domain.hasCustomOverride) {
        processedDomain = {
          ...(await resolveCustom(domain, domain.customInfo)),
          isManuallyEdited: true
        };
      } else {
        // service.query() 内部已处理免费域名：配置了 lookup 时会拉取真实到期日，
        // 失败则回退到注册表元数据。这里直接采信它的返回值，不再用 freeInfo 覆盖，
        // 否则实时查到的 expirationDate 会被 'Auto-Renewal' 顶掉。
        const service = getWhoisService();
        const whoisInfo = await service.query(domain.name, { cacheOnly: overBudget() });
        const freeInfo = appState.freeDomainManager.getInfo(domain.name);

        processedDomain = {
          ...domain,
          registrar: whoisInfo.registrar || 'Unknown',
          registrationDate: whoisInfo.registrationDate || 'Unknown',
          expirationDate: whoisInfo.expirationDate || 'Unknown',
          whoisError: whoisInfo.whoisError || null,
          isFree: Boolean(freeInfo),
          // 永久域名有两个来源：注册表规则（eu.org 这类）和接口返回的哨兵日期
          // （DNSHE 升级永久后返回 2999-12-31）。两者取或，缺一个就会显示成
          // 「35 万天后到期」或者「待设置」。
          isPermanent: Boolean((freeInfo && freeInfo.isPermanent)
            || whoisInfo.isPermanent
            || isPermanentDate(whoisInfo.expirationDate)),
          dataSource: whoisInfo.dataSource || null,
          // 本次没来得及查（超出渲染预算），后台会补
          pending: Boolean(whoisInfo.pending),
          lastUpdated: new Date().toISOString()
        };

        if (Array.isArray(whoisInfo.nameServers) && whoisInfo.nameServers.length) {
          processedDomain.nameServers = whoisInfo.nameServers;
        }
        if (whoisInfo.lookupError) processedDomain.lookupError = whoisInfo.lookupError;
        if (whoisInfo.lookupSkipped) processedDomain.lookupSkipped = true;
      }

      return processedDomain;
    } catch (error) {
      logger.error('处理域名失败', { domain: domain.name, error: error.message });
      return {
        ...domain,
        registrar: domain.isCustomDomain ? domain.customInfo.registrar : 'Error',
        registrationDate: domain.isCustomDomain ? domain.customInfo.registrationDate : 'Error',
        expirationDate: domain.isCustomDomain ? domain.customInfo.expirationDate : 'Error',
        whoisError: error.message,
        isFree: appState.freeDomainManager.isFree(domain.name),
        lastUpdated: new Date().toISOString()
      };
    }
  };

  /**
   * 包一层：把巡检结论挂到域名记录上。
   * 探测本身不在请求路径上跑，这里只是把 Cron 已经算好的结论贴上去。
   */
  const processDomain = async (domain) => {
    const record = await processDomainCore(domain);
    const health = healthMap.get(domain.name);
    return health ? { ...record, health } : record;
  };

  // 按服务商分组限流。DNSHE 公共接口 30 次/分钟，68 个域名一次全量刷新必然超限；
  // 分组后各服务商并行、组内串行，互不拖累。
  const groups = new Map();
  for (const item of allDomainsToProcess) {
    const provider = providerOf(item);
    if (!groups.has(provider)) groups.set(provider, []);
    groups.get(provider).push(item);
  }

  logger.info('按服务商分组刷新', {
    groups: Array.from(groups.entries()).map(([k, v]) => k + ':' + v.length).join(', ')
  });

  const chunks = await Promise.all(
    Array.from(groups.entries()).map(([provider, list]) => (
      provider === 'proxy'
        ? runBatched(list, batchSize, 500, processDomain)
        : runPaced(list, paceFor(provider), processDomain)
    ))
  );

  for (const chunk of chunks) results.push(...chunk);

  const pending = results.filter(item => item && item.pending).length;

  logger.info('域名信息处理完成', {
    processed: results.length,
    total: allDomainsToProcess.length,
    pending
  });
  return { domains: results, pending };
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/** 该域名会走哪个查询通道，决定它的限流节奏 */
function providerOf(domain) {
  const info = appState.freeDomainManager.getInfo(domain.name);
  return info && info.lookup ? info.lookup.type : 'proxy';
}

function paceFor(type) {
  if (type === 'dnshe') return CONFIG.PACE_DNSHE;
  if (type === 'whois') return CONFIG.PACE_WHOIS;
  if (type === 'rdap') return CONFIG.PACE_RDAP;
  return 500;
}

/** 普通域名：保持原有批量并发（WHOIS 代理能承受，且大多数命中的是缓存） */
async function runBatched(list, size, gap, fn) {
  const out = [];

  for (let i = 0; i < list.length; i += size) {
    const startedAt = Date.now();
    const batch = list.slice(i, i + size);
    const settled = await Promise.allSettled(batch.map(fn));

    for (const result of settled) {
      if (result.status === 'fulfilled') out.push(result.value);
      else logger.error('Promise处理失败', { reason: result.reason });
    }

    // 间隔是为了保护上游接口。整批都在几十毫秒内返回说明全是缓存命中、
    // 一个请求都没发出去，这时候再等 500ms 纯属浪费（超预算后尤其明显）
    if (i + size < list.length && gap && Date.now() - startedAt >= 50) await sleep(gap);
  }

  return out;
}

/**
 * 免费域名：组内串行 + 最小间隔。
 *
 * 关键细节：间隔只加在"真的发生了网络请求"之间。命中缓存时 fn 会瞬间返回，
 * 此时不必等待——否则一次刷新里 68 个域名全被缓存命中也要白等两分钟。
 * 用耗时是否超过 50ms 来近似判断（缓存命中远快于此）。
 */
async function runPaced(list, gap, fn) {
  const out = [];
  let lastNetworkAt = 0;

  for (let i = 0; i < list.length; i++) {
    if (lastNetworkAt) {
      const wait = gap - (Date.now() - lastNetworkAt);
      if (wait > 0) await sleep(wait);
    }

    const startedAt = Date.now();
    try {
      out.push(await fn(list[i]));
    } catch (error) {
      logger.error('域名处理失败', { domain: list[i] && list[i].name, error: error.message });
    }

    if (Date.now() - startedAt >= 50) lastNetworkAt = Date.now();
  }

  return out;
}

/**
 * 为到期提醒收集域名。
 *
 * 刻意**不做全量刷新**：cron 触发时如果按正常流程查一遍，DNSHE 组按 2 秒一个
 * 排队，几十个域名就会跑几分钟，Workers 的 waitUntil 撑不到那时候。
 * 所以策略是：
 *   1. 拉 Cloudflare 的 Zone 列表（每个账户一次分页请求，很快）
 *   2. 优先读 KV 缓存——日常有人访问页面，缓存本来就是热的
 *   3. 缓存缺失的，最多补查 maxLive 个（默认 12），其余留到下次
 *
 * 结果是"提醒反映最近一次已知状态"，而不是"强制刷新一次"。这个取舍换来了
 * 定时任务的时间可控，对每日提醒来说完全够用。
 */
export async function collectDomainsForDigest(options = {}) {
  const maxLive = Number.isFinite(options.maxLive) ? Math.max(0, options.maxLive) : 12;
  const out = [];
  const pending = [];

  let zones = [];
  try {
    zones = await fetchCloudflareDomainsInfo();
  } catch (error) {
    logger.error('提醒任务拉取域名失败', { error: error.message });
  }

  const cache = appState.cacheManager;

  for (const zone of zones) {
    const name = zone && zone.name;
    if (!name) continue;

    let info = null;
    try {
      if (cache) info = await cache.get(name);
    } catch (e) {
      info = null;
    }

    if (info) {
      out.push({
        name,
        account: zone.username || '',
        registrar: info.registrar || 'Unknown',
        expirationDate: info.expirationDate || 'Unknown',
        isPermanent: Boolean(info.isPermanent) || isPermanentDate(info.expirationDate),
        // 注册局状态（EPP）交给巡检判定。这里只搬运，不做解释
        status: info.status || null
      });
    } else {
      pending.push({ name, account: zone.username || '' });
    }
  }

  // 自定义域名直接来自 KV，不需要网络
  try {
    await appState.customDomainManager.loadFromKV();
    for (const item of appState.customDomainManager.getAllDomains()) {
      out.push({
        name: item.domain,
        account: '自定义域名',
        registrar: item.registrar || 'Unknown',
        expirationDate: item.expirationDate || 'Unknown',
        isPermanent: isPermanentDate(item.expirationDate),
        status: item.status || null
      });
    }
  } catch (e) {
    logger.warn('提醒任务读取自定义域名失败', { error: e.message });
  }

  const service = getWhoisService();
  if (service) {
    for (const item of pending.slice(0, maxLive)) {
      try {
        const info = await service.query(item.name);
        out.push({
          name: item.name,
          account: item.account,
          registrar: info.registrar || 'Unknown',
          expirationDate: info.expirationDate || 'Unknown',
          isPermanent: Boolean(info.isPermanent) || isPermanentDate(info.expirationDate)
        });
      } catch (error) {
        logger.warn('提醒任务补查失败', { domain: item.name, error: error.message });
      }
    }
  }

  logger.info('提醒任务域名收集完成', {
    total: out.length,
    cached: out.length - Math.min(pending.length, maxLive),
    live: Math.min(pending.length, maxLive),
    skipped: Math.max(0, pending.length - maxLive)
  });

  return out;
}