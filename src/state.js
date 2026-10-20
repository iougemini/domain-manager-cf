// 状态编排层 - 初始化配置/管理器, 以及跨模块编排函数

import { appState } from './app-state.js';
import {
  CONFIG,
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
import { CustomDomainManager } from './managers/custom-domain.js';
import { WhoisService } from './services/whois.js';
import { CloudflareFetcher } from './services/cloudflare.js';

/**
 * 初始化运行时配置
 * 每个请求都会调用, 从环境变量重新加载配置, 避免跨请求状态污染 (P2)
 */
export function initConfig(env) {
  appState.env = env;

  // 从环境变量加载配置(优先级高于 fallback 值)
  if (env.CF_API_KEYS) {
    try {
      appState.CF_API_KEYS = JSON.parse(env.CF_API_KEYS);
      logger.info('已从环境变量加载 CF_API_KEYS');
    } catch (e) {
      logger.warn('环境变量 CF_API_KEYS 格式错误,使用fallback值');
      appState.CF_API_KEYS = CF_API_KEYS_FALLBACK;
    }
  } else {
    logger.warn('未设置环境变量 CF_API_KEYS,使用硬编码值(不安全!)');
    appState.CF_API_KEYS = CF_API_KEYS_FALLBACK;
  }

  if (env.USERNAMES) {
    try {
      appState.USERNAMES = JSON.parse(env.USERNAMES);
      logger.info('已从环境变量加载 USERNAMES');
    } catch (e) {
      logger.warn('环境变量 USERNAMES 格式错误,使用fallback值');
      appState.USERNAMES = USERNAMES_FALLBACK;
    }
  } else {
    logger.warn('未设置环境变量 USERNAMES,使用硬编码值');
    appState.USERNAMES = USERNAMES_FALLBACK;
  }

  if (env.ACCESS_PASSWORD !== undefined) {
    appState.ACCESS_PASSWORD = env.ACCESS_PASSWORD;
    logger.info('已从环境变量加载 ACCESS_PASSWORD');
  } else {
    logger.warn('未设置环境变量 ACCESS_PASSWORD,使用硬编码值(不安全!)');
    appState.ACCESS_PASSWORD = ACCESS_PASSWORD_FALLBACK;
  }

  if (env.ADMIN_PASSWORD) {
    appState.ADMIN_PASSWORD = env.ADMIN_PASSWORD;
    logger.info('已从环境变量加载 ADMIN_PASSWORD');
  } else {
    logger.warn('未设置环境变量 ADMIN_PASSWORD,使用硬编码值(不安全!)');
    appState.ADMIN_PASSWORD = ADMIN_PASSWORD_FALLBACK;
  }

  // 加载 TOKEN_SECRET (P2: 独立 token 签名密钥, 未配置时回退到密码)
  if (env.TOKEN_SECRET) {
    appState.TOKEN_SECRET = env.TOKEN_SECRET;
    logger.info('已从环境变量加载 TOKEN_SECRET');
  } else {
    appState.TOKEN_SECRET = '';
  }

  // 加载 WHOIS_PROXY 配置
  if (env.WHOIS_PROXY) {
    CONFIG.WHOIS_PROXY = env.WHOIS_PROXY;
    logger.info('已从环境变量加载 WHOIS_PROXY', { proxy: CONFIG.WHOIS_PROXY });
  }

  // 配置验证
  const configErrors = validateConfig();
  if (configErrors.length > 0) {
    logger.error('配置错误', { errors: configErrors });
  }
}

/**
 * 初始化管理器实例
 * 每个请求都重建实例, 彻底消除同 isolate 跨请求的状态污染 (P2)
 */
export function initManagers() {
  appState.apiKeyManager = new ApiKeyManager();
  appState.apiKeyManager.initFromEnv();

  if (appState.env && appState.env.DOMAIN_INFO) {
    appState.cacheManager = new CacheManager(appState.env.DOMAIN_INFO);
  } else {
    appState.cacheManager = null;
  }

  appState.freeDomainManager = new FreeDomainManager();
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
    appState.whoisService = new WhoisService(CONFIG.WHOIS_PROXY, appState.cacheManager, appState.freeDomainManager);
    logger.info('WhoisService初始化完成');
  }
  return appState.whoisService;
}

export async function fetchCloudflareDomainsInfo() {
  try {
    if (!appState.cloudflareFetcher && appState.apiKeyManager) {
      appState.cloudflareFetcher = new CloudflareFetcher(appState.apiKeyManager);
      logger.info('CloudflareFetcher初始化完成');
    }

    if (!appState.cloudflareFetcher) {
      logger.error('CloudflareFetcher未初始化');
      return [];
    }

    return await appState.cloudflareFetcher.fetchAllDomains();
  } catch (error) {
    logger.error('获取Cloudflare域名失败', { error: error.message });
    return [];
  }
}

export async function fetchDomainInfo(domains) {
  if (!domains || domains.length === 0) {
    logger.info('没有域名需要处理');
    return [];
  }

  logger.info('开始处理域名信息', { count: domains.length });

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

  for (let i = 0; i < allDomainsToProcess.length; i += batchSize) {
    const batch = allDomainsToProcess.slice(i, i + batchSize);
    logger.info('处理批次', { batch: Math.floor(i / batchSize) + 1, total: Math.ceil(allDomainsToProcess.length / batchSize), count: batch.length });

    const promises = batch.map(async (domain) => {
      try {
        let processedDomain;

        if (domain.isCustomDomain) {
          processedDomain = {
            ...domain,
            registrar: domain.customInfo.registrar,
            registrationDate: domain.customInfo.registrationDate,
            expirationDate: domain.customInfo.expirationDate,
            nameServers: domain.customInfo.nameServers,
            status: domain.customInfo.status,
            notes: domain.customInfo.notes,
            serviceProvider: domain.customInfo.serviceProvider,
            isFree: appState.freeDomainManager.isFree(domain.name),
            lastUpdated: domain.customInfo.lastUpdated || new Date().toISOString()
          };
        } else if (domain.hasCustomOverride) {
          processedDomain = {
            ...domain,
            registrar: domain.customInfo.registrar || 'Unknown',
            registrationDate: domain.customInfo.registrationDate || 'Unknown',
            expirationDate: domain.customInfo.expirationDate || 'Unknown',
            nameServers: domain.customInfo.nameServers || [],
            status: domain.customInfo.status || 'Active',
            notes: domain.customInfo.notes || '',
            serviceProvider: domain.customInfo.serviceProvider,
            isFree: appState.freeDomainManager.isFree(domain.name),
            lastUpdated: domain.customInfo.lastUpdated || new Date().toISOString(),
            isManuallyEdited: true
          };
        } else {
          const service = getWhoisService();
          const whoisInfo = await service.query(domain.name);

          const freeInfo = appState.freeDomainManager.getInfo(domain.name);
          if (freeInfo && !whoisInfo.whoisError) {
            processedDomain = {
              ...domain,
              registrar: freeInfo.registrar || whoisInfo.registrar || 'Unknown',
              registrationDate: freeInfo.registrationDate || whoisInfo.registrationDate || 'Unknown',
              expirationDate: freeInfo.expirationDate || whoisInfo.expirationDate || 'Unknown',
              whoisError: null,
              isFree: true,
              lastUpdated: new Date().toISOString()
            };
          } else {
            processedDomain = {
              ...domain,
              registrar: whoisInfo.registrar || 'Unknown',
              registrationDate: whoisInfo.registrationDate || 'Unknown',
              expirationDate: whoisInfo.expirationDate || 'Unknown',
              whoisError: whoisInfo.whoisError || null,
              isFree: appState.freeDomainManager.isFree(domain.name),
              lastUpdated: new Date().toISOString()
            };
          }
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
    });

    const batchResults = await Promise.allSettled(promises);

    for (const result of batchResults) {
      if (result.status === 'fulfilled') {
        results.push(result.value);
      } else {
        logger.error('Promise处理失败', { reason: result.reason });
      }
    }

    if (i + batchSize < allDomainsToProcess.length) {
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }

  logger.info('域名信息处理完成', { processed: results.length, total: allDomainsToProcess.length });
  return results;
}