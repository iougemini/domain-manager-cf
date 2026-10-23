// WHOIS 缓存管理

import { appState } from '../app-state.js';
import { CONFIG } from '../config.js';
import { logger } from '../logger.js';

export class CacheManager {
  constructor(namespace) {
    this.kv = namespace;
    this.memCache = new Map();      // 内存缓存层
    this.memCacheTTL = 60000;       // 内存缓存TTL: 60秒
  }

  async get(domain) {
    // 优先检查内存缓存
    const memCached = this.memCache.get(domain);
    if (memCached) {
      const memTtl = memCached.ttl > 0 ? memCached.ttl : this.memCacheTTL;
      if (Date.now() - memCached.timestamp < memTtl) {
        logger.debug('内存缓存命中', { domain });
        return memCached.data;
      }
      this.memCache.delete(domain);
    }

    const key = `whois_${domain}`;
    const data = await this.kv.get(key);

    if (!data) return null;

    try {
      const parsed = JSON.parse(data);
      const { data: domainData, timestamp, version } = parsed;

      // 版本检查（用 CACHE_VERSION 而不是展示用的 VERSION：
      // 改 UI / 改品牌不应该让全量 WHOIS 缓存失效）
      if (version && version !== CONFIG.CACHE_VERSION) {
        logger.info('版本不匹配,删除缓存', { domain, oldVersion: version, newVersion: CONFIG.CACHE_VERSION });
        await this.delete(domain);
        return null;
      }

      // 每条缓存可以自带 TTL：查询失败的记录只留几分钟，
      // 不然用户补好 Key 之后还要等 7 天才能看到正确结果
      const ttl = Number(parsed.ttl) > 0 ? Number(parsed.ttl) : CONFIG.CACHE_TTL;

      // 过期检查
      if (Date.now() - timestamp > ttl) {
        logger.debug('缓存过期,删除', { domain });
        await this.delete(domain);
        return null;
      }

      // 免费域名强制刷新检查
      if (appState.freeDomainManager?.isFree(domain) && domainData.registrar === 'Unknown') {
        logger.info('免费域名缓存异常,强制刷新', { domain });
        await this.delete(domain);
        return null;
      }

      // 免费域名兜底值陈旧检查：该后缀已配置实时查询接口，但缓存里还是
      // 'Auto-Renewal' 占位（说明是升级前的旧缓存），主动失效重查一次。
      // 已尝试过实时查询的（liveLookup / lookupError / lookupSkipped）不再重复，
      // 避免第三方接口故障时每次读缓存都触发一次失败查询。
      const freeEntry = appState.freeDomainManager?.getInfo(domain);
      if (
        freeEntry && freeEntry.lookup &&
        domainData.expirationDate === 'Auto-Renewal' &&
        !domainData.liveLookup && !domainData.lookupError && !domainData.lookupSkipped
      ) {
        logger.info('免费域名缓存为兜底值,重新查询', { domain, type: freeEntry.lookup.type });
        await this.delete(domain);
        return null;
      }

      // 写入内存缓存
      this.memCache.set(domain, { data: domainData, timestamp: Date.now() });

      return domainData;
    } catch (error) {
      logger.error('缓存解析错误', { domain, error: error.message });
      await this.delete(domain);
      return null;
    }
  }

  /**
   * @param {string} domain
   * @param {object} data
   * @param {number} [ttlMs] 覆盖默认 TTL。查询失败的记录传 CONFIG.CACHE_FAILURE_TTL，
   *        让"改完配置再刷新"能立刻生效，而不是被 7 天的失败缓存挡住
   */
  async set(domain, data, ttlMs) {
    const key = `whois_${domain}`;
    const ttl = Number(ttlMs) > 0 ? Number(ttlMs) : 0;
    const cacheData = {
      data,
      timestamp: Date.now(),
      version: CONFIG.CACHE_VERSION
    };
    if (ttl) cacheData.ttl = ttl;

    try {
      await this.kv.put(key, JSON.stringify(cacheData));
      // 同时更新内存缓存
      this.memCache.set(domain, { data, timestamp: Date.now(), ttl });
      logger.debug('缓存写入成功', { domain, ttl });
    } catch (error) {
      logger.error('缓存写入失败', { domain, error: error.message });
    }
  }

  /**
   * 按域名条件批量失效。
   * 典型场景：DNSHE 凭证改了，所有 DNSHE 域名的旧缓存（很可能是 401 的兜底值）
   * 必须立刻作废，否则用户改完 Key 还要等 TTL 到期。
   */
  async clearWhere(predicate) {
    if (typeof predicate !== 'function') return 0;

    const list = await this.kv.list({ prefix: 'whois_' });
    const domains = list.keys
      .map(item => item.name.slice('whois_'.length))
      .filter(predicate);

    for (const domain of domains) {
      this.memCache.delete(domain);
      try {
        await this.kv.delete(`whois_${domain}`);
      } catch (error) {
        logger.error('删除缓存失败', { domain, error: error.message });
      }
    }

    if (domains.length) logger.info('按条件清理缓存完成', { count: domains.length });
    return domains.length;
  }

  async delete(domain) {
    this.memCache.delete(domain);  // 同时清除内存缓存
    await this.kv.delete(`whois_${domain}`);
  }

  async clearAll() {
    // 清空内存缓存
    this.memCache.clear();

    const list = await this.kv.list({ prefix: 'whois_' });
    let deletedCount = 0;

    const batchSize = 50;
    for (let i = 0; i < list.keys.length; i += batchSize) {
      const batch = list.keys.slice(i, i + batchSize);

      await Promise.all(batch.map(async (key) => {
        try {
          await this.kv.delete(key.name);
          deletedCount++;
        } catch (error) {
          logger.error('删除缓存失败', { key: key.name, error: error.message });
        }
      }));

      if (i + batchSize < list.keys.length) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }

    logger.info('缓存清理完成', { deletedCount });
    return deletedCount;
  }

  // 获取缓存统计信息
  getStats() {
    return {
      memCacheSize: this.memCache.size,
      memCacheTTL: this.memCacheTTL
    };
  }
}