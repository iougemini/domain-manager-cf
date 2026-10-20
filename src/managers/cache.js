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
    if (memCached && Date.now() - memCached.timestamp < this.memCacheTTL) {
      logger.debug('内存缓存命中', { domain });
      return memCached.data;
    }

    const key = `whois_${domain}`;
    const data = await this.kv.get(key);

    if (!data) return null;

    try {
      const parsed = JSON.parse(data);
      const { data: domainData, timestamp, version } = parsed;

      // 版本检查
      if (version && version !== CONFIG.VERSION) {
        logger.info('版本不匹配,删除缓存', { domain, oldVersion: version, newVersion: CONFIG.VERSION });
        await this.delete(domain);
        return null;
      }

      // 过期检查
      if (Date.now() - timestamp > CONFIG.CACHE_TTL) {
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

      // 写入内存缓存
      this.memCache.set(domain, { data: domainData, timestamp: Date.now() });

      return domainData;
    } catch (error) {
      logger.error('缓存解析错误', { domain, error: error.message });
      await this.delete(domain);
      return null;
    }
  }

  async set(domain, data) {
    const key = `whois_${domain}`;
    const cacheData = {
      data,
      timestamp: Date.now(),
      version: CONFIG.VERSION
    };

    try {
      await this.kv.put(key, JSON.stringify(cacheData));
      // 同时更新内存缓存
      this.memCache.set(domain, { data, timestamp: Date.now() });
      logger.debug('缓存写入成功', { domain });
    } catch (error) {
      logger.error('缓存写入失败', { domain, error: error.message });
    }
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