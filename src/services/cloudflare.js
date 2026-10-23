// Cloudflare 域名信息获取 + API 测试

import { logger } from '../logger.js';

/**
 * Zone 列表的缓存时长。
 *
 * 为什么值得缓存：页面每次渲染都要知道"有哪些域名"，而这份列表来自
 * api.cloudflare.com。Workers 到 Cloudflare API 的一次往返 200–600ms，
 * 比读一次 KV（10–30ms）贵一个数量级，而且这块数据几乎不变。
 *
 * 为什么只有 2 分钟：用户在 Cloudflare 面板里新加一个域名后，最多等 2 分钟
 * 就能在 DSMC 看到。再长就会被当成"漏域名"报 bug。
 */
const ZONE_CACHE_TTL = 2 * 60 * 1000;
const ZONE_CACHE_KEY = 'cache:zones:v1';

// 进程内缓存。KV 那次读虽然便宜，但也不必每个请求都读。
let zoneMemCache = { at: 0, signature: '', domains: null };

/**
 * 清空进程内 Zone 缓存。
 * 生产上靠"账户签名变化"自动失效；这里给测试和强制刷新用。
 */
export function clearZoneCache() {
  zoneMemCache = { at: 0, signature: '', domains: null };
}

export async function testCloudflareApi(api_key, username) {
  try {
    const response = await fetch("https://api.cloudflare.com/client/v4/zones?per_page=1", {
      headers: {
        "Authorization": `Bearer ${api_key}`,
        "Content-Type": "application/json"
      },
      signal: AbortSignal.timeout(10000)
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();

    if (data.success) {
      console.log('API测试成功: ' + username);
      return { success: true };
    } else {
      throw new Error(data.errors?.[0]?.message || "API响应错误");
    }
  } catch (error) {
    console.error('API测试失败: ' + username + ' - ' + error.message);
    return { success: false, error: error.message };
  }
}

export class CloudflareFetcher {
  /**
   * @param {object} apiKeyManager
   * @param {KVNamespace|null} kv 用于跨请求缓存 Zone 列表
   */
  constructor(apiKeyManager, kv) {
    this.apiManager = apiKeyManager;
    this.kv = kv || null;
    /** 最近一次 fetchFromApis 里成功的账户数，0 表示全挂了 */
    this.lastSuccessCount = 0;
  }

  /** 当前生效的账户集合。账户增删改/启停会改变它，缓存据此失效 */
  accountSignature(keys) {
    return keys.map(k => k.id || k.username || '').sort().join('|');
  }

  /**
   * 取全部域名。
   *
   * 结果会缓存 2 分钟（进程内 + KV 两层），因为这块数据几乎不变，
   * 而每次页面渲染都去问一遍 api.cloudflare.com 是当前最大的延迟来源。
   *
   * @param {{force?: boolean}} [options] force=true 跳过缓存，直连 API
   */
  async fetchAllDomains(options = {}) {
    const activeKeys = this.apiManager.getActiveKeys();
    const signature = this.accountSignature(activeKeys);

    if (!options.force) {
      const cached = await this.readCache(signature);
      if (cached) {
        logger.info('Zone 列表命中缓存', { count: cached.length });
        return this.hydrate(cached, activeKeys);
      }
    }

    if (activeKeys.length === 0) {
      throw new Error("没有可用的API密钥");
    }

    const domains = await this.fetchFromApis(activeKeys);

    // 一个账户都没查成功时**不要写缓存**：否则一次网络抖动会让空列表
    // 在缓存里躺 2 分钟，页面看起来像"域名全丢了"，比慢更吓人
    if (this.lastSuccessCount > 0) {
      // 缓存的是脱敏副本：只存 ownerId，不存 Token
      const snapshot = domains.map(d => ({
        name: d.name,
        status: d.status,
        id: d.id,
        plan: d.plan,
        created_on: d.created_on,
        modified_on: d.modified_on,
        username: d.username,
        ownerId: d.ownerId,
        isCloudflare: true
      }));

      await this.writeCache(signature, snapshot);
    } else {
      logger.warn('所有账户均查询失败，跳过 Zone 缓存写入', { accounts: activeKeys.length });
    }

    return domains;
  }

  /** 从缓存读脱敏副本；签名或时间不符则返回 null */
  async readCache(signature) {
    const now = Date.now();

    if (
      zoneMemCache.domains &&
      zoneMemCache.signature === signature &&
      now - zoneMemCache.at < ZONE_CACHE_TTL
    ) {
      return zoneMemCache.domains;
    }

    if (!this.kv) return null;

    try {
      // 不传 'json'：有些 KV 实现（含测试桩）不支持类型参数，统一自己解析
      const raw = await this.kv.get(ZONE_CACHE_KEY);
      if (!raw) return null;
      const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
      if (!parsed || parsed.signature !== signature || !Array.isArray(parsed.domains)) return null;
      if (now - Number(parsed.at || 0) >= ZONE_CACHE_TTL) return null;

      zoneMemCache = { at: Number(parsed.at), signature, domains: parsed.domains };
      return parsed.domains;
    } catch (error) {
      logger.warn('读取 Zone 缓存失败', { error: error.message });
      return null;
    }
  }

  async writeCache(signature, domains) {
    const at = Date.now();
    zoneMemCache = { at, signature, domains };

    if (!this.kv) return;
    try {
      await this.kv.put(
        ZONE_CACHE_KEY,
        JSON.stringify({ at, signature, domains }),
        { expirationTtl: Math.ceil(ZONE_CACHE_TTL / 1000) }
      );
    } catch (error) {
      logger.warn('写入 Zone 缓存失败', { error: error.message });
    }
  }

  /**
   * 把脱敏副本还原成运行时对象：ownerId → 当前 Token。
   *
   * 缓存里刻意不存 Token（KV 里再多一份密钥没有意义，也容易被导出），
   * 读回来时按账户 id 现查。账户被删掉的话 ownerId 对不上，account 留空即可。
   */
  hydrate(list, keys) {
    const byId = new Map(keys.map(k => [k.id || k.username || '', k]));
    return list.map(d => {
      const owner = byId.get(d.ownerId);
      return {
        ...d,
        username: d.username || (owner ? owner.username : '未命名账户')
      };
    });
  }

  async fetchFromApis(activeKeys) {
    logger.info('获取所有Cloudflare域名', { accounts: activeKeys.length });
    const allDomains = new Map();
    this.lastSuccessCount = 0;

    logger.info('并行查询API密钥', { count: activeKeys.length });

    // 使用 Promise.allSettled 并行处理所有 API 密钥
    const results = await Promise.allSettled(
      activeKeys.map(keyInfo =>
        this.fetchDomainsFromSingleApi(keyInfo.key, keyInfo.username)
          .then(domains => ({ keyInfo, domains }))
      )
    );

    // 统一处理结果
    for (const result of results) {
      if (result.status === 'fulfilled') {
        const { keyInfo, domains } = result.value;
        this.apiManager.markSuccess(keyInfo.key);
        this.lastSuccessCount++;

        // 合并域名信息，避免重复
        for (const domain of domains) {
          if (!allDomains.has(domain.name)) {
            allDomains.set(domain.name, {
              ...domain,
              username: keyInfo.username,
              // 归属账户用 id 记，不要把 Token 塞进域名对象——
              // 这个对象会一路流到视图层，一旦有人渲染 d.account 就是明文泄漏
              ownerId: keyInfo.id || keyInfo.username || '',
              accountId: keyInfo.key.slice(0, 8) + '...' + keyInfo.key.slice(-4),
              isCloudflare: true
            });
          }
        }

        logger.info('API查询成功', { username: keyInfo.username, domainCount: domains.length });
      } else {
        logger.error('API查询失败', { error: result.reason?.message || '未知错误' });
      }
    }

    const resultArray = Array.from(allDomains.values());
    logger.info('域名合并完成', { uniqueDomains: resultArray.length });

    return resultArray;
  }

  async fetchDomainsFromSingleApi(api_key, username) {
    const domains = [];
    let page = 1;
    let totalPages = 1;

    do {
      try {
        console.log('📄 ' + username + ': 获取第' + page + '页');

        const response = await fetch(`https://api.cloudflare.com/client/v4/zones?page=${page}&per_page=50`, {
          headers: {
            "Authorization": `Bearer ${api_key}`,
            "Content-Type": "application/json"
          },
          signal: AbortSignal.timeout(30000)
        });

        if (!response.ok) {
          if (response.status === 403) {
            throw new Error("API密钥无效或权限不足");
          } else if (response.status === 429) {
            throw new Error("API请求频率限制");
          } else {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }
        }

        const data = await response.json();

        if (!data.success) {
          throw new Error(data.errors?.[0]?.message || "Cloudflare API返回错误");
        }

        if (data.result && data.result.length > 0) {
          for (const zone of data.result) {
            domains.push({
              name: zone.name,
              status: zone.status,
              id: zone.id,
              plan: zone.plan?.name || 'Unknown',
              created_on: zone.created_on,
              modified_on: zone.modified_on
            });
          }
        }

        totalPages = data.result_info?.total_pages || 1;
        page++;

        // 这里原来每翻一页 sleep 200ms。Cloudflare 的 Zone 列表接口限流是
        // 1200 次/5 分钟，翻页是串行的，根本撞不到限流；纯粹白等。

      } catch (error) {
        console.error('获取第' + page + '页失败: ' + error.message);
        throw error;
      }
    } while (page <= totalPages);

    return domains;
  }
}