// Cloudflare 域名信息获取 + API 测试

import { logger } from '../logger.js';

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
  constructor(apiKeyManager) {
    this.apiManager = apiKeyManager;
  }

  async fetchAllDomains() {
    logger.info('获取所有Cloudflare域名');
    const allDomains = new Map();

    const activeKeys = this.apiManager.getActiveKeys();
    if (activeKeys.length === 0) {
      throw new Error("没有可用的API密钥");
    }

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

        // 合并域名信息，避免重复
        for (const domain of domains) {
          if (!allDomains.has(domain.name)) {
            allDomains.set(domain.name, {
              ...domain,
              account: keyInfo.key,
              username: keyInfo.username,
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

        // 添加延时避免频率限制
        if (page <= totalPages) {
          await new Promise(resolve => setTimeout(resolve, 200));
        }

      } catch (error) {
        console.error('获取第' + page + '页失败: ' + error.message);
        throw error;
      }
    } while (page <= totalPages);

    return domains;
  }
}