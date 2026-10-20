// Cloudflare API 密钥管理

import { appState } from '../app-state.js';
import { logger } from '../logger.js';
import { testCloudflareApi } from '../services/cloudflare.js';

export class ApiKeyManager {
  constructor() {
    this.keys = [];
    this.initialized = false;
  }

  // 从环境变量初始化keys
  initFromEnv() {
    this.keys = appState.CF_API_KEYS.map((key, index) => ({
      key,
      username: appState.USERNAMES[index],
      active: true,
      lastUsed: null,
      errorCount: 0
    }));
    logger.info(`ApiKeyManager初始化完成,共${this.keys.length}个API密钥`);
  }

  async init() {
    if (!this.initialized) {
      await this.loadFromKV();
      this.initialized = true;
    }
  }

  getActiveKeys() {
    return this.keys.filter(k => k.active && k.errorCount < 3);
  }

  markError(key) {
    const keyObj = this.keys.find(k => k.key === key);
    if (keyObj) {
      keyObj.errorCount++;
      if (keyObj.errorCount >= 3) {
        keyObj.active = false;
        logger.warn('API Key 已禁用，错误次数过多', { key: key.slice(0, 10) });
      }
    }
  }

  markSuccess(key) {
    const keyObj = this.keys.find(k => k.key === key);
    if (keyObj) {
      keyObj.lastUsed = Date.now();
      keyObj.errorCount = 0; // 重置错误计数
    }
  }

  async addApiKey(key, username) {
    // 测试API密钥是否有效
    const isValid = await testCloudflareApi(key, username);
    if (!isValid) {
      throw new Error('API密钥无效');
    }

    // 检查是否已存在
    const exists = this.keys.some(k => k.key === key);
    if (exists) {
      throw new Error('API密钥已存在');
    }

    this.keys.push({
      key,
      username,
      active: true,
      lastUsed: null,
      errorCount: 0
    });

    // 保存到KV存储
    await this.saveToKV();
    return true;
  }

  async removeApiKey(key) {
    const index = this.keys.findIndex(k => k.key === key);
    if (index === -1) {
      throw new Error('API密钥不存在');
    }

    this.keys.splice(index, 1);
    await this.saveToKV();
    return true;
  }

  async toggleApiKey(key) {
    const keyObj = this.keys.find(k => k.key === key);
    if (!keyObj) {
      throw new Error('API密钥不存在');
    }

    keyObj.active = !keyObj.active;
    if (keyObj.active) {
      keyObj.errorCount = 0; // 重新启用时重置错误计数
    }

    await this.saveToKV();
    return keyObj.active;
  }

  async saveToKV() {
    if (!appState.env || !appState.env.DOMAIN_INFO) {
      logger.error('DOMAIN_INFO KV命名空间未初始化');
      return;
    }
    const apiKeysData = {
      keys: this.keys,
      lastUpdated: Date.now()
    };
    await appState.env.DOMAIN_INFO.put('cf_api_keys', JSON.stringify(apiKeysData));
  }

  async loadFromKV() {
    if (!appState.env || !appState.env.DOMAIN_INFO) {
      logger.error('DOMAIN_INFO KV命名空间未初始化');
      return;
    }
    try {
      const data = await appState.env.DOMAIN_INFO.get('cf_api_keys');
      if (data) {
        const parsed = JSON.parse(data);
        if (parsed.keys && parsed.keys.length > 0) {
          // 检查KV中的数据是否包含fallback用户名(表示是旧数据)
          const hasFallbackUsernames = parsed.keys.some(k =>
            k.username && k.username.includes('cloudflare username')
          );

          if (hasFallbackUsernames) {
            logger.warn('KV中包含fallback用户名(旧数据),忽略KV数据,使用环境变量');
            return;
          }

          this.keys = parsed.keys;
          logger.info('从KV加载API密钥配置(覆盖环境变量)');
        }
      } else {
        logger.info('KV中无API密钥配置,使用环境变量');
      }
    } catch (error) {
      logger.error('加载API密钥失败', { error: error.message });
    }
  }

  getAllKeys() {
    return this.keys.map(k => ({
      ...k,
      key: k.key.slice(0, 8) + '...' + k.key.slice(-8) // 隐藏密钥中间部分
    }));
  }

  // 清除KV中的旧数据(包含fallback用户名的数据)
  async clearOldKVData() {
    if (!appState.env || !appState.env.DOMAIN_INFO) {
      logger.error('DOMAIN_INFO KV命名空间未初始化');
      return false;
    }
    try {
      const data = await appState.env.DOMAIN_INFO.get('cf_api_keys');
      if (data) {
        const parsed = JSON.parse(data);
        const hasFallbackUsernames = parsed.keys && parsed.keys.some(k =>
          k.username && k.username.includes('cloudflare username')
        );

        if (hasFallbackUsernames) {
          await appState.env.DOMAIN_INFO.delete('cf_api_keys');
          logger.info('已清除KV中的旧API密钥数据');
          return true;
        } else {
          logger.info('KV中没有旧数据');
          return false;
        }
      } else {
        logger.info('KV中没有API密钥数据');
        return false;
      }
    } catch (error) {
      logger.error('清除KV旧数据失败', { error: error.message });
      return false;
    }
  }
}