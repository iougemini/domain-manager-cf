// Cloudflare 账户密钥的运行时视图
//
// 持久化在 managers/accounts-store.js（KV config:accounts），这里只负责：
//   - 把账户数组转成带运行态（errorCount / lastUsed）的密钥列表
//   - 故障熔断：连续失败 3 次自动停用，避免一个失效 Token 拖慢每次刷新
//   - 增删改查委托给 accounts-store，改完立刻重建列表
//
// 注意：这里不再直接读写环境变量。环境变量只作为 accounts-store 的兜底来源，
// 由 initConfig 统一解析后灌进来，避免"两个地方都能改配置"的混乱。

import { appState } from '../app-state.js';
import { logger } from '../logger.js';
import { testCloudflareApi } from '../services/cloudflare.js';
import {
  upsertAccount,
  removeAccount as removeAccountInStore,
  toggleAccount as toggleAccountInStore,
  importAccountsFromEnv,
  resolveAccounts,
  publicAccount
} from './accounts-store.js';

const MAX_ERRORS = 3;

export class ApiKeyManager {
  constructor() {
    /** @type {Array<{id, key, username, label, active, lastUsed, errorCount}>} */
    this.keys = [];
    this.initialized = false;
  }

  /**
   * 从已解析的账户列表初始化。
   * @param {Array} accounts initConfig 产出的账户数组
   */
  initFromAccounts(accounts) {
    this.keys = (accounts || [])
      .filter(item => item && item.token)
      .map(item => ({
        id: item.id || '',
        key: item.token,
        username: item.username || '未命名账户',
        label: item.label || item.username || '未命名账户',
        active: item.enabled !== false,
        // note 也要带上：编辑表单靠它回填，漏了会在保存时把原有备注清空
        note: item.note || '',
        lastUsed: null,
        errorCount: 0
      }));

    logger.info('ApiKeyManager初始化完成', { count: this.keys.length });
    return this.keys;
  }

  /** 兼容旧调用（现在等价于用 appState.accounts 初始化） */
  initFromEnv() {
    return this.initFromAccounts(appState.accounts);
  }

  /** 重新从 KV 载入账户并重建列表 */
  async reload() {
    const { accounts } = await resolveAccounts(
      appState.env ? appState.env.DOMAIN_INFO : null,
      appState.env
    );
    appState.accounts = accounts;
    this.initFromAccounts(accounts);
    // 账户变了，CloudflareFetcher 持有的引用也要重建
    appState.cloudflareFetcher = null;
    return this.keys;
  }

  getActiveKeys() {
    return this.keys.filter(k => k.active && k.errorCount < MAX_ERRORS);
  }

  markError(key) {
    const keyObj = this.keys.find(k => k.key === key);
    if (!keyObj) return;
    keyObj.errorCount++;
    if (keyObj.errorCount >= MAX_ERRORS) {
      keyObj.active = false;
      logger.warn('API Key 已停用，错误次数过多', { key: String(key).slice(0, 10) });
    }
  }

  markSuccess(key) {
    const keyObj = this.keys.find(k => k.key === key);
    if (!keyObj) return;
    keyObj.lastUsed = Date.now();
    keyObj.errorCount = 0;
  }

  /* ---------------- 增删改查（写 KV） ---------------- */

  /** 新增账户，会先验证 Token 是否真的能读 Zone 列表 */
  async addAccount(payload) {
    const result = await testCloudflareApi(payload.token, payload.username || '新账户');
    // 老代码这里写的是 `if (!isValid)`，而 testCloudflareApi 返回的是对象，
    // 永远为真——等于完全没校验。这里必须显式看 .success
    if (!result.success) {
      throw new Error('Token 验证失败：' + (result.error || '无法读取 Zone 列表'));
    }

    const created = await upsertAccount(appState.env.DOMAIN_INFO, payload, null);
    await this.reload();
    return created;
  }

  /** 更新账户；token 留空表示不修改 */
  async updateAccount(id, payload) {
    if (payload && payload.token) {
      const result = await testCloudflareApi(payload.token, payload.username || '账户');
      if (!result.success) {
        throw new Error('Token 验证失败：' + (result.error || '无法读取 Zone 列表'));
      }
    }

    const updated = await upsertAccount(appState.env.DOMAIN_INFO, payload, id);
    await this.reload();
    return updated;
  }

  async removeAccount(id) {
    await removeAccountInStore(appState.env.DOMAIN_INFO, id);
    await this.reload();
    return true;
  }

  async toggleAccount(id) {
    const active = await toggleAccountInStore(appState.env.DOMAIN_INFO, id);
    await this.reload();
    return active;
  }

  async importFromEnv() {
    const result = await importAccountsFromEnv(appState.env.DOMAIN_INFO, appState.env);
    await this.reload();
    return result;
  }

  /** 单独测一个账户的连通性 */
  async testAccount(id) {
    const keyObj = this.keys.find(k => k.id === id);
    if (!keyObj) throw new Error('账户不存在，可能已被删除');
    const result = await testCloudflareApi(keyObj.key, keyObj.username);
    return {
      ok: result.success,
      error: result.error || null,
      username: keyObj.username
    };
  }

  /** 逐个测试全部账户 */
  async testAll() {
    const results = [];
    for (const keyObj of this.keys) {
      const result = await testCloudflareApi(keyObj.key, keyObj.username);
      results.push({
        id: keyObj.id,
        username: keyObj.username,
        label: keyObj.label,
        ok: result.success,
        error: result.error || null,
        active: keyObj.active,
        errorCount: keyObj.errorCount
      });
    }
    return results;
  }

  /**
   * 供接口返回的账户列表。
   * 只回掩码，完整 Token 永远不出后端。
   */
  getAllAccounts() {
    return this.keys.map(k => ({
      id: k.id,
      label: k.label,
      username: k.username,
      tokenMasked: publicAccount({ token: k.key }).tokenMasked,
      active: k.active,
      errorCount: k.errorCount,
      lastUsed: k.lastUsed,
      // note 必须带上：编辑表单靠它回填，漏了就会在保存时把原有备注清空
      note: k.note || ''
    }));
  }

  /** 兼容旧接口名 */
  getAllKeys() {
    return this.getAllAccounts();
  }
}
