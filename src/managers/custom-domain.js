// 自定义(非Cloudflare)域名管理

import { appState } from '../app-state.js';
import { logger } from '../logger.js';

export class CustomDomainManager {
  constructor() {
    this.domains = new Map();
  }

  async loadFromKV() {
    if (!appState.env || !appState.env.DOMAIN_INFO) {
      logger.error('DOMAIN_INFO KV命名空间未初始化');
      return;
    }
    try {
      const data = await appState.env.DOMAIN_INFO.get('custom_domains');
      if (data) {
        const parsed = JSON.parse(data);
        this.domains = new Map(parsed.domains || []);
      }
    } catch (error) {
      logger.error('加载自定义域名失败', { error: error.message });
    }
  }

  async saveToKV() {
    if (!appState.env || !appState.env.DOMAIN_INFO) {
      logger.error('DOMAIN_INFO KV命名空间未初始化');
      return;
    }
    const customDomainsData = {
      domains: Array.from(this.domains.entries()),
      lastUpdated: Date.now()
    };
    await appState.env.DOMAIN_INFO.put('custom_domains', JSON.stringify(customDomainsData));
  }

  async addDomain(domain, info = {}) {
    // 验证域名格式
    if (!domain || !this.isValidDomain(domain)) {
      throw new Error('域名格式无效');
    }

    // 检查是否已存在
    if (this.domains.has(domain)) {
      throw new Error('域名已存在');
    }

    const domainInfo = {
      registrar: info.registrar || 'Unknown',
      // 不再把「添加日期」当成注册日期。以前这么做，查不到真实注册日时会
      // 显示一个假的今天，而且后续自动更新会认为"已经有值了"而不再覆盖
      registrationDate: info.registrationDate || 'Unknown',
      expirationDate: info.expirationDate || 'Unknown',
      nameServers: info.nameServers || [],
      status: info.status || 'Active',
      notes: info.notes || '',
      // 添加时立刻查一次 WHOIS 的结果：ok 表示已写入真实信息，
      // missing 表示没查到、等用户补填
      lookupStatus: info.lookupStatus || 'pending',
      lookupError: info.lookupError || null,
      dataSource: info.dataSource || null,
      isPermanent: Boolean(info.isPermanent),
      addedDate: new Date().toISOString(),
      isCustomDomain: true
    };

    this.domains.set(domain, domainInfo);
    await this.saveToKV();
    return domainInfo;
  }

  async removeDomain(domain) {
    if (!this.domains.has(domain)) {
      throw new Error('域名不存在');
    }

    this.domains.delete(domain);
    await this.saveToKV();
    return true;
  }

  async updateDomain(domain, info) {
    if (!this.domains.has(domain)) {
      throw new Error('域名不存在');
    }

    const existing = this.domains.get(domain);
    const updated = {
      ...existing,
      ...info,
      lastUpdated: new Date().toISOString()
    };

    this.domains.set(domain, updated);
    await this.saveToKV();
    return true;
  }

  getDomain(domain) {
    return this.domains.get(domain);
  }

  getAllDomains() {
    return Array.from(this.domains.entries()).map(([domain, info]) => ({
      domain,
      ...info
    }));
  }

  isValidDomain(domain) {
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
    return domainRegex.test(domain);
  }
}