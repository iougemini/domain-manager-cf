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

  async addDomain(domain, info) {
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
      registrationDate: info.registrationDate || new Date().toISOString().split('T')[0],
      expirationDate: info.expirationDate || 'Unknown',
      nameServers: info.nameServers || [],
      status: info.status || 'Active',
      notes: info.notes || '',
      addedDate: new Date().toISOString(),
      isCustomDomain: true
    };

    this.domains.set(domain, domainInfo);
    await this.saveToKV();
    return true;
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