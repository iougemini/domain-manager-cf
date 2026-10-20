// 免费域名管理

export class FreeDomainManager {
  constructor() {
    this.domains = new Map([
      ['eu.org', {
        registrar: 'NIC.EU.ORG',
        registrationDate: '1996-04-29',
        type: 'persistent',
        isPermanent: true,  // 标记为永久域名
        description: '欧洲免费域名服务'
      }],
      ['pp.ua', {
        registrar: 'NIC.UA',
        registrationDate: '2002-03-15',
        expirationDate: 'Auto-Renewal',
        type: 'renewable',
        description: '乌克兰免费域名服务'
      }],
      ['qzz.io', {
        registrar: 'DIGITALPLAT.ORG',
        registrationDate: '2018-10-12',
        expirationDate: 'Auto-Renewal',
        type: 'renewable',
        description: '免费IO子域名服务'
      }],
      ['us.kg', {
        registrar: 'DIGITALPLAT.ORG',
        registrationDate: '2020-05-20',
        expirationDate: 'Auto-Renewal',
        type: 'renewable',
        description: '免费KG域名服务'
      }],
      ['xx.kg', {
        registrar: 'DIGITALPLAT.ORG',
        registrationDate: '2021-03-10',
        expirationDate: 'Auto-Renewal',
        type: 'renewable',
        description: '免费KG域名服务'
      }],
      ['dpdns.org', {
        registrar: 'DIGITALPLAT.ORG',
        registrationDate: '2010-06-01',
        type: 'renewable',
        description: '免费DNS域名服务'
      }]
    ]);
  }

  isFree(domain) {
    if (!domain) return false;

    if (this.domains.has(domain)) return true;

    for (const freeDomain of this.domains.keys()) {
      if (domain.endsWith('.' + freeDomain)) return true;
    }

    return false;
  }

  getInfo(domain) {
    if (!domain) return null;

    // 直接匹配
    if (this.domains.has(domain)) {
      return {
        ...this.domains.get(domain),
        isFreeSubdomain: true,
        level: 'primary'
      };
    }

    // 子域名匹配
    for (const [freeDomain, info] of this.domains) {
      if (domain.endsWith('.' + freeDomain)) {
        return {
          registrar: info.registrar,
          registrationDate: 'N/A',
          expirationDate: info.expirationDate,
          isFreeSubdomain: true,
          level: 'subdomain',
          parent: freeDomain,
          description: `${info.description} - 子域名`
        };
      }
    }

    return null;
  }
}