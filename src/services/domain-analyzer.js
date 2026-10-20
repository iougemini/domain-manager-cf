// 域名状态分析器 (纯静态)

export class DomainAnalyzer {
  static analyze(domains) {
    if (!domains || domains.length === 0) {
      return {
        total: 0,
        active: 0,
        expired: 0,
        expiringSoon: 0,
        unknown: 0,
        free: 0,
        errors: 0
      };
    }

    const stats = {
      total: domains.length,
      active: 0,
      expired: 0,
      expiringSoon: 0,
      unknown: 0,
      free: 0,
      errors: 0
    };

    const now = new Date();
    const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

    for (const domain of domains) {
      if (domain.isFree) {
        stats.free++;
        continue;
      }

      if (domain.whoisError) {
        stats.errors++;
        continue;
      }

      if (domain.expirationDate === 'Unknown' || domain.registrationDate === 'Unknown') {
        stats.unknown++;
        continue;
      }

      try {
        const expDate = new Date(domain.expirationDate);

        if (expDate < now) {
          stats.expired++;
        } else if (expDate < thirtyDaysFromNow) {
          stats.expiringSoon++;
        } else {
          stats.active++;
        }
      } catch (error) {
        stats.unknown++;
      }
    }

    return stats;
  }

  static getExpiringDomains(domains, days = 30) {
    if (!domains || domains.length === 0) return [];

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() + days);

    return domains.filter(domain => {
      if (domain.isFree || domain.whoisError) return false;

      try {
        const expDate = new Date(domain.expirationDate);
        return expDate <= cutoffDate && expDate > new Date();
      } catch (error) {
        return false;
      }
    }).sort((a, b) => new Date(a.expirationDate) - new Date(b.expirationDate));
  }
}