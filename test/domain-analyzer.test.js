import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { DomainAnalyzer } from '../src/services/domain-analyzer.js';

const days = (n) => new Date(Date.now() + n * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

describe('DomainAnalyzer.analyze', () => {
  it('空数组返回全零', () => {
    const stats = DomainAnalyzer.analyze([]);
    assert.equal(stats.total, 0);
    assert.equal(stats.active, 0);
    assert.equal(stats.expiringSoon, 0);
  });

  it('统计免费域名', () => {
    const stats = DomainAnalyzer.analyze([{ name: 'x.eu.org', isFree: true }]);
    assert.equal(stats.free, 1);
    assert.equal(stats.total, 1);
  });

  it('统计错误域名', () => {
    const stats = DomainAnalyzer.analyze([{ name: 'x.com', whoisError: 'err' }]);
    assert.equal(stats.errors, 1);
  });

  it('统计未知日期域名', () => {
    const stats = DomainAnalyzer.analyze([{ name: 'x.com', expirationDate: 'Unknown', registrationDate: '2020-01-01' }]);
    assert.equal(stats.unknown, 1);
  });

  it('统计即将到期域名(30天内)', () => {
    const stats = DomainAnalyzer.analyze([
      { name: 'x.com', expirationDate: days(10), registrationDate: '2020-01-01' }
    ]);
    assert.equal(stats.expiringSoon, 1);
  });

  it('统计已过期域名', () => {
    const stats = DomainAnalyzer.analyze([
      { name: 'x.com', expirationDate: days(-10), registrationDate: '2020-01-01' }
    ]);
    assert.equal(stats.expired, 1);
  });

  it('统计正常域名(>30天)', () => {
    const stats = DomainAnalyzer.analyze([
      { name: 'x.com', expirationDate: days(60), registrationDate: '2020-01-01' }
    ]);
    assert.equal(stats.active, 1);
  });
});

describe('DomainAnalyzer.getExpiringDomains', () => {
  it('返回到期日升序排列的即将过期域名', () => {
    const domains = [
      { name: 'later.com', expirationDate: days(20), registrationDate: '2020-01-01' },
      { name: 'sooner.com', expirationDate: days(5), registrationDate: '2020-01-01' }
    ];
    const result = DomainAnalyzer.getExpiringDomains(domains, 30);
    assert.equal(result.length, 2);
    assert.equal(result[0].name, 'sooner.com');
    assert.equal(result[1].name, 'later.com');
  });

  it('排除免费域名和错误域名', () => {
    const domains = [
      { name: 'free.eu.org', isFree: true, expirationDate: days(3) },
      { name: 'err.com', whoisError: 'x', expirationDate: days(3) },
      { name: 'ok.com', expirationDate: days(3), registrationDate: '2020-01-01' }
    ];
    const result = DomainAnalyzer.getExpiringDomains(domains, 30);
    assert.equal(result.length, 1);
    assert.equal(result[0].name, 'ok.com');
  });
});