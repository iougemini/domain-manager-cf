// WhoisService 的"只读缓存"模式
//
// 页面渲染超出时间预算后会切成 cacheOnly：还能把已缓存的域名渲染出来，
// 没缓存的返回 pending 占位、交给后台补。这里要保证两点：
//   1. cacheOnly 真的不发任何网络请求（否则预算等于没加）
//   2. pending 不会被误当成"查询失败"（whoisError），否则界面一片红

import test from 'node:test';
import assert from 'node:assert/strict';
import { WhoisService } from '../src/services/whois.js';

function stubCache(hit = null) {
  const writes = [];
  return {
    writes,
    async get() { return hit; },
    async set(domain, data) { writes.push({ domain, data }); }
  };
}

test('cacheOnly 且无缓存：返回 pending 占位，不报错', async () => {
  const cache = stubCache(null);
  const service = new WhoisService('', cache, { getInfo: () => null });

  const result = await service.query('example.com', { cacheOnly: true });

  assert.equal(result.pending, true);
  assert.equal(result.expirationDate, 'Unknown');
  assert.equal(result.whoisError, undefined, 'pending 不是错误，不该带 whoisError');
  assert.equal(cache.writes.length, 0, 'cacheOnly 不该写缓存');
});

test('cacheOnly 且命中缓存：直接返回缓存，不标 pending', async () => {
  const cached = { registrar: 'Cloudflare, Inc.', expirationDate: '2027-01-01' };
  const service = new WhoisService('', stubCache(cached), { getInfo: () => null });

  const result = await service.query('example.com', { cacheOnly: true });

  assert.equal(result, cached);
  assert.equal(result.pending, undefined);
});

test('cacheOnly 时免费域名仍返回注册表元数据', async () => {
  const meta = { registrar: 'DNSHE', expirationDate: 'Auto-Renewal', renew: 'auto' };
  const service = new WhoisService('', stubCache(null), { getInfo: () => meta });

  const result = await service.query('demo.us.ci', { cacheOnly: true });

  assert.equal(result.registrar, 'DNSHE');
  assert.equal(result.expirationDate, 'Auto-Renewal', '本地常量不该被 pending 顶掉');
  assert.equal(result.pending, true);
  assert.equal(result.dataSource, 'registry');
});

test('不传 cacheOnly 时行为不变：未配代理返回明确错误', async () => {
  const service = new WhoisService('', stubCache(null), { getInfo: () => null });

  const result = await service.query('example.com');

  assert.equal(result.whoisError, 'WHOIS proxy not configured');
  assert.equal(result.pending, undefined);
});

test('forceRefresh 跳过缓存读取（新增域名时不能被旧失败记录挡住）', async () => {
  let reads = 0;
  const cache = {
    async get() { reads++; return { registrar: '旧值', expirationDate: '2020-01-01' }; },
    async set() {}
  };
  const service = new WhoisService('', cache, { getInfo: () => null });

  const result = await service.query('example.com', { forceRefresh: true });

  assert.equal(reads, 0, 'forceRefresh 不该读缓存');
  assert.notEqual(result.registrar, '旧值');
  assert.equal(result.whoisError, 'WHOIS proxy not configured');
});
