// WHOIS 缓存层测试
//
// 重点是"失败结果只能短暂停留"这条：v2.2.0 把 DNSHE 的 401 兜底值按默认 7 天
// 缓存，用户补好 Key 之后刷新还是同一句报错，改配置像是完全没生效。
import test, { describe } from 'node:test';
import assert from 'node:assert/strict';
import { CacheManager } from '../src/managers/cache.js';
import { CONFIG } from '../src/config.js';
import { fakeKV } from './_fake-kv.js';

const sleep = ms => new Promise(r => setTimeout(r, ms));

describe('CacheManager', () => {
  test('写入后能读回', async () => {
    const cache = new CacheManager(fakeKV());
    await cache.set('a.com', { registrar: 'X', expirationDate: '2027-01-01' });

    const got = await cache.get('a.com');
    assert.equal(got.registrar, 'X');
    assert.equal(got.expirationDate, '2027-01-01');
  });

  test('未命中返回 null', async () => {
    const cache = new CacheManager(fakeKV());
    assert.equal(await cache.get('nope.com'), null);
  });

  test('自定义 TTL 会被持久化，并在过期后失效', async () => {
    const kv = fakeKV();
    const cache = new CacheManager(kv);
    await cache.set('b.com', { lookupError: '401' }, 5);

    const raw = JSON.parse(await kv.get('whois_b.com'));
    assert.equal(raw.ttl, 5);

    await sleep(15);
    assert.equal(await cache.get('b.com'), null);
    // 过期条目要顺手删掉，不能只是"读不到"
    assert.equal(await kv.get('whois_b.com'), null);
  });

  test('不传 TTL 时用默认 CACHE_TTL', async () => {
    const kv = fakeKV();
    const cache = new CacheManager(kv);
    await cache.set('c.com', { registrar: 'Y' });

    const raw = JSON.parse(await kv.get('whois_c.com'));
    assert.equal(raw.ttl, undefined);
    assert.equal(CONFIG.CACHE_TTL, 7 * 24 * 60 * 60 * 1000);
  });

  test('缓存版本不匹配时丢弃', async () => {
    const kv = fakeKV({
      'whois_d.com': JSON.stringify({
        data: { registrar: 'Z' },
        timestamp: Date.now(),
        version: '0.0.1'
      })
    });
    const cache = new CacheManager(kv);
    assert.equal(await cache.get('d.com'), null);
    assert.equal(await kv.get('whois_d.com'), null);
  });

  test('clearWhere 只清匹配的域名', async () => {
    const kv = fakeKV();
    const cache = new CacheManager(kv);
    await cache.set('x.us.ci', { registrar: 'DNSHE' });
    await cache.set('y.cc.cd', { registrar: 'DNSHE' });
    await cache.set('keep.dpdns.org', { registrar: 'DigitalPlat' });

    const removed = await cache.clearWhere(d => d.endsWith('us.ci') || d.endsWith('cc.cd'));
    assert.equal(removed, 2);

    assert.equal(await cache.get('x.us.ci'), null);
    assert.equal(await cache.get('y.cc.cd'), null);
    assert.equal((await cache.get('keep.dpdns.org')).registrar, 'DigitalPlat');
  });

  test('clearWhere 传非法参数时安全返回 0', async () => {
    const cache = new CacheManager(fakeKV());
    assert.equal(await cache.clearWhere(null), 0);
    assert.equal(await cache.clearWhere('x'), 0);
  });

  test('clearWhere 同时清内存缓存', async () => {
    const cache = new CacheManager(fakeKV());
    await cache.set('m.us.ci', { registrar: 'DNSHE' });
    await cache.get('m.us.ci');            // 进内存层
    await cache.clearWhere(d => d.endsWith('us.ci'));
    assert.equal(cache.getStats().memCacheSize, 0);
  });
});
