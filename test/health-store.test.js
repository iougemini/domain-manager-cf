// 域名健康巡检
//
// 重点在调度语义而不是探测本身（探测已由 dns-check / registry-status 各自测过）：
// 谁该被跳过、超上限怎么算、探测失败算不算域名的问题、结果有没有真的写进去。

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  healthKey,
  readHealth,
  readHealthBatch,
  summarizeRecord,
  runHealthCheck,
  collectHealthAlerts
} from '../src/managers/health-store.js';
import { fakeKV, readJSON } from './_fake-kv.js';

function checkerReturning(map) {
  return {
    async check(name) {
      const preset = map[name] || { status: 'ok', records: { a: ['1.1.1.1'], aaaa: [], cname: [] }, error: null };
      return { ...preset, checkedAt: new Date().toISOString() };
    }
  };
}

test('healthKey 统一小写，避免同一域名两条记录', () => {
  assert.equal(healthKey('Example.COM'), 'health:example.com');
  assert.equal(healthKey(''), 'health:');
});

test('readHealth 能解析 JSON —— 依赖 get 的 type:json 选项', async () => {
  const kv = fakeKV({ 'health:example.com': JSON.stringify({ checkedAt: '2026-10-23T00:00:00Z' }) });
  const record = await readHealth(kv, 'example.com');
  assert.equal(record.checkedAt, '2026-10-23T00:00:00Z');
});

test('readHealth 对坏数据与缺失 KV 返回 null', async () => {
  assert.equal(await readHealth(fakeKV({ 'health:x.com': 'not json' }), 'x.com'), null);
  assert.equal(await readHealth(null, 'x.com'), null);
  assert.equal(await readHealth(fakeKV(), 'x.com'), null);
});

test('readHealthBatch 只返回存在的记录', async () => {
  const kv = fakeKV({
    'health:a.com': JSON.stringify({ checkedAt: '2026-10-23T00:00:00Z' }),
    'health:b.com': JSON.stringify({ checkedAt: '2026-10-23T00:00:00Z' })
  });
  const map = await readHealthBatch(kv, ['a.com', 'b.com', 'c.com']);
  assert.equal(map.size, 2);
  assert.ok(map.has('a.com'));
  assert.ok(!map.has('c.com'));
});

test('巡检写入 KV 并带过期时间', async () => {
  const kv = fakeKV();
  const result = await runHealthCheck({
    kv,
    domains: [{ name: 'a.com' }],
    dnsChecker: checkerReturning({})
  });

  assert.equal(result.checked, 1);
  assert.equal(result.failed, 0);
  const stored = readJSON(kv, 'health:a.com');
  assert.equal(stored.dns.status, 'ok');
  assert.ok(kv.store.get('__ttl:health:a.com'), '写入时缺少 expirationTtl');
});

test('间隔内不重复探测', async () => {
  const now = Date.parse('2026-10-23T12:00:00Z');
  const kv = fakeKV({
    'health:a.com': JSON.stringify({ dns: { status: 'ok' }, checkedAt: '2026-10-23T00:00:00Z' })
  });

  const result = await runHealthCheck({
    kv,
    domains: [{ name: 'a.com' }],
    dnsChecker: checkerReturning({}),
    options: { now, minIntervalMs: 20 * 60 * 60 * 1000 }
  });

  assert.equal(result.checked, 0);
  assert.equal(result.skipped, 1);
});

test('超过间隔会重新探测', async () => {
  const now = Date.parse('2026-10-23T12:00:00Z');
  const kv = fakeKV({
    'health:a.com': JSON.stringify({ dns: { status: 'ok' }, checkedAt: '2026-10-21T00:00:00Z' })
  });

  const result = await runHealthCheck({
    kv,
    domains: [{ name: 'a.com' }],
    dnsChecker: checkerReturning({}),
    options: { now, minIntervalMs: 20 * 60 * 60 * 1000 }
  });

  assert.equal(result.checked, 1);
});

test('force 忽略间隔限制', async () => {
  const now = Date.parse('2026-10-23T12:00:00Z');
  const kv = fakeKV({
    'health:a.com': JSON.stringify({ dns: { status: 'ok' }, checkedAt: '2026-10-23T11:59:00Z' })
  });

  const result = await runHealthCheck({
    kv,
    domains: [{ name: 'a.com' }],
    dnsChecker: checkerReturning({}),
    options: { now, force: true }
  });

  assert.equal(result.checked, 1);
});

test('maxDomains 限制本轮数量，其余计入 skipped', async () => {
  const kv = fakeKV();
  const domains = Array.from({ length: 10 }, (_, i) => ({ name: `d${i}.com` }));

  const result = await runHealthCheck({
    kv,
    domains,
    dnsChecker: checkerReturning({}),
    options: { maxDomains: 4 }
  });

  assert.equal(result.checked, 4);
  assert.equal(result.skipped, 6);
});

test('nxdomain 进 problems', async () => {
  const kv = fakeKV();
  const result = await runHealthCheck({
    kv,
    domains: [{ name: 'gone.com' }],
    dnsChecker: checkerReturning({
      'gone.com': { status: 'nxdomain', records: { a: [], aaaa: [], cname: [] }, error: null }
    })
  });

  assert.equal(result.problems.length, 1);
  assert.equal(result.problems[0].name, 'gone.com');
  assert.equal(result.problems[0].level, 'danger');
});

test('nodata 不进 problems —— 囤着没配解析的域名不该报警', async () => {
  const kv = fakeKV();
  const result = await runHealthCheck({
    kv,
    domains: [{ name: 'idle.com' }],
    dnsChecker: checkerReturning({
      'idle.com': { status: 'nodata', records: { a: [], aaaa: [], cname: [] }, error: null }
    })
  });

  assert.equal(result.problems.length, 0);
});

test('clientHold 进 problems 并标记 suspended', async () => {
  const kv = fakeKV();
  const result = await runHealthCheck({
    kv,
    domains: [{ name: 'held.com' }],
    dnsChecker: checkerReturning({}),
    registryLookup: name => (name === 'held.com' ? ['client hold'] : null)
  });

  assert.equal(result.problems.length, 1);
  assert.equal(result.problems[0].suspended, true);
});

test('clientTransferProhibited 不产生告警', async () => {
  const kv = fakeKV();
  const result = await runHealthCheck({
    kv,
    domains: [{ name: 'normal.com' }],
    dnsChecker: checkerReturning({}),
    registryLookup: () => ['client transfer prohibited', 'client delete prohibited']
  });

  assert.equal(result.problems.length, 0);
});

test('探测失败计入 failed，但不算域名事故', async () => {
  const kv = fakeKV();
  const result = await runHealthCheck({
    kv,
    domains: [{ name: 'x.com' }],
    dnsChecker: checkerReturning({
      'x.com': { status: 'error', records: { a: [], aaaa: [], cname: [] }, error: 'boom' }
    })
  });

  assert.equal(result.failed, 1);
  assert.equal(result.problems.length, 0);
});

test('DNS 检查抛异常不会中断整轮巡检', async () => {
  const kv = fakeKV();
  const result = await runHealthCheck({
    kv,
    domains: [{ name: 'bad.com' }, { name: 'good.com' }],
    dnsChecker: {
      async check(name) {
        if (name === 'bad.com') throw new Error('explode');
        return { status: 'ok', records: { a: ['1.1.1.1'] }, checkedAt: new Date().toISOString() };
      }
    }
  });

  assert.equal(result.checked, 2);
  assert.equal(result.failed, 1);
  assert.ok(readJSON(kv, 'health:good.com'));
});

test('registryLookup 抛异常按"无状态"处理', async () => {
  const kv = fakeKV();
  const result = await runHealthCheck({
    kv,
    domains: [{ name: 'a.com' }],
    dnsChecker: checkerReturning({}),
    registryLookup: () => { throw new Error('bad cache'); }
  });

  assert.equal(result.checked, 1);
  assert.equal(result.problems.length, 0);
});

test('写 KV 失败不影响本轮统计', async () => {
  const kv = fakeKV();
  kv.put = async () => { throw new Error('kv down'); };

  const result = await runHealthCheck({
    kv,
    domains: [{ name: 'a.com' }],
    dnsChecker: checkerReturning({})
  });

  assert.equal(result.checked, 1);
});

test('空域名列表直接返回，不发请求', async () => {
  let called = 0;
  const result = await runHealthCheck({
    kv: fakeKV(),
    domains: [],
    dnsChecker: { async check() { called++; return { status: 'ok' }; } }
  });

  assert.equal(result.checked, 0);
  assert.equal(called, 0);
});

test('summarizeRecord 对空记录返回 unknown', () => {
  const s = summarizeRecord(null);
  assert.equal(s.level, 'unknown');
  assert.equal(s.dnsLabel, '未探测');
  assert.equal(s.problems.length, 0);
});

test('summarizeRecord 把 warn 与 danger 分开', () => {
  const warn = summarizeRecord({ dns: { status: 'ok' }, registry: { status: ['pending restore'] } });
  assert.equal(warn.level, 'warn');

  const danger = summarizeRecord({ dns: { status: 'nxdomain' }, registry: null });
  assert.equal(danger.level, 'danger');
});

test('collectHealthAlerts 让暂停解析排在最前', () => {
  const map = new Map([
    ['zzz.com', { dns: { status: 'nxdomain' }, registry: null }],
    ['aaa.com', { dns: { status: 'ok' }, registry: { status: ['client hold'] } }]
  ]);

  const alerts = collectHealthAlerts(map);
  assert.equal(alerts.length, 2);
  assert.equal(alerts[0].name, 'aaa.com', '暂停解析比解析丢失更严重');
  assert.equal(alerts[1].name, 'zzz.com');
});
