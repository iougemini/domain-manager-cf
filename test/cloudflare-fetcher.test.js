// CloudflareFetcher：Zone 列表缓存的正确性
//
// 这块逻辑的风险点不是"缓存没生效"，而是"缓存把不该留的东西留下了"：
// 域名对象会一路流到视图层，只要里面带着 Token，随便哪次渲染都会泄漏；
// 缓存写进 KV 更是多存一份密钥。所以下面的断言重点在脱敏。

import test from 'node:test';
import assert from 'node:assert/strict';
import { CloudflareFetcher, clearZoneCache } from '../src/services/cloudflare.js';
import { fakeKV, readJSON } from './_fake-kv.js';

const TOKEN = 'cf-token-abcdefghijklmnopqrstuvwxyz0123456789';

function makeManager(keys) {
  return {
    keys,
    getActiveKeys() { return this.keys.filter(k => k.active !== false); },
    markSuccess() {}
  };
}

function zone(name, id) {
  return { name, id, status: 'active', plan: { name: 'Free' }, created_on: '2024-01-01', modified_on: '2024-02-01' };
}

/** 拦截 fetch，按调用顺序返回预设结果，并记录次数 */
function stubFetch(handler) {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push(String(url));
    return handler(String(url), init);
  };
  return {
    calls,
    restore() { globalThis.fetch = original; }
  };
}

const okResponse = zones => ({
  ok: true,
  status: 200,
  async json() {
    return { success: true, result: zones, result_info: { total_pages: 1 } };
  }
});

test.beforeEach(() => clearZoneCache());

test('返回的域名对象不带 Token，只有 ownerId 与 username', async () => {
  const stub = stubFetch(() => okResponse([zone('a.com', 'z1')]));
  try {
    const fetcher = new CloudflareFetcher(makeManager([{ id: 'acc1', key: TOKEN, username: '主账户' }]), null);
    const list = await fetcher.fetchAllDomains();

    assert.equal(list.length, 1);
    assert.equal(list[0].name, 'a.com');
    assert.equal(list[0].username, '主账户');
    assert.equal(list[0].ownerId, 'acc1');
    assert.equal(list[0].account, undefined, '域名对象不该带 account 字段');
    assert.ok(!JSON.stringify(list).includes(TOKEN), '序列化后不应出现明文 Token');
  } finally {
    stub.restore();
  }
});

test('写入 KV 的缓存里不含 Token', async () => {
  const kv = fakeKV();
  const stub = stubFetch(() => okResponse([zone('a.com', 'z1')]));
  try {
    const fetcher = new CloudflareFetcher(makeManager([{ id: 'acc1', key: TOKEN, username: '主账户' }]), kv);
    await fetcher.fetchAllDomains();

    const raw = kv.store.get('cache:zones:v1');
    assert.ok(raw, '应该写了缓存');
    assert.ok(!raw.includes(TOKEN), 'KV 缓存里不应出现明文 Token');
  } finally {
    stub.restore();
  }
});

test('第二次调用命中缓存，不再请求 Cloudflare', async () => {
  const kv = fakeKV();
  const stub = stubFetch(() => okResponse([zone('a.com', 'z1')]));
  try {
    const manager = makeManager([{ id: 'acc1', key: TOKEN, username: '主账户' }]);
    const first = new CloudflareFetcher(manager, kv);
    await first.fetchAllDomains();
    const afterFirst = stub.calls.length;

    // 换一个实例（模拟下一个请求），进程内缓存仍应命中
    const second = new CloudflareFetcher(manager, kv);
    const list = await second.fetchAllDomains();

    assert.equal(stub.calls.length, afterFirst, '命中缓存时不应再发请求');
    assert.equal(list[0].name, 'a.com');
    assert.equal(list[0].username, '主账户');
  } finally {
    stub.restore();
  }
});

test('进程内缓存清空后，从 KV 还原且不丢 username', async () => {
  const kv = fakeKV();
  const stub = stubFetch(() => okResponse([zone('a.com', 'z1')]));
  try {
    const manager = makeManager([{ id: 'acc1', key: TOKEN, username: '主账户' }]);
    await new CloudflareFetcher(manager, kv).fetchAllDomains();
    const afterFirst = stub.calls.length;

    clearZoneCache(); // 只清内存，KV 还在

    const list = await new CloudflareFetcher(manager, kv).fetchAllDomains();
    assert.equal(stub.calls.length, afterFirst, 'KV 命中时不应再发请求');
    assert.equal(list[0].username, '主账户');
  } finally {
    stub.restore();
  }
});

test('账户集合变化后缓存失效', async () => {
  const kv = fakeKV();
  const stub = stubFetch(() => okResponse([zone('a.com', 'z1')]));
  try {
    const one = makeManager([{ id: 'acc1', key: TOKEN, username: '主账户' }]);
    await new CloudflareFetcher(one, kv).fetchAllDomains();
    const afterFirst = stub.calls.length;

    const two = makeManager([
      { id: 'acc1', key: TOKEN, username: '主账户' },
      { id: 'acc2', key: 'another-token', username: '备用账户' }
    ]);
    await new CloudflareFetcher(two, kv).fetchAllDomains();

    assert.ok(stub.calls.length > afterFirst, '账户变了应该重新拉取');
  } finally {
    stub.restore();
  }
});

test('全部账户失败时不写缓存，避免空列表挂两分钟', async () => {
  const kv = fakeKV();
  const stub = stubFetch(() => ({ ok: false, status: 500, statusText: 'Internal', async json() { return {}; } }));
  try {
    const fetcher = new CloudflareFetcher(makeManager([{ id: 'acc1', key: TOKEN, username: '主账户' }]), kv);
    const list = await fetcher.fetchAllDomains();

    assert.deepEqual(list, []);
    assert.equal(kv.store.get('cache:zones:v1'), undefined, '全挂时不该写缓存');
  } finally {
    stub.restore();
  }
});

test('force 跳过缓存直连 API', async () => {
  const kv = fakeKV();
  const stub = stubFetch(() => okResponse([zone('a.com', 'z1')]));
  try {
    const manager = makeManager([{ id: 'acc1', key: TOKEN, username: '主账户' }]);
    await new CloudflareFetcher(manager, kv).fetchAllDomains();
    const afterFirst = stub.calls.length;

    await new CloudflareFetcher(manager, kv).fetchAllDomains({ force: true });
    assert.ok(stub.calls.length > afterFirst, 'force 应该绕过缓存');
  } finally {
    stub.restore();
  }
});

test('没有可用账户时抛出明确错误', async () => {
  const fetcher = new CloudflareFetcher(makeManager([]), null);
  await assert.rejects(() => fetcher.fetchAllDomains(), /没有可用的API密钥/);
});
