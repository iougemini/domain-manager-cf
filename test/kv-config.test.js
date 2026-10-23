import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  MEM_TTL,
  invalidateConfig,
  __resetConfigCache,
  readConfig,
  writeConfig,
  mutateConfig,
  makeId,
  maskSecret
} from '../src/managers/kv-config.js';
import { fakeKV, readJSON } from './_fake-kv.js';

beforeEach(() => __resetConfigCache());

describe('readConfig', () => {
  it('读到 JSON 就解析', async () => {
    const kv = fakeKV({ 'config:x': JSON.stringify({ a: 1 }) });
    assert.deepEqual(await readConfig(kv, 'config:x'), { a: 1 });
  });

  it('key 不存在时返回 fallback', async () => {
    const kv = fakeKV();
    assert.equal(await readConfig(kv, 'config:none'), null);
    assert.deepEqual(await readConfig(kv, 'config:none2', { d: 1 }), { d: 1 });
  });

  // 空值也进缓存（省一次 KV 往返），所以同一个 key 后续调用拿到的是首次的 fallback。
  // 代码里每个 key 只用固定一个 fallback，因此这是安全的；这里把语义钉住防回归。
  it('空值被缓存，后续同 key 返回首次 fallback', async () => {
    const kv = fakeKV();
    assert.equal(await readConfig(kv, 'config:miss', null), null);
    assert.equal(await readConfig(kv, 'config:miss', { d: 1 }), null);
  });

  it('空字符串也当作缺失', async () => {
    const kv = fakeKV({ 'config:empty': '' });
    assert.equal(await readConfig(kv, 'config:empty'), null);
  });

  it('坏 JSON 不抛异常，退回 fallback', async () => {
    const kv = fakeKV({ 'config:bad': '{not json' });
    assert.deepEqual(await readConfig(kv, 'config:bad', { ok: true }), { ok: true });
  });

  it('KV 未绑定时安全返回 fallback', async () => {
    assert.equal(await readConfig(null, 'config:x'), null);
    assert.deepEqual(await readConfig(undefined, 'config:x', []), []);
  });

  it('命中缓存后不再读 KV', async () => {
    let gets = 0;
    const kv = {
      get: async k => { gets++; return JSON.stringify({ n: gets }); },
      put: async () => {}
    };
    await readConfig(kv, 'config:cache');
    const second = await readConfig(kv, 'config:cache');
    assert.equal(gets, 1);
    assert.equal(second.n, 1);
  });
});

describe('writeConfig', () => {
  it('写入后立即可读（缓存已更新）', async () => {
    const kv = fakeKV();
    await writeConfig(kv, 'config:w', { v: 1 });
    assert.deepEqual(readJSON(kv, 'config:w'), { v: 1 });
    // 不走 KV 也应拿到新值
    assert.deepEqual(await readConfig(kv, 'config:w'), { v: 1 });
  });

  it('KV 未绑定时抛错，而不是静默失败', async () => {
    await assert.rejects(() => writeConfig(null, 'k', {}), /KV 未绑定/);
  });

  it('invalidateConfig 让下一次读回到 KV', async () => {
    const kv = fakeKV({ 'config:i': JSON.stringify({ v: 'old' }) });
    await readConfig(kv, 'config:i');
    // 模拟另一个 isolate 改了值
    await kv.put('config:i', JSON.stringify({ v: 'new' }));
    invalidateConfig('config:i');
    assert.deepEqual(await readConfig(kv, 'config:i'), { v: 'new' });
  });

  it('MEM_TTL 是 60 秒', () => {
    assert.equal(MEM_TTL, 60000);
  });
});

describe('mutateConfig', () => {
  it('基于 KV 最新值修改，不用内存旧值', async () => {
    const kv = fakeKV({ 'config:m': JSON.stringify({ list: ['a'] }) });
    // 先让缓存装上一个旧值
    await readConfig(kv, 'config:m');
    // 别处追加了 b
    await kv.put('config:m', JSON.stringify({ list: ['a', 'b'] }));

    const next = await mutateConfig(kv, 'config:m', { list: [] }, cur => ({
      list: [...cur.list, 'c']
    }));
    assert.deepEqual(next.list, ['a', 'b', 'c']);
  });

  it('key 缺失时用 fallback 起步', async () => {
    const kv = fakeKV();
    const next = await mutateConfig(kv, 'config:m2', { n: 0 }, cur => ({ n: cur.n + 1 }));
    assert.equal(next.n, 1);
  });

  it('坏 JSON 时用 fallback 起步而不是崩', async () => {
    const kv = fakeKV({ 'config:m3': 'oops' });
    const next = await mutateConfig(kv, 'config:m3', { n: 5 }, cur => ({ n: cur.n + 1 }));
    assert.equal(next.n, 6);
  });
});

describe('makeId', () => {
  it('带前缀时形如 prefix_xxxxxxxx', () => {
    const id = makeId('ch');
    assert.match(id, /^ch_[0-9a-f]{8}$/);
  });

  it('不带前缀时是 8 位十六进制', () => {
    assert.match(makeId(), /^[0-9a-f]{8}$/);
  });

  it('连续生成的 ID 不相同', () => {
    const ids = new Set(Array.from({ length: 50 }, () => makeId('a')));
    assert.equal(ids.size, 50);
  });
});

describe('maskSecret', () => {
  it('空值返回空串', () => {
    assert.equal(maskSecret(''), '');
    assert.equal(maskSecret(null), '');
    assert.equal(maskSecret(undefined), '');
  });

  it('短值只露两位', () => {
    assert.equal(maskSecret('abc'), 'ab••••');
    assert.equal(maskSecret('abcdefghij'), 'ab••••');
  });

  it('长值保留首 6 尾 4', () => {
    const masked = maskSecret('1234567890abcdef');
    assert.equal(masked, '123456••••••••cdef');
    assert.ok(!masked.includes('7890abc'));
  });

  it('自定义首尾长度', () => {
    assert.equal(maskSecret('1234567890abcdef', 2, 2), '12••••••••ef');
  });

  // 机器人地址的 token 在路径末段，取前 6 位只会得到 "https:"
  it('URL 保留 origin 与路径前缀，只遮末段', () => {
    const masked = maskSecret('https://open.feishu.cn/open-apis/bot/v2/hook/abcdef123456');
    assert.equal(masked, 'https://open.feishu.cn/open-apis/bot/v2/hook/••••••••3456');
    assert.ok(!masked.includes('abcdef12'));
  });

  it('URL 末段过短时整段遮蔽', () => {
    assert.equal(maskSecret('https://example.com/hook'), 'https://example.com/••••••••');
  });

  it('只有 origin 的 URL 退回普通掩码', () => {
    const masked = maskSecret('https://example.com');
    assert.ok(masked.includes('••'));
    assert.ok(masked.startsWith('https:'));
  });

  it('http 与 https 都走 URL 分支', () => {
    assert.ok(maskSecret('http://a.test/x/secretvalue').startsWith('http://a.test/x/'));
  });

  it('掩码结果始终含 ••（前端据此判断"未修改"）', () => {
    for (const v of ['a', 'abcdefghijklmnop', 'https://x.test/a/b', 'https://x.test']) {
      assert.ok(maskSecret(v).includes('••'), v);
    }
  });
});
