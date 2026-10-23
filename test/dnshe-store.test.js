import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import {
  DNSHE_KEY,
  normalizeDnshePayload,
  publicCredential,
  loadDnsheCredentials,
  enabledDnsheCredentials,
  upsertDnsheCredential,
  removeDnsheCredential,
  toggleDnsheCredential
} from '../src/managers/dnshe-store.js';
import { __resetConfigCache } from '../src/managers/kv-config.js';
import { fakeKV, readJSON } from './_fake-kv.js';

const KEY_A = 'cfsd_9f2a7c41b8e3';
const KEY_B = 'cfsd_3b8d6e0a1c9f';
const SECRET_A = 'sk_7d1e5a9c2b4f';
const SECRET_B = 'sk_2a4c8e0f6b1d';

describe('DNSHE 凭证：校验', () => {
  it('缺少 Key 拒绝', () => {
    assert.throws(() => normalizeDnshePayload({ secret: SECRET_A }), /API Key/);
  });

  it('Key 含非法字符拒绝', () => {
    assert.throws(() => normalizeDnshePayload({ key: 'cfsd 9f2a!', secret: SECRET_A }), /格式异常/);
  });

  it('新增时必须给 Secret', () => {
    assert.throws(() => normalizeDnshePayload({ key: KEY_A }), /API Secret/);
  });

  it('编辑时允许不传 Secret', () => {
    const entry = normalizeDnshePayload({ key: KEY_A }, { requireSecret: false });
    assert.equal(entry.key, KEY_A);
    assert.equal(entry.secret, '');
  });

  it('label 留空时回退为 DNSHE', () => {
    const entry = normalizeDnshePayload({ key: KEY_A, secret: SECRET_A });
    assert.equal(entry.label, 'DNSHE');
  });
});

describe('DNSHE 凭证：CRUD', () => {
  beforeEach(() => __resetConfigCache());

  it('新增后写入 KV', async () => {
    const kv = fakeKV();
    const created = await upsertDnsheCredential(kv, {
      label: '主账户', key: KEY_A, secret: SECRET_A
    });

    assert.ok(created.id.startsWith('dnshe_'));
    const stored = readJSON(kv, DNSHE_KEY);
    assert.equal(stored.length, 1);
    assert.equal(stored[0].key, KEY_A);
  });

  it('拒绝重复的 Key', async () => {
    const kv = fakeKV();
    await upsertDnsheCredential(kv, { key: KEY_A, secret: SECRET_A });
    await assert.rejects(
      () => upsertDnsheCredential(kv, { key: KEY_A, secret: SECRET_B }),
      /已经添加过/
    );
  });

  it('编辑时 Secret 留空则保留原值', async () => {
    const kv = fakeKV();
    const created = await upsertDnsheCredential(kv, { key: KEY_A, secret: SECRET_A });

    await upsertDnsheCredential(kv, { label: '改名', key: KEY_A, secret: '' }, created.id);

    const stored = readJSON(kv, DNSHE_KEY)[0];
    assert.equal(stored.label, '改名');
    assert.equal(stored.secret, SECRET_A);
  });

  it('删除不存在的凭证报错', async () => {
    await assert.rejects(() => removeDnsheCredential(fakeKV(), 'dnshe_x'), /不存在/);
  });

  it('启停切换只影响 enabled', async () => {
    const kv = fakeKV();
    const created = await upsertDnsheCredential(kv, { key: KEY_A, secret: SECRET_A });

    assert.equal(await toggleDnsheCredential(kv, created.id), false);
    const all = await loadDnsheCredentials(kv);
    assert.equal(all[0].enabled, false);
    assert.equal(all[0].key, KEY_A);
  });
});

describe('DNSHE 凭证：生效集合', () => {
  beforeEach(() => __resetConfigCache());

  it('只返回启用中的凭证，保持添加顺序', async () => {
    const kv = fakeKV();
    await upsertDnsheCredential(kv, { key: KEY_A, secret: SECRET_A });
    const second = await upsertDnsheCredential(kv, { key: KEY_B, secret: SECRET_B });
    await toggleDnsheCredential(kv, second.id);

    const enabled = await enabledDnsheCredentials(kv);
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0].key, KEY_A);
  });

  it('KV 为空时返回空数组而不是抛错', async () => {
    assert.deepEqual(await loadDnsheCredentials(fakeKV()), []);
  });

  it('KV 内容损坏时返回空数组', async () => {
    const kv = fakeKV({ [DNSHE_KEY]: 'not-json' });
    assert.deepEqual(await loadDnsheCredentials(kv), []);
  });
});

describe('DNSHE 凭证：对外投影', () => {
  it('Key 与 Secret 都只返回掩码', () => {
    const out = publicCredential({
      id: 'dnshe_1', label: '主账户', key: KEY_A, secret: SECRET_A, enabled: true
    });

    assert.ok(out.keyMasked.includes('••'));
    assert.ok(out.secretMasked.includes('••'));
    assert.equal(out.key, undefined);
    assert.equal(out.secret, undefined);
    assert.ok(!JSON.stringify(out).includes(SECRET_A));
  });
});
