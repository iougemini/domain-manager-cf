import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import {
  ACCOUNTS_KEY,
  accountsFromEnv,
  normalizeAccountPayload,
  publicAccount,
  resolveAccounts,
  upsertAccount,
  removeAccount,
  toggleAccount,
  importAccountsFromEnv,
  saveAccounts
} from '../src/managers/accounts-store.js';
import { __resetConfigCache } from '../src/managers/kv-config.js';
import { fakeKV, readJSON } from './_fake-kv.js';

const TOKEN_A = 'abcdefghijklmnopqrstuvwxyz0123456789';
const TOKEN_B = 'zyxwvutsrqponmlkjihgfedcba9876543210';

describe('账户存储：校验', () => {
  it('缺少账户名称直接拒绝', () => {
    assert.throws(() => normalizeAccountPayload({ token: TOKEN_A }), /账户名称/);
  });

  it('缺少 Token 时拒绝（新增场景）', () => {
    assert.throws(() => normalizeAccountPayload({ username: 'main' }), /API Token/);
  });

  it('编辑时允许不传 Token', () => {
    const entry = normalizeAccountPayload({ username: 'main' }, { requireToken: false });
    assert.equal(entry.username, 'main');
    assert.equal(entry.token, undefined);
  });

  it('Token 含空格拒绝', () => {
    assert.throws(
      () => normalizeAccountPayload({ username: 'main', token: 'abc def ghi jkl mnop qrst' }),
      /不能包含空格/
    );
  });

  it('Token 过短拒绝', () => {
    assert.throws(() => normalizeAccountPayload({ username: 'main', token: 'short' }), /长度异常/);
  });

  it('label 留空时回退到 username', () => {
    const entry = normalizeAccountPayload({ username: 'main', token: TOKEN_A });
    assert.equal(entry.label, 'main');
  });
});

describe('账户存储：CRUD', () => {
  beforeEach(() => __resetConfigCache());

  it('新增后能从 KV 读回', async () => {
    const kv = fakeKV();
    const created = await upsertAccount(kv, { username: 'main', label: '主账户', token: TOKEN_A });

    assert.ok(created.id.startsWith('acct_'));
    const stored = readJSON(kv, ACCOUNTS_KEY);
    assert.equal(stored.length, 1);
    assert.equal(stored[0].token, TOKEN_A);
  });

  it('拒绝同名账户', async () => {
    const kv = fakeKV();
    await upsertAccount(kv, { username: 'main', token: TOKEN_A });
    await assert.rejects(
      () => upsertAccount(kv, { username: 'MAIN', token: TOKEN_B }),
      /同名账户/
    );
  });

  it('编辑时 token 留空则保留原值', async () => {
    const kv = fakeKV();
    const created = await upsertAccount(kv, { username: 'main', token: TOKEN_A });

    await upsertAccount(kv, { username: 'main2', token: '' }, created.id);

    const stored = readJSON(kv, ACCOUNTS_KEY)[0];
    assert.equal(stored.username, 'main2');
    assert.equal(stored.token, TOKEN_A);
    assert.ok(stored.updatedAt);
  });

  it('编辑时填了新 token 则替换', async () => {
    const kv = fakeKV();
    const created = await upsertAccount(kv, { username: 'main', token: TOKEN_A });
    await upsertAccount(kv, { username: 'main', token: TOKEN_B }, created.id);

    assert.equal(readJSON(kv, ACCOUNTS_KEY)[0].token, TOKEN_B);
  });

  it('删除不存在的账户报错', async () => {
    const kv = fakeKV();
    await assert.rejects(() => removeAccount(kv, 'acct_missing'), /不存在/);
  });

  it('删除后列表为空', async () => {
    const kv = fakeKV();
    const created = await upsertAccount(kv, { username: 'main', token: TOKEN_A });
    await removeAccount(kv, created.id);
    assert.deepEqual(readJSON(kv, ACCOUNTS_KEY), []);
  });

  it('启停切换', async () => {
    const kv = fakeKV();
    const created = await upsertAccount(kv, { username: 'main', token: TOKEN_A });

    assert.equal(await toggleAccount(kv, created.id), false);
    assert.equal(readJSON(kv, ACCOUNTS_KEY)[0].enabled, false);

    assert.equal(await toggleAccount(kv, created.id), true);
  });
});

describe('账户存储：来源优先级', () => {
  beforeEach(() => __resetConfigCache());

  it('KV 为空时回退环境变量', async () => {
    const kv = fakeKV();
    const env = {
      CF_API_KEYS: JSON.stringify([TOKEN_A]),
      USERNAMES: JSON.stringify(['main'])
    };

    const { accounts, source } = await resolveAccounts(kv, env);
    assert.equal(source, 'env');
    assert.equal(accounts.length, 1);
    assert.equal(accounts[0].username, 'main');
    assert.equal(accounts[0].source, 'env');
  });

  it('KV 有数据时优先 KV', async () => {
    const kv = fakeKV();
    await saveAccounts(kv, [{ id: 'acct_1', username: 'kv-account', token: TOKEN_B, enabled: true }]);
    __resetConfigCache();

    const env = { CF_API_KEYS: JSON.stringify([TOKEN_A]), USERNAMES: JSON.stringify(['env-account']) };
    const { accounts, source } = await resolveAccounts(kv, env);

    assert.equal(source, 'kv');
    assert.equal(accounts[0].username, 'kv-account');
  });

  it('两边都没有时 source 为 none', async () => {
    const { accounts, source } = await resolveAccounts(fakeKV(), {});
    assert.equal(source, 'none');
    assert.deepEqual(accounts, []);
  });

  it('环境变量 JSON 写坏时不抛异常', () => {
    const accounts = accountsFromEnv({ CF_API_KEYS: '{not json', USERNAMES: '[]' });
    assert.deepEqual(accounts, []);
  });
});

describe('账户存储：导入环境变量', () => {
  beforeEach(() => __resetConfigCache());

  it('导入后转为 KV 并可编辑', async () => {
    const kv = fakeKV();
    const env = {
      CF_API_KEYS: JSON.stringify([TOKEN_A, TOKEN_B]),
      USERNAMES: JSON.stringify(['main', 'labs'])
    };

    const result = await importAccountsFromEnv(kv, env);
    assert.equal(result.added, 2);
    assert.equal(result.total, 2);

    const { source } = await resolveAccounts(kv, env);
    assert.equal(source, 'kv');
  });

  it('重复导入不会产生重复条目', async () => {
    const kv = fakeKV();
    const env = { CF_API_KEYS: JSON.stringify([TOKEN_A]), USERNAMES: JSON.stringify(['main']) };

    await importAccountsFromEnv(kv, env);
    const second = await importAccountsFromEnv(kv, env);

    assert.equal(second.added, 0);
    assert.equal(second.total, 1);
  });

  it('环境变量为空时给出明确错误', async () => {
    await assert.rejects(() => importAccountsFromEnv(fakeKV(), {}), /没有可导入的账户/);
  });
});

describe('账户存储：对外投影', () => {
  it('Token 只返回掩码', () => {
    const out = publicAccount({ id: 'a', username: 'main', token: TOKEN_A, enabled: true });
    assert.ok(out.tokenMasked.includes('••'));
    assert.equal(out.token, undefined);
    assert.equal(out.username, 'main');
  });

  it('保留备注与启用状态', () => {
    const out = publicAccount({ id: 'a', username: 'main', token: TOKEN_A, enabled: false, note: '归档' });
    assert.equal(out.note, '归档');
    assert.equal(out.enabled, false);
  });
});

// 运行时视图必须把 note 带出来：编辑表单靠它回填，漏了就会在保存时清空原有备注
describe('ApiKeyManager 运行时视图', () => {
  it('getAllAccounts 带 note 与掩码 Token', async () => {
    const { ApiKeyManager } = await import('../src/managers/api-key.js');
    const mgr = new ApiKeyManager();
    mgr.initFromAccounts([
      { id: 'a1', label: '主账户', username: 'gemini', token: TOKEN_A, enabled: true, note: '主站' }
    ]);

    const [row] = mgr.getAllAccounts();
    assert.equal(row.note, '主站');
    assert.equal(row.label, '主账户');
    assert.equal(row.active, true);
    assert.ok(row.tokenMasked.includes('••'));
    assert.equal(row.token, undefined);
    assert.equal(row.key, undefined);
  });

  it('没有备注时返回空串而不是 undefined', async () => {
    const { ApiKeyManager } = await import('../src/managers/api-key.js');
    const mgr = new ApiKeyManager();
    mgr.initFromAccounts([{ id: 'a1', username: 'u', token: TOKEN_A }]);

    assert.equal(mgr.getAllAccounts()[0].note, '');
  });
});
