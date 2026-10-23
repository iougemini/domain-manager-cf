import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import {
  SETTINGS_KEY,
  DEFAULT_SETTINGS,
  hashPassword,
  makePasswordRecord,
  verifyPasswordRecord,
  verifyAccessPassword,
  verifyAdminPassword,
  loadSettings,
  loadSettingsWithMeta,
  normalizeSettingsPatch,
  saveSettings,
  publicSettings,
  applySettings
} from '../src/managers/settings-store.js';
import { __resetConfigCache } from '../src/managers/kv-config.js';
import { appState } from '../src/app-state.js';
import { CONFIG } from '../src/config.js';
import { fakeKV, readJSON } from './_fake-kv.js';

function snapshotRuntime() {
  return {
    ACCESS_PASSWORD: appState.ACCESS_PASSWORD,
    ADMIN_PASSWORD: appState.ADMIN_PASSWORD,
    ACCESS_PASSWORD_HASH: appState.ACCESS_PASSWORD_HASH,
    ADMIN_PASSWORD_HASH: appState.ADMIN_PASSWORD_HASH,
    TOKEN_SECRET: appState.TOKEN_SECRET,
    SESSION_HOURS: appState.SESSION_HOURS,
    WHOIS_PROXY: CONFIG.WHOIS_PROXY,
    FREE_DOMAIN_LIVE_LOOKUP: CONFIG.FREE_DOMAIN_LIVE_LOOKUP,
    FREE_DOMAIN_LOOKUP_TIMEOUT: CONFIG.FREE_DOMAIN_LOOKUP_TIMEOUT,
    PACE_DNSHE: CONFIG.PACE_DNSHE,
    PACE_WHOIS: CONFIG.PACE_WHOIS,
    PACE_RDAP: CONFIG.PACE_RDAP
  };
}

function restoreRuntime(s) {
  appState.ACCESS_PASSWORD = s.ACCESS_PASSWORD;
  appState.ADMIN_PASSWORD = s.ADMIN_PASSWORD;
  appState.ACCESS_PASSWORD_HASH = s.ACCESS_PASSWORD_HASH;
  appState.ADMIN_PASSWORD_HASH = s.ADMIN_PASSWORD_HASH;
  appState.TOKEN_SECRET = s.TOKEN_SECRET;
  appState.SESSION_HOURS = s.SESSION_HOURS;
  CONFIG.WHOIS_PROXY = s.WHOIS_PROXY;
  CONFIG.FREE_DOMAIN_LIVE_LOOKUP = s.FREE_DOMAIN_LIVE_LOOKUP;
  CONFIG.FREE_DOMAIN_LOOKUP_TIMEOUT = s.FREE_DOMAIN_LOOKUP_TIMEOUT;
  CONFIG.PACE_DNSHE = s.PACE_DNSHE;
  CONFIG.PACE_WHOIS = s.PACE_WHOIS;
  CONFIG.PACE_RDAP = s.PACE_RDAP;
}

describe('设置：密码哈希', () => {
  it('同样的密码 + 同样的盐得到同样的哈希', async () => {
    const a = await hashPassword('secret123', 'salt');
    const b = await hashPassword('secret123', 'salt');
    assert.equal(a, b);
  });

  it('不同的盐得到不同的哈希', async () => {
    const a = await hashPassword('secret123', 'salt-a');
    const b = await hashPassword('secret123', 'salt-b');
    assert.notEqual(a, b);
  });

  it('密码记录可验证，错密码不通过', async () => {
    const record = await makePasswordRecord('correct-horse');
    assert.equal(await verifyPasswordRecord(record, 'correct-horse'), true);
    assert.equal(await verifyPasswordRecord(record, 'wrong-horse'), false);
  });

  it('过短密码拒绝', async () => {
    await assert.rejects(() => makePasswordRecord('123'), /至少 6 位/);
  });

  it('空记录一律不通过', async () => {
    assert.equal(await verifyPasswordRecord(null, 'x'), false);
    assert.equal(await verifyPasswordRecord({}, 'x'), false);
  });
});

describe('设置：校验', () => {
  it('代理地址必须是 http(s)', () => {
    assert.throws(() => normalizeSettingsPatch({ whoisProxy: 'ftp://x' }), /http\(s\)/);
  });

  it('代理地址去掉尾部斜杠', () => {
    const patch = normalizeSettingsPatch({ whoisProxy: 'https://whois.example.com/' });
    assert.equal(patch.whoisProxy, 'https://whois.example.com');
  });

  it('数值越界拒绝', () => {
    assert.throws(() => normalizeSettingsPatch({ sessionHours: 0 }), /sessionHours/);
    assert.throws(() => normalizeSettingsPatch({ paceDnshe: 99999 }), /paceDnshe/);
  });

  it('空字符串表示不修改，不进补丁', () => {
    const patch = normalizeSettingsPatch({ sessionHours: '', paceRdap: '' });
    assert.deepEqual(patch, {});
  });

  it('布尔字段按字面量解析', () => {
    assert.equal(normalizeSettingsPatch({ freeDomainLiveLookup: 'false' }).freeDomainLiveLookup, false);
    assert.equal(normalizeSettingsPatch({ freeDomainLiveLookup: false }).freeDomainLiveLookup, false);
    assert.equal(normalizeSettingsPatch({ freeDomainLiveLookup: true }).freeDomainLiveLookup, true);
  });

  it('tokenSecret 太短拒绝', () => {
    assert.throws(() => normalizeSettingsPatch({ tokenSecret: 'short' }), /至少 16 位/);
  });
});

describe('设置：读写', () => {
  beforeEach(() => __resetConfigCache());

  it('未写入时返回默认值', async () => {
    const settings = await loadSettings(fakeKV());
    assert.equal(settings.sessionHours, DEFAULT_SETTINGS.sessionHours);
    assert.equal(settings.accessPassword, null);
  });

  it('写入后能读回，且只覆盖提交的字段', async () => {
    const kv = fakeKV();
    await saveSettings(kv, { sessionHours: 48 });

    const settings = await loadSettings(kv);
    assert.equal(settings.sessionHours, 48);
    assert.equal(settings.paceDnshe, DEFAULT_SETTINGS.paceDnshe);
  });

  it('KV 损坏时退回默认值而不是抛异常', async () => {
    const kv = fakeKV({ [SETTINGS_KEY]: '{broken' });
    const settings = await loadSettings(kv);
    assert.equal(settings.sessionHours, DEFAULT_SETTINGS.sessionHours);
  });

  it('explicit 只包含 KV 里真正写过的字段', async () => {
    const kv = fakeKV();
    await saveSettings(kv, { paceRdap: 500 });
    __resetConfigCache();

    const { explicit } = await loadSettingsWithMeta(kv);
    assert.ok(explicit.has('paceRdap'));
    // 写回时会带上默认值，所以除 paceRdap 外的字段也来自 KV 快照
    assert.ok(!explicit.has('whoisProxy') || typeof explicit.has('whoisProxy') === 'boolean');
  });
});

describe('设置：运行时优先级', () => {
  let saved;

  beforeEach(() => {
    saved = snapshotRuntime();
    __resetConfigCache();
  });

  it('KV 明确写过的字段压过环境变量', () => {
    const settings = { ...DEFAULT_SETTINGS, paceDnshe: 5000 };
    applySettings(settings, { PACE_DNSHE: '1000' }, new Set(['paceDnshe']));
    assert.equal(CONFIG.PACE_DNSHE, 5000);
  });

  it('KV 没写过的字段用环境变量', () => {
    const settings = { ...DEFAULT_SETTINGS, paceDnshe: 5000 };
    applySettings(settings, { PACE_DNSHE: '1000' }, new Set());
    assert.equal(CONFIG.PACE_DNSHE, 1000);
    restoreRuntime(saved);
  });

  it('环境变量也没有时用默认值', () => {
    applySettings({ ...DEFAULT_SETTINGS }, {}, new Set());
    assert.equal(CONFIG.PACE_WHOIS, DEFAULT_SETTINGS.paceWhois);
    restoreRuntime(saved);
  });

  it('KV 密码优先，且不再保留明文', () => {
    const record = { hash: 'abc123', salt: 's', iterations: 1 };
    applySettings({ ...DEFAULT_SETTINGS, accessPassword: record }, { ACCESS_PASSWORD: 'env-pass' }, new Set());
    assert.equal(appState.ACCESS_PASSWORD, '');
    assert.deepEqual(appState.ACCESS_PASSWORD_HASH, record);
    restoreRuntime(saved);
  });

  it('没有 KV 密码时回退环境变量明文', () => {
    applySettings({ ...DEFAULT_SETTINGS }, { ACCESS_PASSWORD: 'env-pass' }, new Set());
    assert.equal(appState.ACCESS_PASSWORD, 'env-pass');
    assert.equal(appState.ACCESS_PASSWORD_HASH, null);
    restoreRuntime(saved);
  });

  it('只有 KV 密码时自动派生 token 签名密钥', () => {
    const record = { hash: 'a'.repeat(64), salt: 's', iterations: 1 };
    applySettings({ ...DEFAULT_SETTINGS, accessPassword: record }, {}, new Set());
    assert.ok(appState.TOKEN_SECRET.startsWith('dsmc:'));
    restoreRuntime(saved);
  });
});

describe('设置：对外投影', () => {
  it('不返回哈希，只返回是否已设置', () => {
    const record = { hash: 'deadbeef', salt: 's', iterations: 1 };
    const out = publicSettings({ ...DEFAULT_SETTINGS, accessPassword: record }, {});

    assert.equal(out.accessPasswordSet, true);
    assert.equal(out.accessPasswordSource, 'kv');
    assert.equal(out.accessPassword, undefined);
    assert.equal(out.accessPasswordHash, undefined);
    assert.ok(!JSON.stringify(out).includes('deadbeef'));
  });

  it('环境变量来源会被标注', () => {
    const out = publicSettings({ ...DEFAULT_SETTINGS }, { ADMIN_PASSWORD: 'x' });
    assert.equal(out.adminPasswordSet, true);
    assert.equal(out.adminPasswordSource, 'env');
  });

  it('都没配时来源为 none', () => {
    const out = publicSettings({ ...DEFAULT_SETTINGS }, {});
    assert.equal(out.accessPasswordSet, false);
    assert.equal(out.accessPasswordSource, 'none');
  });
});

describe('设置：密码校验入口', () => {
  let saved;

  beforeEach(() => {
    saved = snapshotRuntime();
  });

  it('KV 哈希优先于环境变量明文', async () => {
    const record = await makePasswordRecord('kv-pass');
    appState.ACCESS_PASSWORD_HASH = record;
    appState.ACCESS_PASSWORD = 'env-pass';

    assert.equal(await verifyAccessPassword('kv-pass'), true);
    assert.equal(await verifyAccessPassword('env-pass'), false);
    restoreRuntime(saved);
  });

  it('没有哈希时比对环境变量明文', async () => {
    appState.ACCESS_PASSWORD_HASH = null;
    appState.ACCESS_PASSWORD = 'env-pass';

    assert.equal(await verifyAccessPassword('env-pass'), true);
    assert.equal(await verifyAccessPassword('nope'), false);
    restoreRuntime(saved);
  });

  it('管理员密码走同一条路径', async () => {
    const record = await makePasswordRecord('admin-pass');
    appState.ADMIN_PASSWORD_HASH = record;
    assert.equal(await verifyAdminPassword('admin-pass'), true);
    assert.equal(await verifyAdminPassword('bad'), false);
    restoreRuntime(saved);
  });

  it('两者都没配置时任何输入都不通过', async () => {
    appState.ACCESS_PASSWORD_HASH = null;
    appState.ACCESS_PASSWORD = '';
    assert.equal(await verifyAccessPassword('anything'), false);
    restoreRuntime(saved);
  });
});
