// 视图层测试：重点盯「视图读的字段，投影到底给不给」。
//
// 这类 bug 单测和冒烟都容易漏：页面能渲染、状态码 200、没有 JS 报错，
// 只是某个字段恒为 undefined，于是徽标一直显示「未设置」、备注被清空。
// 本轮真踩到两处（settingsView 读 s.accessPassword 而投影给的是 accessPasswordSet；
// getAllAccounts 漏了 note 导致编辑账户会清空备注），所以单独钉住。
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { settingsView, accountsView, dnsheView, notifyView } from '../src/ui/views.js';
import { publicSettings, DEFAULT_SETTINGS } from '../src/managers/settings-store.js';
import { publicAccount } from '../src/managers/accounts-store.js';
import { publicCredential } from '../src/managers/dnshe-store.js';
import { publicNotifyConfig } from '../src/managers/notify-store.js';

describe('settingsView', () => {
  const view = (settings) => settingsView({ settings, dnsheCredentials: [] });

  it('已设置密码时显示「已设置（KV）」，不是「未设置」', () => {
    const html = view({
      accessPasswordSet: true, accessPasswordSource: 'kv',
      adminPasswordSet: true, adminPasswordSource: 'kv'
    });
    assert.ok(html.includes('已设置（KV）'));
    assert.ok(!html.includes('未设置'));
  });

  it('未设置密码时显示「未设置」', () => {
    const html = view({ accessPasswordSet: false, adminPasswordSet: false });
    assert.equal((html.match(/未设置/g) || []).length, 2);
  });

  it('密码来自环境变量时徽标区分开', () => {
    const html = view({ accessPasswordSet: true, accessPasswordSource: 'env' });
    assert.ok(html.includes('来自环境变量'));
  });

  it('已设置时输入框提示「留空表示不修改」', () => {
    const html = view({ accessPasswordSet: true, accessPasswordSource: 'kv' });
    assert.ok(html.includes('留空表示不修改'));
  });

  // 视图读的每个字段都必须在 publicSettings 的产出里
  it('publicSettings 覆盖视图读取的全部字段', () => {
    const pub = publicSettings(DEFAULT_SETTINGS, {});
    const html = view(pub);

    // 从渲染结果反查：不该出现 undefined 字样
    assert.ok(!/undefined/.test(html), '渲染结果里出现了 undefined');

    for (const key of ['accessPasswordSet', 'accessPasswordSource', 'adminPasswordSet',
      'adminPasswordSource', 'tokenSecretSet', 'sessionHours', 'whoisProxy',
      'whoisProxySource', 'freeDomainLiveLookup', 'freeDomainLookupTimeout',
      'freeDomainLookupUa', 'paceDnshe', 'paceWhois', 'paceRdap']) {
      assert.ok(key in pub, 'publicSettings 缺少字段：' + key);
    }
  });

  it('publicSettings 不泄露哈希', () => {
    const pub = publicSettings(DEFAULT_SETTINGS, {});
    const blob = JSON.stringify(pub);
    assert.ok(!blob.includes('hash'));
    assert.ok(!blob.includes('salt'));
  });
});

describe('accountsView', () => {
  // 视图拿的是 getAllAccounts() 的产出：tokenMasked 已掩码，没有明文 token
  const account = {
    id: 'acct_1', label: '主账户', username: 'gemini',
    tokenMasked: 'abcdef••••••••cdef', active: true, errorCount: 0,
    lastUsed: null, note: '主站与客户站点'
  };
  const model = (over = {}) => ({
    accounts: [account], domains: [], isAdmin: true, accountSource: 'kv', ...over
  });

  it('渲染备注，且 Token 只出现掩码', () => {
    const html = accountsView(model());
    assert.ok(html.includes('主站与客户站点'));
    assert.ok(html.includes('abcdef••••••••cdef'));
  });

  it('没有 tokenMasked 时显示占位符而不是 undefined', () => {
    const html = accountsView(model({ accounts: [{ ...account, tokenMasked: undefined }] }));
    assert.ok(html.includes('>—<'));
    assert.ok(!html.includes('undefined'));
  });

  it('没有备注时不渲染多余分隔符', () => {
    const html = accountsView(model({ accounts: [{ ...account, note: '' }] }));
    assert.ok(!html.includes('gemini · </small>'));
  });

  it('非管理员不渲染操作按钮', () => {
    const html = accountsView(model({ isAdmin: false }));
    assert.ok(!html.includes('data-action="acct-remove"'));
    assert.ok(!html.includes('data-action="acct-add"'));
  });

  it('错误数达到阈值时用 danger 色', () => {
    const html = accountsView(model({ accounts: [{ ...account, errorCount: 3 }] }));
    assert.ok(html.includes('var(--danger)'));
  });

  it('账户为空时给出引导而不是空表格', () => {
    const html = accountsView(model({ accounts: [] }));
    assert.ok(html.includes('还没有配置 Cloudflare 账户'));
  });

  it('来源是环境变量时提示可导入', () => {
    const html = accountsView(model({ accountSource: 'env' }));
    assert.ok(html.includes('acct-import'));
    assert.ok(html.includes('CF_API_KEYS'));
  });
});

describe('dnsheView', () => {
  it('渲染掩码 Key，不含明文', () => {
    const cred = publicCredential({
      id: 'dnshe_1', label: '主账户', key: 'cfsd_9f2a7c41b8e3', secret: 'sk_7d1e5a9c2b4f', enabled: true
    });
    const html = dnsheView({ dnsheCredentials: [cred], admin: true });

    assert.ok(html.includes('••'));
    assert.ok(!html.includes('cfsd_9f2a7c41b8e3'));
    assert.ok(!html.includes('sk_7d1e5a9c2b4f'));
  });

  it('停用的凭证有区分标记', () => {
    const cred = publicCredential({ id: 'd', label: 'X', key: 'cfsd_12345678', enabled: false });
    const html = dnsheView({ dnsheCredentials: [cred], admin: true });
    assert.match(html, /switch(?! on)/);
  });

  it('只剩环境变量凭证时提示"缺 Secret"', () => {
    const html = dnsheView({
      dnsheCredentials: [], admin: true,
      dnsheEnv: { hasKey: true, hasSecret: false }
    });
    assert.match(html, /当前在用环境变量/);
    assert.match(html, /缺少 <code>DNSHE_API_SECRET<\/code>/);
  });

  it('页面里已有凭证时不再提示环境变量', () => {
    const cred = publicCredential({ id: 'd', label: 'X', key: 'cfsd_12345678', secret: 'sk_12345678', enabled: true });
    const html = dnsheView({
      dnsheCredentials: [cred], admin: true,
      dnsheEnv: { hasKey: true, hasSecret: true }
    });
    assert.ok(!html.includes('当前在用环境变量'));
  });
});

describe('notifyView', () => {
  const config = publicNotifyConfig({
    enabled: true,
    rules: { daysBefore: 30, includeExpired: true, timezoneOffset: 8 },
    channels: [
      { id: 'ch_1', type: 'feishu', label: '运维群', enabled: true, config: { webhook: 'https://open.feishu.cn/open-apis/bot/v2/hook/abcdef123456' } },
      { id: 'ch_2', type: 'telegram', label: 'TG', enabled: true, config: { token: '123456:ABCDEF', chatId: '100' } }
    ]
  });

  it('渲染渠道行，且不泄露 Webhook token', () => {
    const html = notifyView({ notify: config, notifyState: {} });
    assert.ok(html.includes('运维群'));
    assert.ok(html.includes('Telegram') || html.includes('飞书机器人'));
    assert.ok(!html.includes('abcdef123456'));
  });

  it('规则值回填到下拉框', () => {
    const html = notifyView({ notify: config, notifyState: {} });
    assert.match(html, /<option value="30" selected>/);
  });

  it('渠道缺字段时显示「缺少字段」', () => {
    const bad = publicNotifyConfig({
      enabled: true, rules: {},
      channels: [{ id: 'c', type: 'telegram', label: 'T', enabled: true, config: { token: 'x' } }]
    });
    const html = notifyView({ notify: bad, notifyState: {} });
    assert.ok(html.includes('缺少字段'));
  });

  it('渠道齐全时显示「已配置」', () => {
    const html = notifyView({ notify: config, notifyState: {} });
    assert.ok(html.includes('已配置'));
  });
});
