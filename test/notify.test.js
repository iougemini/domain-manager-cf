import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import {
  CHANNELS,
  channelMetas,
  isPermanentDate,
  daysUntil,
  buildExpiryDigest,
  normalizeChannelConfig,
  interpretResponse,
  NotificationService,
  buildTestMessage
} from '../src/services/notify.js';
import {
  NOTIFY_KEY,
  STATE_KEY,
  DEFAULT_NOTIFY,
  loadNotifyConfig,
  saveNotifyConfig,
  publicChannel,
  publicNotifyConfig,
  normalizeChannelPayload,
  upsertChannel,
  removeChannel,
  toggleChannel,
  saveNotifyRules,
  loadNotifyState,
  saveNotifyState,
  fingerprintOf,
  runDigest,
  testChannel
} from '../src/managers/notify-store.js';
import { __resetConfigCache } from '../src/managers/kv-config.js';
import { fakeKV, readJSON } from './_fake-kv.js';

// 固定"现在"：2026-10-21 10:00 UTC（= UTC+8 的 18:00，同一天）
const NOW = Date.parse('2026-10-21T10:00:00Z');

const DOMAINS = [
  { name: 'expired.com', account: 'main', registrar: 'CF', expirationDate: '2026-10-10' },
  { name: 'week.com', account: 'main', registrar: 'CF', expirationDate: '2026-10-25' },
  { name: 'month.com', account: 'labs', registrar: 'CF', expirationDate: '2026-11-15' },
  { name: 'far.com', account: 'labs', registrar: 'CF', expirationDate: '2027-06-01' },
  { name: 'forever.us.ci', account: 'labs', registrar: 'DNSHE', expirationDate: '2999-12-31', isPermanent: true },
  { name: 'unknown.com', account: 'main', registrar: 'CF', expirationDate: 'Unknown' }
];

function okFetch(payload = { code: 0 }) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    return { ok: true, status: 200, text: async () => JSON.stringify(payload) };
  };
  impl.calls = calls;
  return impl;
}

/* ---------------- 日期与摘要 ---------------- */

describe('通知：日期判定', () => {
  it('2999 年视为永久', () => {
    assert.equal(isPermanentDate('2999-12-31'), true);
    assert.equal(isPermanentDate('9999-12-31'), true);
    assert.equal(isPermanentDate('2027-01-01'), false);
    assert.equal(isPermanentDate('Unknown'), false);
  });

  it('按 UTC+8 计算距今天数', () => {
    assert.equal(daysUntil('2026-10-21', 8, NOW), 0);
    assert.equal(daysUntil('2026-10-25', 8, NOW), 4);
    assert.equal(daysUntil('2026-10-10', 8, NOW), -11);
  });

  it('非法日期返回 null', () => {
    assert.equal(daysUntil('Unknown', 8, NOW), null);
    assert.equal(daysUntil('', 8, NOW), null);
  });
});

describe('通知：到期摘要', () => {
  it('只收录窗口内的域名，按紧急度分组', () => {
    const digest = buildExpiryDigest(DOMAINS, { daysBefore: 30 }, NOW);

    assert.equal(digest.count, 3);
    assert.deepEqual(digest.groups, { expired: 1, week: 1, month: 1 });
    assert.equal(digest.names[0], 'expired.com');
  });

  it('永久域名不参与告警', () => {
    const digest = buildExpiryDigest(DOMAINS, { daysBefore: 3650 }, NOW);
    assert.ok(!digest.names.includes('forever.us.ci'));
  });

  it('只给哨兵日期、没有 isPermanent 标记也能排除', () => {
    const digest = buildExpiryDigest(
      [{ name: 'x.us.ci', expirationDate: '2999-12-31' }],
      { daysBefore: 30 },
      NOW
    );
    assert.equal(digest.count, 0);
  });

  it('includeExpired=false 时排除已过期', () => {
    const digest = buildExpiryDigest(DOMAINS, { daysBefore: 30, includeExpired: false }, NOW);
    assert.equal(digest.count, 2);
    assert.equal(digest.groups.expired, 0);
  });

  it('标题带数量，正文分块', () => {
    const digest = buildExpiryDigest(DOMAINS, { daysBefore: 30 }, NOW);
    assert.match(digest.title, /3 个域名/);
    assert.match(digest.text, /已过期/);
    assert.match(digest.text, /超期 11 天/);
    assert.match(digest.markdown, /###/);
    assert.match(digest.html, /<table/);
  });

  it('没有待处理域名时给出正面文案', () => {
    const digest = buildExpiryDigest(
      [{ name: 'ok.com', expirationDate: '2027-12-31' }],
      { daysBefore: 30 },
      NOW
    );
    assert.equal(digest.count, 0);
    assert.match(digest.text, /安全期/);
  });

  it('空输入不抛异常', () => {
    const digest = buildExpiryDigest(null, {}, NOW);
    assert.equal(digest.count, 0);
  });
});

/* ---------------- 渠道请求构建 ---------------- */

describe('通知：渠道请求构建', () => {
  const message = {
    title: 'T', text: 'plain body', markdown: '### md', html: '<b>x</b>'
  };

  it('通用 Webhook：JSON POST，可带鉴权头', async () => {
    const req = await CHANNELS.webhook.build({ url: 'https://x.test/hook', token: 'Bearer k' }, message, NOW);
    assert.equal(req.url, 'https://x.test/hook');
    assert.equal(req.init.headers.Authorization, 'Bearer k');

    const body = JSON.parse(req.init.body);
    assert.equal(body.source, 'DSMC');
    assert.equal(body.title, 'T');
    assert.equal(body.text, 'plain body');
  });

  it('飞书：无密钥时不带签名', async () => {
    const req = await CHANNELS.feishu.build({ webhook: 'https://open.feishu.cn/x' }, message, NOW);
    const body = JSON.parse(req.init.body);
    assert.equal(body.msg_type, 'text');
    assert.equal(body.sign, undefined);
    assert.match(body.content.text, /^T/);
  });

  it('飞书：有密钥时带 timestamp 与 sign', async () => {
    const req = await CHANNELS.feishu.build({ webhook: 'https://open.feishu.cn/x', secret: 'sec' }, message, NOW);
    const body = JSON.parse(req.init.body);
    assert.equal(body.timestamp, String(Math.floor(NOW / 1000)));
    assert.ok(body.sign && body.sign.length > 10);
  });

  it('钉钉：签名进 query 参数', async () => {
    const req = await CHANNELS.dingtalk.build(
      { accessToken: 'tok', secret: 'SECabc' },
      message,
      NOW
    );
    assert.match(req.url, /access_token=tok/);
    assert.match(req.url, /timestamp=/);
    assert.match(req.url, /sign=/);

    const body = JSON.parse(req.init.body);
    assert.equal(body.msgtype, 'markdown');
    assert.equal(body.markdown.text, '### md');
  });

  it('企业微信：key 进 query', async () => {
    const req = await CHANNELS.wecom.build({ key: 'k1' }, message, NOW);
    assert.match(req.url, /key=k1/);
    assert.equal(JSON.parse(req.init.body).msgtype, 'markdown');
  });

  it('Telegram：token 进路径，chat_id 进 body', async () => {
    const req = await CHANNELS.telegram.build({ token: '123:ABC', chatId: '-100200' }, message, NOW);
    assert.match(req.url, /bot123:ABC\/sendMessage/);
    assert.equal(JSON.parse(req.init.body).chat_id, '-100200');
  });

  it('Server 酱：表单编码', async () => {
    const req = await CHANNELS.serverchan.build({ sendKey: 'SCT123' }, message, NOW);
    assert.match(req.url, /SCT123\.send/);
    assert.match(req.init.headers['Content-Type'], /x-www-form-urlencoded/);
    assert.match(req.init.body, /title=T/);
  });

  it('PushPlus：markdown 模板', async () => {
    const req = await CHANNELS.pushplus.build({ token: 'p1' }, message, NOW);
    const body = JSON.parse(req.init.body);
    assert.equal(body.template, 'markdown');
    assert.equal(body.content, '### md');
  });

  it('Bark：支持自建服务器', async () => {
    const req = await CHANNELS.bark.build({ key: 'bk', server: 'https://bark.test/' }, message, NOW);
    assert.equal(req.url, 'https://bark.test/bk');
    assert.equal(JSON.parse(req.init.body).group, 'DSMC');
  });

  it('邮件：收件人按逗号拆开，带 Bearer', async () => {
    const req = await CHANNELS.email.build(
      { apiKey: 're_x', from: 'a@x.com', to: 'b@y.com, c@z.com' },
      message,
      NOW
    );
    assert.equal(req.init.headers.Authorization, 'Bearer re_x');
    const body = JSON.parse(req.init.body);
    assert.deepEqual(body.to, ['b@y.com', 'c@z.com']);
    assert.equal(body.html, '<b>x</b>');
  });

  it('每个渠道都声明了表单字段，UI 才能动态渲染', () => {
    const metas = channelMetas();
    assert.equal(metas.length, Object.keys(CHANNELS).length);
    for (const meta of metas) {
      assert.ok(meta.fields.length > 0, meta.key + ' 没有字段');
      for (const field of meta.fields) {
        assert.ok(field.name && field.label, meta.key + ' 字段定义不完整');
      }
    }
  });
});

/* ---------------- 响应判定 ---------------- */

describe('通知：响应判定', () => {
  it('HTTP 非 2xx 一律失败', () => {
    assert.equal(interpretResponse('webhook', 500, 'boom').ok, false);
  });

  it('飞书 code 0 成功，非 0 失败', () => {
    assert.equal(interpretResponse('feishu', 200, '{"code":0}').ok, true);
    const bad = interpretResponse('feishu', 200, '{"code":19001,"msg":"param invalid"}');
    assert.equal(bad.ok, false);
    assert.match(bad.error, /param invalid/);
  });

  it('钉钉 / 企业微信用 errcode', () => {
    assert.equal(interpretResponse('dingtalk', 200, '{"errcode":0}').ok, true);
    assert.equal(interpretResponse('dingtalk', 200, '{"errcode":310000,"errmsg":"sign not match"}').ok, false);
    assert.equal(interpretResponse('wecom', 200, '{"errcode":93000,"errmsg":"invalid key"}').ok, false);
  });

  it('Telegram 用 ok 字段', () => {
    assert.equal(interpretResponse('telegram', 200, '{"ok":true}').ok, true);
    assert.equal(interpretResponse('telegram', 200, '{"ok":false,"description":"chat not found"}').ok, false);
  });

  it('PushPlus / Bark 用 code 200', () => {
    assert.equal(interpretResponse('pushplus', 200, '{"code":200}').ok, true);
    assert.equal(interpretResponse('pushplus', 200, '{"code":500,"msg":"bad"}').ok, false);
    assert.equal(interpretResponse('bark', 200, '{"code":200}').ok, true);
  });

  it('纯文本 200 视为成功（自建 webhook 常见）', () => {
    assert.equal(interpretResponse('webhook', 200, 'ok').ok, true);
  });
});

/* ---------------- 发送 ---------------- */

describe('通知：发送', () => {
  it('成功时返回 ok', async () => {
    const service = new NotificationService({ fetchImpl: okFetch({ code: 0 }) });
    const result = await service.send(
      { type: 'feishu', config: { webhook: 'https://x' } },
      buildTestMessage(),
      NOW
    );
    assert.equal(result.ok, true);
  });

  it('网络异常收敛成 ok:false，不抛', async () => {
    const service = new NotificationService({
      fetchImpl: async () => { throw new Error('ECONNRESET'); }
    });
    const result = await service.send(
      { type: 'webhook', config: { url: 'https://x' } },
      buildTestMessage(),
      NOW
    );
    assert.equal(result.ok, false);
    assert.match(result.error, /ECONNRESET/);
  });

  it('不支持的渠道类型给出可读错误', async () => {
    const service = new NotificationService({ fetchImpl: okFetch() });
    const result = await service.send({ type: 'nope' }, buildTestMessage(), NOW);
    assert.equal(result.ok, false);
    assert.match(result.error, /不支持/);
  });

  it('broadcast 跳过停用的渠道', async () => {
    const impl = okFetch();
    const service = new NotificationService({ fetchImpl: impl });

    const results = await service.broadcast([
      { id: '1', type: 'webhook', config: { url: 'https://a' }, enabled: true },
      { id: '2', type: 'webhook', config: { url: 'https://b' }, enabled: false }
    ], buildTestMessage(), NOW);

    assert.equal(results.length, 1);
    assert.equal(impl.calls.length, 1);
  });
});

/* ---------------- 渠道配置校验 ---------------- */

describe('通知：渠道配置校验', () => {
  it('未知类型拒绝', () => {
    assert.throws(() => normalizeChannelConfig('nope', {}), /不支持/);
  });

  it('必填字段缺失拒绝', () => {
    assert.throws(() => normalizeChannelConfig('webhook', {}), /Webhook 地址/);
  });

  it('地址格式不对拒绝', () => {
    assert.throws(() => normalizeChannelConfig('webhook', { url: 'ftp://x' }), /http\(s\)/);
  });

  it('通过后返回规范化对象', () => {
    const out = normalizeChannelConfig('bark', { key: ' k1 ', server: 'https://api.day.app' });
    assert.equal(out.key, 'k1');
    assert.equal(out.server, 'https://api.day.app');
  });
});

/* ---------------- 配置与状态 ---------------- */

describe('通知：配置读写', () => {
  beforeEach(() => __resetConfigCache());

  it('未配置时返回默认值且未启用', async () => {
    const config = await loadNotifyConfig(fakeKV());
    assert.equal(config.enabled, false);
    assert.deepEqual(config.channels, []);
    assert.equal(config.rules.daysBefore, DEFAULT_NOTIFY.rules.daysBefore);
  });

  it('保存规则只动规则，不影响渠道', async () => {
    const kv = fakeKV();
    await saveNotifyConfig(kv, {
      enabled: true,
      rules: { daysBefore: 15 },
      channels: [{ id: 'ch_1', type: 'bark', config: { key: 'k' }, enabled: true }]
    });

    const next = await saveNotifyRules(kv, { daysBefore: 60, includeExpired: false });
    assert.equal(next.rules.daysBefore, 60);
    assert.equal(next.rules.includeExpired, false);
    assert.equal(next.channels.length, 1);
    assert.equal(next.enabled, true);
  });

  it('规则越界拒绝', async () => {
    await assert.rejects(() => saveNotifyRules(fakeKV(), { daysBefore: 9999 }), /1–365/);
  });

  it('渠道新增 / 切换 / 删除', async () => {
    const kv = fakeKV();
    const created = await upsertChannel(kv, {
      type: 'bark', label: '手机', config: { key: 'bk' }
    });
    assert.ok(created.id.startsWith('ch_'));

    assert.equal(await toggleChannel(kv, created.id), false);
    assert.equal(readJSON(kv, NOTIFY_KEY).channels[0].enabled, false);

    await removeChannel(kv, created.id);
    assert.deepEqual(readJSON(kv, NOTIFY_KEY).channels, []);
  });

  it('编辑时掩码值不会被当成真值写回', async () => {
    const kv = fakeKV();
    const created = await upsertChannel(kv, {
      type: 'feishu', config: { webhook: 'https://x', secret: 'real-secret' }
    });

    // 模拟前端把掩码回传
    await upsertChannel(kv, {
      type: 'feishu',
      config: { webhook: 'https://x', secret: 'real••••••••cret' }
    }, created.id);

    const stored = readJSON(kv, NOTIFY_KEY).channels[0];
    assert.equal(stored.config.secret, 'real-secret');
  });

  it('对外投影掩码凭证字段', () => {
    const pub = publicChannel({
      id: 'ch_1', type: 'telegram', label: 'TG',
      config: { token: '123456:ABCDEFGH', chatId: '100' }, enabled: true
    });

    assert.ok(pub.config.token.includes('••'));
    assert.equal(pub.config.chatId, '100');
    assert.equal(pub.ready, true);
  });

  it('缺字段时 ready 为 false', () => {
    const pub = publicChannel({ id: 'c', type: 'telegram', config: { token: 'x' } });
    assert.equal(pub.ready, false);
  });

  it('publicNotifyConfig 不含明文凭证', () => {
    const out = publicNotifyConfig({
      enabled: true,
      rules: {},
      channels: [{ id: 'c', type: 'serverchan', config: { sendKey: 'SCTsecret123' }, enabled: true }]
    });
    assert.ok(!JSON.stringify(out).includes('SCTsecret123'));
  });

  // 机器人地址把 token 写在路径里，原样回传等于把凭证送到前端
  it('飞书 webhook 地址也被掩码，不泄露 hook token', () => {
    const hook = 'https://open.feishu.cn/open-apis/bot/v2/hook/abcdef123456';
    const pub = publicChannel({ id: 'c', type: 'feishu', config: { webhook: hook }, enabled: true });

    assert.ok(!JSON.stringify(pub).includes('abcdef123456'));
    assert.ok(pub.config.webhook.includes('••'));
    // 平台与路径前缀保留，方便用户认出是哪个机器人
    assert.ok(pub.config.webhook.startsWith('https://open.feishu.cn/'));
    assert.equal(pub.ready, true);
  });

  it('通用 Webhook 的 url 同样被掩码', () => {
    const url = 'https://example.com/hook?sign=supersecret';
    const pub = publicChannel({ id: 'c', type: 'webhook', config: { url }, enabled: true });

    assert.ok(!JSON.stringify(pub).includes('supersecret'));
    assert.ok(pub.config.url.includes('••'));
  });

  it('webhook 掩码值回传时保留原值', async () => {
    const kv = fakeKV();
    const hook = 'https://open.feishu.cn/open-apis/bot/v2/hook/abcdef123456';
    const created = await upsertChannel(kv, { type: 'feishu', config: { webhook: hook } });

    const masked = publicChannel(readJSON(kv, NOTIFY_KEY).channels[0]).config.webhook;
    await upsertChannel(kv, { type: 'feishu', config: { webhook: masked } }, created.id);

    assert.equal(readJSON(kv, NOTIFY_KEY).channels[0].config.webhook, hook);
  });
});

/* ---------------- 编排：去重与发送 ---------------- */

describe('通知：定时推送编排', () => {
  beforeEach(() => __resetConfigCache());

  const channel = { id: 'ch_1', type: 'webhook', label: 'hook', config: { url: 'https://x' }, enabled: true };

  async function seed(kv) {
    await saveNotifyConfig(kv, {
      enabled: true,
      rules: { daysBefore: 30 },
      channels: [channel]
    });
  }

  it('未启用时跳过', async () => {
    const kv = fakeKV();
    const result = await runDigest({ kv, domains: DOMAINS, nowMs: NOW });
    assert.equal(result.skipped, true);
    assert.match(result.reason, /未启用/);
  });

  it('没有渠道时跳过', async () => {
    const kv = fakeKV();
    await saveNotifyConfig(kv, { enabled: true, rules: {}, channels: [] });
    const result = await runDigest({ kv, domains: DOMAINS, nowMs: NOW });
    assert.equal(result.skipped, true);
    assert.match(result.reason, /渠道/);
  });

  it('正常发送并写入状态', async () => {
    const kv = fakeKV();
    await seed(kv);

    const result = await runDigest({ kv, domains: DOMAINS, nowMs: NOW, fetchImpl: okFetch() });

    assert.equal(result.skipped, false);
    assert.equal(result.count, 3);
    assert.equal(result.sent, 1);
    assert.equal(result.failed, 0);

    const state = readJSON(kv, STATE_KEY);
    assert.equal(state.lastResult.length, 1);
    assert.equal(state.sentOn, '2026-10-21');
  });

  it('内容没变时第二次跳过', async () => {
    const kv = fakeKV();
    await seed(kv);
    await runDigest({ kv, domains: DOMAINS, nowMs: NOW, fetchImpl: okFetch() });

    const second = await runDigest({ kv, domains: DOMAINS, nowMs: NOW + 3600000, fetchImpl: okFetch() });
    assert.equal(second.skipped, true);
    assert.match(second.reason, /内容一致/);
  });

  it('内容变化后重新推送', async () => {
    const kv = fakeKV();
    await seed(kv);
    await runDigest({ kv, domains: DOMAINS, nowMs: NOW, fetchImpl: okFetch() });

    const changed = DOMAINS.concat([
      { name: 'new.com', account: 'main', expirationDate: '2026-10-23' }
    ]);
    const second = await runDigest({ kv, domains: changed, nowMs: NOW, fetchImpl: okFetch() });

    assert.equal(second.skipped, false);
    assert.equal(second.count, 4);
  });

  it('force 忽略去重', async () => {
    const kv = fakeKV();
    await seed(kv);
    await runDigest({ kv, domains: DOMAINS, nowMs: NOW, fetchImpl: okFetch() });

    const forced = await runDigest({ kv, domains: DOMAINS, nowMs: NOW, fetchImpl: okFetch(), force: true });
    assert.equal(forced.skipped, false);
  });

  it('没有待处理域名时不发送', async () => {
    const kv = fakeKV();
    await seed(kv);
    const result = await runDigest({
      kv,
      domains: [{ name: 'ok.com', expirationDate: '2027-12-31' }],
      nowMs: NOW,
      fetchImpl: okFetch()
    });
    assert.equal(result.skipped, true);
    assert.match(result.reason, /没有需要提醒/);
  });

  it('全部渠道失败时不更新指纹，下次还会重试', async () => {
    const kv = fakeKV();
    await seed(kv);

    const failing = async () => ({ ok: false, status: 500, text: async () => 'boom' });
    await runDigest({ kv, domains: DOMAINS, nowMs: NOW, fetchImpl: failing });

    const state = readJSON(kv, STATE_KEY);
    assert.equal(state.lastFingerprint, '');
  });

  it('指纹对域名集合敏感', () => {
    const a = fingerprintOf({ count: 1, groups: { expired: 0, week: 1, month: 0 }, names: ['a.com'] });
    const b = fingerprintOf({ count: 1, groups: { expired: 0, week: 1, month: 0 }, names: ['b.com'] });
    assert.notEqual(a, b);
  });

  it('KV 未绑定时安全跳过', async () => {
    const result = await runDigest({ kv: null, domains: DOMAINS });
    assert.equal(result.skipped, true);
  });
});

describe('通知：单渠道测试', () => {
  beforeEach(() => __resetConfigCache());

  it('发送测试消息并记录结果', async () => {
    const kv = fakeKV();
    const created = await upsertChannel(kv, {
      type: 'webhook', label: 'hook', config: { url: 'https://x' }
    });

    const result = await testChannel(kv, created.id, { fetchImpl: okFetch() });
    assert.equal(result.ok, true);

    const state = await loadNotifyState(kv);
    assert.equal(state.lastResult[0].test, true);
  });

  it('渠道不存在时报错', async () => {
    await assert.rejects(() => testChannel(fakeKV(), 'ch_x'), /不存在/);
  });
});
