// 通知配置与发送状态
//
// 配置：config:notify
//   { enabled, rules: { daysBefore, includeExpired, timezoneOffset },
//     channels: [{ id, type, label, config, enabled, createdAt }] }
//
// 状态：notify:state
//   { lastRunAt, lastFingerprint, lastResult: [...], sentOn }
//
// 为什么要状态：cron 每天跑一次，如果内容没变还天天推同样的清单，用户很快就
// 会把这个机器人静音。所以内容指纹（域名集合 + 紧急度分布）相同就跳过，
// 除非用户手动点了「立即发送」。

import { readConfig, writeConfig, makeId, maskSecret } from './kv-config.js';
import {
  CHANNELS,
  normalizeChannelConfig,
  buildExpiryDigest,
  buildHealthDigest,
  buildTestMessage,
  NotificationService
} from '../services/notify.js';

export const NOTIFY_KEY = 'config:notify';
export const STATE_KEY = 'notify:state';

const MAX_CHANNELS = 20;

/**
 * 这些字段属于凭证，读接口一律掩码返回。
 *
 * `url` / `webhook` 也在内：飞书、钉钉、企业微信的机器人地址把 token 写在路径里
 * （.../hook/xxxxxxxx），通用 Webhook 也常在 query 里带签名。如果原样回传前端，
 * 掩码就形同虚设——任何人打开 DevTools 或截个图就把凭证拿走了。
 */
const SECRET_FIELDS = new Set([
  'secret', 'token', 'apiKey', 'sendKey', 'key', 'accessToken', 'webhook', 'url'
]);

export const DEFAULT_NOTIFY = {
  enabled: false,
  rules: {
    daysBefore: 30,
    includeExpired: true,
    timezoneOffset: 8
  },
  channels: []
};

/* ---------------- 配置读写 ---------------- */

export async function loadNotifyConfig(kv) {
  const stored = await readConfig(kv, NOTIFY_KEY, null);
  if (!stored || typeof stored !== 'object') {
    return { ...DEFAULT_NOTIFY, rules: { ...DEFAULT_NOTIFY.rules }, channels: [] };
  }

  return {
    enabled: stored.enabled === true,
    rules: { ...DEFAULT_NOTIFY.rules, ...(stored.rules || {}) },
    channels: Array.isArray(stored.channels) ? stored.channels.filter(c => c && c.type) : []
  };
}

export async function saveNotifyConfig(kv, config) {
  const next = {
    enabled: config.enabled === true,
    rules: { ...DEFAULT_NOTIFY.rules, ...(config.rules || {}) },
    channels: Array.isArray(config.channels) ? config.channels.slice(0, MAX_CHANNELS) : []
  };
  await writeConfig(kv, NOTIFY_KEY, next);
  return next;
}

/** 对外投影：凭证字段掩码，并标注是否已配置完整 */
export function publicChannel(channel) {
  if (!channel) return null;
  const def = CHANNELS[channel.type];
  const config = {};

  for (const [key, value] of Object.entries(channel.config || {})) {
    config[key] = SECRET_FIELDS.has(key) ? maskSecret(value) : value;
  }

  return {
    id: channel.id,
    type: channel.type,
    typeLabel: def ? def.label : channel.type,
    label: channel.label || (def ? def.label : channel.type),
    enabled: channel.enabled !== false,
    config,
    // 必填字段是否都有值（掩码值也算有）
    ready: Boolean(def) && def.fields.every(f => !f.required || config[f.name]),
    createdAt: channel.createdAt || null,
    updatedAt: channel.updatedAt || null
  };
}

export function publicNotifyConfig(config) {
  const c = config || DEFAULT_NOTIFY;
  return {
    enabled: c.enabled === true,
    rules: { ...DEFAULT_NOTIFY.rules, ...(c.rules || {}) },
    channels: (c.channels || []).map(publicChannel)
  };
}

/* ---------------- 渠道增删改 ---------------- */

export function normalizeChannelPayload(data, existing) {
  const type = String((data && data.type) || '').trim();
  if (!CHANNELS[type]) throw new Error('不支持的通知渠道：' + (type || '(空)'));

  const label = String((data && data.label) || '').trim().slice(0, 40) || CHANNELS[type].label;

  // 编辑时前端拿到的是掩码值，留空或与掩码相同都表示"保持原值"
  const incoming = { ...((data && data.config) || {}) };
  const previous = (existing && existing.config) || {};
  for (const field of SECRET_FIELDS) {
    const value = incoming[field];
    if (!value || (typeof value === 'string' && value.includes('••'))) {
      if (previous[field]) incoming[field] = previous[field];
    }
  }

  const config = normalizeChannelConfig(type, incoming);

  return {
    type,
    label,
    config,
    enabled: data && data.enabled !== undefined ? data.enabled !== false : true
  };
}

export async function upsertChannel(kv, payload, id) {
  const current = await loadNotifyConfig(kv);
  const list = current.channels.slice();
  const now = new Date().toISOString();

  if (id) {
    const index = list.findIndex(item => item.id === id);
    if (index === -1) throw new Error('通知渠道不存在，可能已被删除');

    const patch = normalizeChannelPayload(payload, list[index]);
    list[index] = {
      ...list[index],
      ...patch,
      id: list[index].id,
      createdAt: list[index].createdAt || now,
      updatedAt: now
    };
    await saveNotifyConfig(kv, { ...current, channels: list });
    return list[index];
  }

  if (list.length >= MAX_CHANNELS) throw new Error('通知渠道已达上限（' + MAX_CHANNELS + ' 个）');

  const entry = normalizeChannelPayload(payload, null);
  const created = { ...entry, id: makeId('ch'), createdAt: now, updatedAt: now };
  list.push(created);
  await saveNotifyConfig(kv, { ...current, channels: list });
  return created;
}

export async function removeChannel(kv, id) {
  const current = await loadNotifyConfig(kv);
  const next = current.channels.filter(item => item.id !== id);
  if (next.length === current.channels.length) throw new Error('通知渠道不存在，可能已被删除');
  await saveNotifyConfig(kv, { ...current, channels: next });
  return true;
}

export async function toggleChannel(kv, id) {
  const current = await loadNotifyConfig(kv);
  const index = current.channels.findIndex(item => item.id === id);
  if (index === -1) throw new Error('通知渠道不存在，可能已被删除');

  const list = current.channels.slice();
  const nextEnabled = !(list[index].enabled !== false);
  list[index] = { ...list[index], enabled: nextEnabled, updatedAt: new Date().toISOString() };
  await saveNotifyConfig(kv, { ...current, channels: list });
  return nextEnabled;
}

/** 只改开关与规则，不动渠道列表 */
export async function saveNotifyRules(kv, patch) {
  const current = await loadNotifyConfig(kv);

  const rules = { ...current.rules };
  if (patch && patch.daysBefore !== undefined && patch.daysBefore !== '') {
    const value = Number(patch.daysBefore);
    if (!Number.isFinite(value) || value < 1 || value > 365) throw new Error('提前天数应在 1–365 之间');
    rules.daysBefore = Math.round(value);
  }
  if (patch && patch.includeExpired !== undefined) {
    rules.includeExpired = patch.includeExpired !== false && patch.includeExpired !== 'false';
  }
  if (patch && patch.timezoneOffset !== undefined && patch.timezoneOffset !== '') {
    const value = Number(patch.timezoneOffset);
    if (!Number.isFinite(value) || value < -12 || value > 14) throw new Error('时区偏移应在 -12 – +14 之间');
    rules.timezoneOffset = value;
  }

  const enabled = patch && patch.enabled !== undefined
    ? (patch.enabled !== false && patch.enabled !== 'false')
    : current.enabled;

  return saveNotifyConfig(kv, { ...current, enabled, rules });
}

/* ---------------- 发送状态 ---------------- */

export async function loadNotifyState(kv) {
  const stored = await readConfig(kv, STATE_KEY, null);
  if (!stored || typeof stored !== 'object') {
    return { lastRunAt: null, lastFingerprint: '', lastResult: [], sentOn: null };
  }
  return {
    lastRunAt: stored.lastRunAt || null,
    lastFingerprint: stored.lastFingerprint || '',
    lastResult: Array.isArray(stored.lastResult) ? stored.lastResult : [],
    sentOn: stored.sentOn || null
  };
}

export async function saveNotifyState(kv, state) {
  return writeConfig(kv, STATE_KEY, state);
}

/** 内容指纹：域名集合 + 紧急度分布，任何一项变化都算"有新情况" */
export function fingerprintOf(digest) {
  if (!digest) return '';
  const names = (digest.names || []).slice().sort().join(',');
  // 按 key 排序取全部计数，不写死 expired/week/month —— 健康告警的分组是
  // suspended/other，写死的话它的指纹会退化成 "undefined/undefined/undefined"
  const groupSig = digest.groups
    ? Object.keys(digest.groups).sort().map(k => k + ':' + digest.groups[k]).join('/')
    : '';
  return [digest.count, groupSig, names].join('|');
}

/**
 * 执行一次到期检查并推送。
 *
 * 到期摘要与健康告警是两条独立消息，各自去重：
 * 到期摘要"内容没变就别重复发"，健康告警"同一批异常别重复发"。
 * 合成一条会让两类信息的去重条件互相干扰 —— 到期列表没变就把新出现的
 * clientHold 一起跳过了。
 *
 * @param {object} options
 * @param {KVNamespace} options.kv
 * @param {Array} options.domains 原始域名记录
 * @param {Array} [options.healthAlerts] 巡检发现的异常（managers/health-store.js）
 * @param {boolean} [options.force] 忽略去重（手动"立即发送"）
 * @param {number} [options.nowMs]
 * @param {Function} [options.fetchImpl]
 * @returns {Promise<object>}
 */
export async function runDigest(options) {
  const { kv, domains, healthAlerts, force } = options || {};
  const nowMs = options && options.nowMs ? options.nowMs : Date.now();

  if (!kv) return { skipped: true, reason: 'KV 未绑定' };

  const config = await loadNotifyConfig(kv);
  if (!config.enabled && !force) return { skipped: true, reason: '通知未启用' };

  const channels = config.channels.filter(c => c && c.enabled !== false);
  if (!channels.length) return { skipped: true, reason: '没有启用的通知渠道' };

  const digest = buildExpiryDigest(domains, config.rules, nowMs);
  const alerts = Array.isArray(healthAlerts) ? healthAlerts.filter(a => a && a.name) : [];
  const healthDigest = alerts.length ? buildHealthDigest(alerts, nowMs) : null;

  if (!digest.count && !healthDigest && !force) {
    return { skipped: true, reason: '没有需要提醒的域名', count: 0 };
  }

  const state = await loadNotifyState(kv);
  const service = new NotificationService({ fetchImpl: options.fetchImpl });

  const sentResults = [];
  let sentFingerprint = state.lastFingerprint;
  let healthFingerprint = state.lastHealthFingerprint;

  // ── 到期摘要 ──────────────────────────────────────────
  const expiryFp = fingerprintOf(digest);
  const expiryDue = Boolean(digest.count) && (force || expiryFp !== state.lastFingerprint);
  if (expiryDue) {
    const results = await service.broadcast(channels, digest, nowMs);
    sentResults.push(...results);
    if (results.some(r => r.ok)) sentFingerprint = expiryFp;
  }

  // ── 健康告警 ──────────────────────────────────────────
  const healthFp = healthDigest ? fingerprintOf(healthDigest) : '';
  const healthDue = Boolean(healthDigest) && (force || healthFp !== state.lastHealthFingerprint);
  if (healthDue) {
    const results = await service.broadcast(channels, healthDigest, nowMs);
    sentResults.push(...results);
    if (results.some(r => r.ok)) healthFingerprint = healthFp;
  }

  if (!expiryDue && !healthDue && !force) {
    return {
      skipped: true,
      reason: '与上次推送内容一致，已跳过',
      count: digest.count,
      healthCount: alerts.length
    };
  }

  const okCount = sentResults.filter(r => r.ok).length;
  await saveNotifyState(kv, {
    lastRunAt: new Date(nowMs).toISOString(),
    lastFingerprint: sentFingerprint,
    lastHealthFingerprint: healthFingerprint,
    lastResult: sentResults,
    sentOn: new Date(nowMs).toISOString().slice(0, 10)
  });

  return {
    skipped: false,
    count: digest.count,
    healthCount: alerts.length,
    title: digest.title,
    healthTitle: healthDigest ? healthDigest.title : null,
    sent: okCount,
    failed: sentResults.length - okCount,
    results: sentResults
  };
}

/** 单渠道测试发送 */
export async function testChannel(kv, id, options = {}) {
  const config = await loadNotifyConfig(kv);
  const channel = config.channels.find(c => c.id === id);
  if (!channel) throw new Error('通知渠道不存在，可能已被删除');

  const service = new NotificationService({ fetchImpl: options.fetchImpl });
  const result = await service.send(channel, buildTestMessage());

  // 测试结果也记进状态，页面刷新后还能看到
  const state = await loadNotifyState(kv);
  await saveNotifyState(kv, {
    ...state,
    lastRunAt: new Date().toISOString(),
    lastResult: [{
      id: channel.id,
      type: channel.type,
      label: channel.label,
      ok: result.ok,
      error: result.error || null,
      test: true
    }]
  });

  return { ok: result.ok, error: result.error || null };
}
