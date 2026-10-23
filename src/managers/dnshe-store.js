// DNSHE 查询凭证的 KV 存储
//
// 为什么 DNSHE 单独一页，而不是塞进「设置」：
//
// 实测（2026-10）DNSHE v2 的**所有**端点都必须带 X-API-Key / X-API-Secret，
// 不带就是 401 auth_invalid_credentials，连官方文档标注为"公开"的 whois 端点也一样。
// 而这两类端点的权限范围并不相同：
//
//   endpoint=whois&domain=xxx     按域名查询，属于平台级公开数据 ——
//                                 任一把有效凭证都能查平台上任意 DNSHE 域名
//   endpoint=subdomains/dns_records/quota/keys
//                                 严格账户级 —— 只能看到、只能改自己账户下的东西
//
// 也就是说：**一把 Key 足够查全部 DNSHE 域名的 WHOIS**，但不同账户的 Key
// 配额、有效期、失效风险是独立的。所以这里按"可多条凭证 + 自动故障切换"设计：
// 只有一把时体验等同设置页里的一个字段；有多把时，前一把 401/403 会自动换下一把，
// 不会因为某个账户的 Key 过期就让所有 DNSHE 域名一起掉到兜底值。
//
// 数据结构：{ id, label, key, secret, enabled, createdAt, updatedAt }

import { readConfig, writeConfig, makeId, maskSecret } from './kv-config.js';

export const DNSHE_KEY = 'config:dnshe';

const MAX_CREDENTIALS = 20;

/** 校验并规范化 */
export function normalizeDnshePayload(data, options = {}) {
  const requireSecret = options.requireSecret !== false;
  const raw = data || {};

  const key = String(raw.key || '').trim();
  const secret = String(raw.secret || '').trim();

  if (!key) throw new Error('请填写 DNSHE API Key');
  if (!/^[A-Za-z0-9_-]{8,200}$/.test(key)) {
    throw new Error('API Key 格式异常（只允许字母、数字、下划线、连字符）');
  }

  if (!secret && requireSecret) throw new Error('请填写 DNSHE API Secret');
  if (secret && !/^[A-Za-z0-9_.-]{8,200}$/.test(secret)) {
    throw new Error('API Secret 格式异常');
  }

  return {
    label: String(raw.label || '').trim().slice(0, 40) || 'DNSHE',
    key,
    secret,
    enabled: raw.enabled !== false
  };
}

export function publicCredential(item) {
  if (!item) return null;
  return {
    id: item.id,
    label: item.label || 'DNSHE',
    keyMasked: maskSecret(item.key),
    secretMasked: maskSecret(item.secret, 4, 3),
    enabled: item.enabled !== false,
    createdAt: item.createdAt || null,
    updatedAt: item.updatedAt || null
  };
}

/** 读取全部凭证（含停用的，供管理页面展示） */
export async function loadDnsheCredentials(kv) {
  const stored = await readConfig(kv, DNSHE_KEY, null);
  if (!Array.isArray(stored)) return [];
  return stored.filter(item => item && item.key);
}

/** 只取启用中的，按创建顺序（先加的优先尝试） */
export async function enabledDnsheCredentials(kv) {
  const all = await loadDnsheCredentials(kv);
  return all.filter(item => item.enabled !== false);
}

export async function saveDnsheCredentials(kv, list) {
  return writeConfig(kv, DNSHE_KEY, (list || []).slice(0, MAX_CREDENTIALS));
}

export async function upsertDnsheCredential(kv, payload, id) {
  const list = await loadDnsheCredentials(kv);
  const now = new Date().toISOString();

  if (id) {
    const index = list.findIndex(item => item.id === id);
    if (index === -1) throw new Error('凭证不存在，可能已被删除');

    const patch = normalizeDnshePayload(payload, { requireSecret: false });
    const prev = list[index];
    list[index] = {
      ...prev,
      label: patch.label,
      key: patch.key,
      // secret 留空表示不修改
      secret: patch.secret || prev.secret,
      enabled: payload && payload.enabled !== undefined ? payload.enabled !== false : prev.enabled !== false,
      updatedAt: now
    };

    await saveDnsheCredentials(kv, list);
    return list[index];
  }

  if (list.length >= MAX_CREDENTIALS) {
    throw new Error('凭证数量已达上限（' + MAX_CREDENTIALS + ' 条）');
  }

  const entry = normalizeDnshePayload(payload, { requireSecret: true });
  if (list.some(item => item.key === entry.key)) {
    throw new Error('这条 API Key 已经添加过了');
  }

  const created = { ...entry, id: makeId('dnshe'), createdAt: now, updatedAt: now };
  list.push(created);
  await saveDnsheCredentials(kv, list);
  return created;
}

export async function removeDnsheCredential(kv, id) {
  const list = await loadDnsheCredentials(kv);
  const next = list.filter(item => item.id !== id);
  if (next.length === list.length) throw new Error('凭证不存在，可能已被删除');
  await saveDnsheCredentials(kv, next);
  return true;
}

export async function toggleDnsheCredential(kv, id) {
  const list = await loadDnsheCredentials(kv);
  const index = list.findIndex(item => item.id === id);
  if (index === -1) throw new Error('凭证不存在，可能已被删除');

  const nextEnabled = !(list[index].enabled !== false);
  list[index] = { ...list[index], enabled: nextEnabled, updatedAt: new Date().toISOString() };
  await saveDnsheCredentials(kv, list);
  return nextEnabled;
}
