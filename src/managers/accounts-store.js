// Cloudflare 账户的 KV 存储
//
// 这一层取代了原先「CF_API_KEYS / USERNAMES 两个平行数组 + 环境变量」的写法。
// 老写法有三个问题：
//   1. 两个数组靠下标对齐，少写一个用户名就整列错位；
//   2. 加一个账户必须重新部署；
//   3. 无法单独停用某个账户（只能从数组里删掉再部署）。
//
// 新数据结构：
//   { id, label, username, token, enabled, note, createdAt, updatedAt }
//
//   label    — 显示名，例如「主账户」「客户 A」，留空时回退到 username
//   username — 域名列表里的分组名，沿用原语义，避免改动 cloudflare.js
//   token    — Cloudflare API Token（Zone:Read 即可）
//
// 优先级：KV config:accounts > 环境变量 CF_API_KEYS/USERNAMES。
// 环境变量那条路保留，是为了让老部署在升级后仍能直接跑起来，
// 页面上会提示「当前使用环境变量配置」，点一下「导入」即可转为可编辑。

import { readConfig, writeConfig, mutateConfig, makeId, maskSecret } from './kv-config.js';

export const ACCOUNTS_KEY = 'config:accounts';

const MAX_ACCOUNTS = 50;
const TOKEN_MIN = 20;
const TOKEN_MAX = 200;

/** 从环境变量解析出的账户（source = 'env'） */
export function accountsFromEnv(env) {
  if (!env) return [];

  const parseList = (raw) => {
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      return [];
    }
  };

  const keys = parseList(env.CF_API_KEYS);
  const names = parseList(env.USERNAMES);

  return keys
    .map((token, index) => {
      const value = String(token || '').trim();
      if (!value) return null;
      return {
        id: 'env_' + index,
        label: String(names[index] || '').trim() || ('账户 ' + (index + 1)),
        username: String(names[index] || '').trim() || ('账户 ' + (index + 1)),
        token: value,
        enabled: true,
        note: '来自环境变量',
        source: 'env',
        createdAt: null,
        updatedAt: null
      };
    })
    .filter(Boolean);
}

/**
 * 校验并规范化前端提交的账户。
 * token 只在新增时必填；编辑时留空表示"不修改"，避免每次改备注都要重贴一遍密钥。
 */
export function normalizeAccountPayload(data, options = {}) {
  const requireToken = options.requireToken !== false;
  const raw = data || {};

  const username = String(raw.username || '').trim();
  if (!username) throw new Error('请填写账户名称（用于域名分组显示）');
  if (username.length > 64) throw new Error('账户名称过长（最多 64 字符）');

  const label = String(raw.label || '').trim().slice(0, 40) || username;
  const note = String(raw.note || '').trim().slice(0, 200);

  const token = String(raw.token || '').trim();
  if (!token && requireToken) throw new Error('请填写 Cloudflare API Token');
  if (token) {
    if (/\s/.test(token)) throw new Error('API Token 不能包含空格或换行');
    if (token.length < TOKEN_MIN || token.length > TOKEN_MAX) {
      throw new Error('API Token 长度异常（应在 ' + TOKEN_MIN + '–' + TOKEN_MAX + ' 字符之间）');
    }
  }

  const entry = { label, username, note };
  if (token) entry.token = token;
  if (raw.enabled !== undefined) entry.enabled = raw.enabled !== false;
  return entry;
}

/** 去掉敏感字段，供接口返回 */
export function publicAccount(account) {
  if (!account) return null;
  return {
    id: account.id,
    label: account.label || account.username,
    username: account.username,
    tokenMasked: maskSecret(account.token),
    enabled: account.enabled !== false,
    note: account.note || '',
    source: account.source || 'kv',
    createdAt: account.createdAt || null,
    updatedAt: account.updatedAt || null
  };
}

/**
 * 读取生效的账户列表。
 * KV 有数据就用 KV，否则退回环境变量——这样老部署不会因为没配 KV 而白屏。
 * @returns {Promise<{accounts: Array, source: 'kv'|'env'|'none'}>}
 */
export async function resolveAccounts(kv, env) {
  const stored = await readConfig(kv, ACCOUNTS_KEY, null);

  if (Array.isArray(stored) && stored.length) {
    return {
      accounts: stored.map(item => ({ ...item, source: 'kv' })),
      source: 'kv'
    };
  }

  const fromEnv = accountsFromEnv(env);
  return { accounts: fromEnv, source: fromEnv.length ? 'env' : 'none' };
}

/** 覆盖写入（内部用，调用方应先 resolveAccounts 拿到完整数组） */
export async function saveAccounts(kv, accounts) {
  const list = (accounts || []).slice(0, MAX_ACCOUNTS);
  return writeConfig(kv, ACCOUNTS_KEY, list);
}

/**
 * 新增或更新。
 * @param {KVNamespace} kv
 * @param {object} payload 前端提交
 * @param {string} [id] 有 id 表示更新，没有表示新增
 */
export async function upsertAccount(kv, payload, id) {
  const existing = await readConfig(kv, ACCOUNTS_KEY, null);
  const list = Array.isArray(existing) ? existing.slice() : [];

  const now = new Date().toISOString();

  if (id) {
    const index = list.findIndex(item => item && item.id === id);
    if (index === -1) throw new Error('账户不存在，可能已被删除');

    const patch = normalizeAccountPayload(payload, { requireToken: false });
    const prev = list[index];
    list[index] = {
      ...prev,
      ...patch,
      // token 留空表示不修改，保留原值
      token: patch.token || prev.token,
      enabled: payload && payload.enabled !== undefined ? payload.enabled !== false : prev.enabled !== false,
      id: prev.id,
      createdAt: prev.createdAt || now,
      updatedAt: now
    };

    await saveAccounts(kv, list);
    return list[index];
  }

  if (list.length >= MAX_ACCOUNTS) {
    throw new Error('账户数量已达上限（' + MAX_ACCOUNTS + ' 个）');
  }

  const entry = normalizeAccountPayload(payload, { requireToken: true });

  // 同名账户会让域名列表出现两个无法区分的小组，直接拒绝
  if (list.some(item => String(item.username || '').toLowerCase() === entry.username.toLowerCase())) {
    throw new Error('已存在同名账户：' + entry.username);
  }

  const created = {
    ...entry,
    id: makeId('acct'),
    enabled: entry.enabled !== false,
    source: 'kv',
    createdAt: now,
    updatedAt: now
  };

  list.push(created);
  await saveAccounts(kv, list);
  return created;
}

/** 删除 */
export async function removeAccount(kv, id) {
  const list = await readConfig(kv, ACCOUNTS_KEY, null);
  const source = Array.isArray(list) ? list : [];

  const next = source.filter(item => item && item.id !== id);
  if (next.length === source.length) throw new Error('账户不存在，可能已被删除');

  await saveAccounts(kv, next);
  return true;
}

/** 启用 / 停用 */
export async function toggleAccount(kv, id) {
  const list = await readConfig(kv, ACCOUNTS_KEY, null);
  const source = Array.isArray(list) ? list.slice() : [];

  const index = source.findIndex(item => item && item.id === id);
  if (index === -1) throw new Error('账户不存在，可能已被删除');

  const nextEnabled = !(source[index].enabled !== false);
  source[index] = {
    ...source[index],
    enabled: nextEnabled,
    updatedAt: new Date().toISOString()
  };

  await saveAccounts(kv, source);
  return nextEnabled;
}

/**
 * 把环境变量里的账户导入 KV，之后就可以在页面上编辑了。
 * 已存在同 token 的条目会被跳过，避免点两次出现两遍。
 */
export async function importAccountsFromEnv(kv, env) {
  const fromEnv = accountsFromEnv(env);
  if (!fromEnv.length) throw new Error('环境变量里没有可导入的账户（CF_API_KEYS 为空）');

  const existing = await readConfig(kv, ACCOUNTS_KEY, null);
  const list = Array.isArray(existing) ? existing.slice() : [];
  const tokens = new Set(list.map(item => item && item.token));

  let added = 0;
  for (const account of fromEnv) {
    if (tokens.has(account.token)) continue;
    list.push({
      id: makeId('acct'),
      label: account.label,
      username: account.username,
      token: account.token,
      enabled: true,
      note: '从环境变量导入',
      source: 'kv',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });
    added++;
  }

  if (added) await saveAccounts(kv, list);
  return { added, total: list.length };
}

/** 测试用：直接改一条（模拟并发写） */
export async function patchAccount(kv, id, patch) {
  return mutateConfig(kv, ACCOUNTS_KEY, [], list => {
    const source = Array.isArray(list) ? list.slice() : [];
    const index = source.findIndex(item => item && item.id === id);
    if (index !== -1) source[index] = { ...source[index], ...patch };
    return source;
  });
}
