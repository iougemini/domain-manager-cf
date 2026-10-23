// 运行设置的 KV 存储
//
// 原先这些东西只能通过 wrangler secret / vars 配置，改一次要重新部署。
// 现在搬到 KV，页面上直接改，60 秒内全节点生效。
//
// 密码的处理方式与之前不同：环境变量里是明文，KV 里存的是 **加盐 SHA-256**。
// 理由很直接——设置页要展示"密码是否已设置"，如果存明文，任何一次误操作
// （比如接口把整个 settings 对象返回给前端）就等于把密码泄出去了。
// 存哈希之后接口只返回 hasPassword: true/false，前端永远拿不到原文。
//
// 兼容策略：KV 里没有密码就用环境变量里的明文，老部署升级后不会突然锁死。

import { readConfig, writeConfig } from './kv-config.js';
import { appState } from '../app-state.js';
import { CONFIG } from '../config.js';
import { secureCompare } from '../auth.js';

export const SETTINGS_KEY = 'config:settings';

export const DEFAULT_SETTINGS = {
  // 密码记录形如 { hash, salt }，null 表示未设置（回退环境变量）
  accessPassword: null,
  adminPassword: null,
  tokenSecret: '',
  sessionHours: 24,
  whoisProxy: '',
  freeDomainLiveLookup: true,
  freeDomainLookupTimeout: 8000,
  freeDomainLookupUa: '',
  paceDnshe: 2000,
  paceWhois: 1200,
  paceRdap: 300
};

const LIMITS = {
  sessionHours: [1, 720],
  freeDomainLookupTimeout: [1000, 30000],
  paceDnshe: [0, 10000],
  paceWhois: [0, 10000],
  paceRdap: [0, 5000]
};

const PASSWORD_MIN = 6;
const PASSWORD_MAX = 128;

/* ---------------- 密码哈希 ---------------- */

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function randomSalt() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * PBKDF2-HMAC-SHA256。
 *
 * 为什么不用循环 digest：纯 JS 里跑 1000 次 SHA-256 会吃掉 Workers 免费额度
 * 的 CPU 时间（单请求 10ms 上限），而 PBKDF2 是原生实现，同样强度下快一个量级。
 * 迭代次数写进记录里，将来调高不会让老密码失效。
 */
const PBKDF2_ITERATIONS = 30000;

export async function hashPassword(password, salt, iterations = PBKDF2_ITERATIONS) {
  const encoder = new TextEncoder();
  const material = await crypto.subtle.importKey(
    'raw',
    encoder.encode(String(password)),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: encoder.encode(String(salt)),
      iterations,
      hash: 'SHA-256'
    },
    material,
    256
  );

  return toHex(bits);
}

/** 生成可直接入库的密码记录 */
export async function makePasswordRecord(password) {
  const text = String(password || '');
  if (text.length < PASSWORD_MIN) throw new Error('密码至少 ' + PASSWORD_MIN + ' 位');
  if (text.length > PASSWORD_MAX) throw new Error('密码最长 ' + PASSWORD_MAX + ' 位');

  const salt = randomSalt();
  const hash = await hashPassword(text, salt);
  return { hash, salt, iterations: PBKDF2_ITERATIONS };
}

/** 校验密码记录；记录为空时返回 false（调用方回退明文比对） */
export async function verifyPasswordRecord(record, input) {
  if (!record || !record.hash || !record.salt) return false;
  if (!input) return false;
  const hash = await hashPassword(String(input), record.salt, record.iterations || PBKDF2_ITERATIONS);
  return secureCompare(hash, record.hash);
}

/** 统一的密码校验入口：先看 KV 哈希，再回退环境变量明文 */
export async function verifyAccessPassword(input) {
  if (appState.ACCESS_PASSWORD_HASH) {
    return verifyPasswordRecord(appState.ACCESS_PASSWORD_HASH, input);
  }
  const expected = appState.ACCESS_PASSWORD;
  if (!expected) return false;
  return secureCompare(input, expected);
}

export async function verifyAdminPassword(input) {
  if (appState.ADMIN_PASSWORD_HASH) {
    return verifyPasswordRecord(appState.ADMIN_PASSWORD_HASH, input);
  }
  const expected = appState.ADMIN_PASSWORD;
  if (!expected) return false;
  return secureCompare(input, expected);
}

/* ---------------- 读写 ---------------- */

/**
 * 读取设置，同时告诉调用方「哪些字段是 KV 里明确写过的」。
 *
 * 这个区分很重要：默认值里 freeDomainLiveLookup 是 true，如果只看合并后的值，
 * 就无法判断"用户明确设成 true"和"根本没配"，环境变量里的 false 会被默认值吃掉。
 * applySettings 需要它来决定每个字段到底听谁的。
 */
export async function loadSettingsWithMeta(kv) {
  const stored = await readConfig(kv, SETTINGS_KEY, null);
  const settings = { ...DEFAULT_SETTINGS };
  const explicit = new Set();

  if (stored && typeof stored === 'object') {
    for (const key of Object.keys(DEFAULT_SETTINGS)) {
      if (stored[key] !== undefined && stored[key] !== null) {
        settings[key] = stored[key];
        explicit.add(key);
      }
    }
    // 密码记录为 null 也算"明确清空"，但我们的语义是 null = 回退环境变量，
    // 所以这里不把它计入 explicit
  }

  return { settings, explicit };
}

/** 读取设置（已与默认值合并，缺失字段不会变成 undefined） */
export async function loadSettings(kv) {
  return (await loadSettingsWithMeta(kv)).settings;
}

/**
 * 校验前端提交的补丁。
 * 密码字段不在这里处理（要异步哈希），由调用方单独调用 makePasswordRecord。
 * 空字符串表示"不修改"，因此不会出现在返回值里。
 */
export function normalizeSettingsPatch(data) {
  const raw = data || {};
  const patch = {};

  if (raw.whoisProxy !== undefined) {
    const value = String(raw.whoisProxy || '').trim();
    if (value && !/^https?:\/\/[^\s]+$/i.test(value)) {
      throw new Error('WHOIS 代理必须是 http(s) 开头的完整地址');
    }
    patch.whoisProxy = value.replace(/\/+$/, '');
  }

  if (raw.freeDomainLookupUa !== undefined) {
    patch.freeDomainLookupUa = String(raw.freeDomainLookupUa || '').trim().slice(0, 200);
  }

  if (raw.freeDomainLiveLookup !== undefined) {
    patch.freeDomainLiveLookup = raw.freeDomainLiveLookup !== false
      && raw.freeDomainLiveLookup !== 'false';
  }

  for (const [field, [min, max]] of Object.entries(LIMITS)) {
    if (raw[field] === undefined || raw[field] === '') continue;
    const value = Number(raw[field]);
    if (!Number.isFinite(value)) throw new Error(field + ' 必须是数字');
    if (value < min || value > max) throw new Error(field + ' 应在 ' + min + '–' + max + ' 之间');
    patch[field] = Math.round(value);
  }

  if (raw.tokenSecret !== undefined) {
    const value = String(raw.tokenSecret || '').trim();
    if (value && value.length < 16) throw new Error('Token 签名密钥至少 16 位');
    patch.tokenSecret = value.slice(0, 128);
  }

  return patch;
}

/** 合并写入 */
export async function saveSettings(kv, patch) {
  const current = await loadSettings(kv);
  const next = { ...current, ...(patch || {}) };
  await writeConfig(kv, SETTINGS_KEY, next);
  return next;
}

/**
 * 对外投影：把密码记录换成布尔标记。
 * 任何返回给前端的设置都必须走这里，避免哈希（以及未来的其它敏感字段）泄露。
 */
export function publicSettings(settings, env) {
  const s = settings || DEFAULT_SETTINGS;
  const envAccess = Boolean(env && env.ACCESS_PASSWORD);
  const envAdmin = Boolean(env && env.ADMIN_PASSWORD);

  return {
    accessPasswordSet: Boolean(s.accessPassword) || envAccess,
    accessPasswordSource: s.accessPassword ? 'kv' : (envAccess ? 'env' : 'none'),
    adminPasswordSet: Boolean(s.adminPassword) || envAdmin,
    adminPasswordSource: s.adminPassword ? 'kv' : (envAdmin ? 'env' : 'none'),
    tokenSecretSet: Boolean(s.tokenSecret) || Boolean(env && env.TOKEN_SECRET),
    sessionHours: s.sessionHours,
    whoisProxy: s.whoisProxy || '',
    whoisProxySource: s.whoisProxy ? 'kv' : (env && env.WHOIS_PROXY ? 'env' : 'none'),
    freeDomainLiveLookup: s.freeDomainLiveLookup !== false,
    freeDomainLookupTimeout: s.freeDomainLookupTimeout,
    freeDomainLookupUa: s.freeDomainLookupUa || '',
    paceDnshe: s.paceDnshe,
    paceWhois: s.paceWhois,
    paceRdap: s.paceRdap
  };
}

/**
 * 把设置灌进运行时。
 * 优先级：KV 明确写过的字段 > 环境变量 > 代码默认值。
 * 用 explicit 集合而不是"值是否为空"来判断，是因为默认值本身也可能是有效值
 * （比如 freeDomainLiveLookup 默认 true）。
 *
 * @param {object} settings
 * @param {object} env
 * @param {Set<string>} [explicit] KV 里明确设置过的字段名
 */
export function applySettings(settings, env, explicit) {
  const s = settings || DEFAULT_SETTINGS;
  const known = explicit instanceof Set ? explicit : new Set();

  const asBool = v => !(v === false || v === 'false' || v === '0' || v === 'off' || v === 'no');
  const asNum = (v, fallback) => {
    const n = Number(v);
    return Number.isFinite(n) ? n : fallback;
  };

  const pick = (field, envValue, coerce) => {
    if (known.has(field)) return coerce(s[field]);
    if (envValue !== undefined && envValue !== null && envValue !== '') return coerce(envValue);
    return coerce(s[field]);
  };

  // 密码：KV 有哈希就不再用明文
  appState.ACCESS_PASSWORD_HASH = s.accessPassword || null;
  appState.ADMIN_PASSWORD_HASH = s.adminPassword || null;
  appState.ACCESS_PASSWORD = s.accessPassword ? '' : ((env && env.ACCESS_PASSWORD) || '');
  appState.ADMIN_PASSWORD = s.adminPassword ? '' : ((env && env.ADMIN_PASSWORD) || '');

  // token 签名密钥：显式配置 > 环境变量 > 由密码哈希派生
  // 派生是为了避免"配了 KV 密码但没配 TOKEN_SECRET"时签名密钥变成空串
  let secret = s.tokenSecret || (env && env.TOKEN_SECRET) || '';
  if (!secret && appState.ACCESS_PASSWORD_HASH) {
    secret = 'dsmc:' + String(appState.ACCESS_PASSWORD_HASH.hash).slice(0, 32);
  }
  if (!secret && appState.ADMIN_PASSWORD_HASH) {
    secret = 'dsmc:' + String(appState.ADMIN_PASSWORD_HASH.hash).slice(0, 32);
  }
  appState.TOKEN_SECRET = secret;

  appState.SESSION_HOURS = pick('sessionHours', env && env.SESSION_HOURS, v => asNum(v, 24));

  CONFIG.WHOIS_PROXY = pick('whoisProxy', env && env.WHOIS_PROXY, v => String(v || '').trim().replace(/\/+$/, ''));
  CONFIG.FREE_DOMAIN_LIVE_LOOKUP = pick('freeDomainLiveLookup', env && env.FREE_DOMAIN_LIVE_LOOKUP, asBool);
  CONFIG.FREE_DOMAIN_LOOKUP_TIMEOUT = pick('freeDomainLookupTimeout', env && env.FREE_DOMAIN_LOOKUP_TIMEOUT, v => asNum(v, 8000));
  CONFIG.FREE_DOMAIN_LOOKUP_UA = pick('freeDomainLookupUa', env && env.FREE_DOMAIN_LOOKUP_UA, v => String(v || '').trim());
  CONFIG.PACE_DNSHE = pick('paceDnshe', env && env.PACE_DNSHE, v => asNum(v, 2000));
  CONFIG.PACE_WHOIS = pick('paceWhois', env && env.PACE_WHOIS, v => asNum(v, 1200));
  CONFIG.PACE_RDAP = pick('paceRdap', env && env.PACE_RDAP, v => asNum(v, 300));
}
