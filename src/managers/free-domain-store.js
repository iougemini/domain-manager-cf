// 免费域名白名单的 KV 动态配置
//
// 目标：改白名单不用改代码、不用重新部署。配置存在 KV 的 config:free-domains，
// 管理页面的增删改都写这里；读路径用 60 秒内存缓存，避免每个请求都打 KV。
//
// 为什么要有内存缓存：initManagers() 每个请求都会重建 FreeDomainManager，
// 如果每次都读 KV，页面刷新一次就多一次 KV 读（Workers 的 KV 读虽然便宜，
// 但延迟是实打实的）。60 秒的代价是"改完最多 1 分钟生效"，对白名单完全够用。
//
// 数据结构：JSON 数组，元素形如
//   { "suffix": "is-a.dev", "registrar": "is-a.dev", "renew": "permanent" }
//   { "suffix": "eu.org", "disabled": true }   ← 禁用内置条目
//
// 注意：这个 Map 是模块级的，作用域是单个 isolate。多 isolate 之间最多各自
// 缓存 60 秒，不会出现长时间不一致。

export const CONFIG_KEY = 'config:free-domains';
export const MEM_TTL = 60000;

/** @type {{at: number, entries: Array|null}} */
let cache = { at: 0, entries: null };

/** 清掉内存缓存（写入后调用，让本 isolate 立即生效） */
export function invalidateFreeDomainConfig() {
  cache = { at: 0, entries: null };
}

/** 测试用：完全重置模块状态 */
export function __resetFreeDomainConfig() {
  invalidateFreeDomainConfig();
}

function parse(raw) {
  if (!raw) return [];
  try {
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch (e) {
    return [];
  }
}

/**
 * 读取 KV 里的覆盖配置。
 * KV 未绑定或读失败时返回上一次成功的结果（或空数组），绝不抛异常——
 * 白名单配置坏了不能把整个页面拖挂。
 * @param {KVNamespace|null} kv
 * @returns {Promise<Array>}
 */
export async function loadFreeDomainEntries(kv) {
  if (!kv) return [];

  if (cache.entries && Date.now() - cache.at < MEM_TTL) {
    return cache.entries;
  }

  try {
    const raw = await kv.get(CONFIG_KEY);
    const entries = parse(raw);
    cache = { at: Date.now(), entries };
    return entries;
  } catch (e) {
    return cache.entries || [];
  }
}

/**
 * 写入完整配置数组。
 * @param {KVNamespace} kv
 * @param {Array} entries
 */
export async function saveFreeDomainEntries(kv, entries) {
  if (!kv) throw new Error('KV 未绑定，无法保存免费域名配置');
  const list = Array.isArray(entries) ? entries : [];
  await kv.put(CONFIG_KEY, JSON.stringify(list));
  cache = { at: Date.now(), entries: list };
  return list;
}

/**
 * 读最新配置（绕过缓存）后做一次修改并写回。
 * 用于增删改：必须先拿最新值，否则并发写会把别人刚加的后缀覆盖掉。
 * @param {KVNamespace} kv
 * @param {(entries: Array) => Array} mutator
 */
export async function updateFreeDomainEntries(kv, mutator) {
  if (!kv) throw new Error('KV 未绑定，无法保存免费域名配置');

  let current = [];
  try {
    current = parse(await kv.get(CONFIG_KEY));
  } catch (e) {
    current = [];
  }

  const next = mutator(current.slice());
  return saveFreeDomainEntries(kv, next);
}

/**
 * 按后缀 upsert 一条配置。
 * 同后缀已存在则整体替换（避免出现两条互相矛盾的记录）。
 */
export function upsertEntry(entries, entry) {
  const suffix = String(entry.suffix || '').toLowerCase();
  const rest = entries.filter(item => String(item && item.suffix || '').toLowerCase() !== suffix);
  rest.push(entry);
  return rest;
}

/** 从配置数组里移除某个后缀的所有覆盖项（等于恢复内置默认） */
export function dropEntry(entries, suffix) {
  const key = String(suffix || '').toLowerCase();
  return entries.filter(item => String(item && item.suffix || '').toLowerCase() !== key);
}
