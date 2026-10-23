// 自定义域名记录的合并规则
//
// 一条自定义域名有两份数据：
//   1. KV 里存的那条记录（可能是手工填的，也可能是上次查询写入的）
//   2. 刚刚查到的实时结果
//
// 两份都不能无条件相信：实时结果可能是 N/A / Unknown（没配 WHOIS 代理、
// 域名还没注册），本地记录可能早就过时（人家续过费了）。所以这里逐字段取
// 「第一个有意义的值」，并且把「到底有没有拿到到期日」单独表达出来——
// UI 靠这个决定是显示正常状态，还是提示用户补填。
//
// 独立成模块是为了能直接单测：合并规则出错的后果是静默的（页面 200、
// 字段恒为 Unknown），靠看页面发现不了。

import { isPermanentDate } from './free-domain-lookup.js';

// WHOIS 各家表达"没有值"的写法不统一，全部归一到"没有"
const MEANINGLESS = new Set(['', 'unknown', 'n/a', 'error', 'null', 'undefined']);

/** 只保留有意义的值：空串、Unknown、N/A、Error 一律视为"没有" */
export function knownValue(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number') return String(value);
  const text = String(value).trim();
  if (!text || MEANINGLESS.has(text.toLowerCase())) return null;
  return text;
}

/** 这条记录是否已经有可用的到期信息（含永久 / 自动续期这类非日期值） */
export function hasUsableExpiry(record) {
  if (!record) return false;
  if (record.isPermanent) return true;
  return Boolean(knownValue(record.expirationDate));
}

/**
 * 合并本地记录与实时查询结果。
 *
 * @param {object} local KV 里的自定义域名记录
 * @param {object|null} live 实时查询结果（可为 null）
 * @returns {{registrar: string, registrationDate: string, expirationDate: string,
 *   isPermanent: boolean, nameServers: string[], dataSource: string|null,
 *   lookupStatus: 'ok'|'manual'|'missing', lookupError: string|null, pending: boolean}}
 */
export function mergeCustomDomainRecord(local = {}, live = null) {
  const pick = (first, second) => knownValue(first) || knownValue(second) || 'Unknown';

  const expirationDate = pick(live && live.expirationDate, local.expirationDate);
  const isPermanent = Boolean(
    (live && live.isPermanent)
    || local.isPermanent
    || isPermanentDate(expirationDate)
  );

  // 用户手工改过的记录（autoUpdateWhois === false）以本地为准，
  // 实时值只用来补本地缺的字段
  const manualOnly = local.autoUpdateWhois === false;
  const complete = isPermanent || Boolean(knownValue(expirationDate));

  const liveSource = knownValue(live && live.dataSource);
  const localSource = knownValue(local.dataSource);

  let dataSource = null;
  if (manualOnly) dataSource = 'manual';
  else dataSource = liveSource || localSource || null;

  // 只有"确实没数据"时才把查询错误暴露给页面。查到东西还挂个错误提示，
  // 用户会以为这条数据不可信
  const lookupError = complete
    ? null
    : (knownValue(live && live.lookupError)
      || knownValue(live && live.whoisError)
      || knownValue(local.lookupError)
      || null);

  let lookupStatus;
  if (!complete) lookupStatus = 'missing';
  else if (manualOnly) lookupStatus = 'manual';
  else lookupStatus = 'ok';

  const liveNameServers = live && Array.isArray(live.nameServers) && live.nameServers.length
    ? live.nameServers
    : null;

  return {
    registrar: pick(live && live.registrar, local.registrar),
    registrationDate: pick(live && live.registrationDate, local.registrationDate),
    expirationDate,
    isPermanent,
    nameServers: liveNameServers || (Array.isArray(local.nameServers) ? local.nameServers : []),
    dataSource,
    lookupStatus,
    lookupError,
    pending: Boolean(live && live.pending)
  };
}
