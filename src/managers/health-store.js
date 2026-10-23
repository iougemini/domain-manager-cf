// 域名健康巡检
//
// 巡检与页面渲染是两条独立的路径，这一点很关键：
//
//   页面渲染有 4 秒预算，塞不进几十个域名的 DNS 探测；
//   而巡检是"定期看一眼"，本来就不该在用户打开页面时才跑。
//
// 所以巡检只跑在 Cron 里，结果写进 KV（health:<domain>），页面渲染时**只读 KV**，
// 零网络成本。用户想看最新状态可以手动触发单个域名的巡检。
//
// 巡检覆盖两层：
//   注册层  RDAP / WHOIS 返回的 EPP 状态（clientHold 这类），数据来自已有缓存，不额外请求
//   解析层  DoH 查 A / AAAA / CNAME，判断域名还能不能解析

import { CONFIG } from '../config.js';
import { parseRegistryStatus, isActionable } from '../services/registry-status.js';
import { isDnsProblem, describeDnsStatus } from '../services/dns-check.js';

const HEALTH_PREFIX = 'health:';

/** 巡检结果保留 2 天：每天巡检一次，留一天冗余，避免某次 Cron 失败就整片空白 */
const HEALTH_TTL_SECONDS = Math.round(CONFIG.HEALTH_TTL / 1000);

/** 同一个域名在这个间隔内不重复探测 */
const DEFAULT_MIN_INTERVAL_MS = CONFIG.HEALTH_MIN_INTERVAL;

/** 单次巡检的域名上限。Cron 有执行时长限制，宁可分几天轮完，也不要一次超时全丢 */
const DEFAULT_MAX_DOMAINS = CONFIG.HEALTH_MAX_DOMAINS;

/** DoH 并发数。同时发几十个请求会被公共解析服务限速 */
const CONCURRENCY = 4;

export function healthKey(domain) {
  return HEALTH_PREFIX + String(domain || '').toLowerCase();
}

/**
 * 读单个域名的巡检记录。读失败当作"没有记录"——
 * 巡检结果属于锦上添花，不该让页面因为一条坏数据而报错。
 */
export async function readHealth(kv, domain) {
  if (!kv || !domain) return null;
  try {
    const raw = await kv.get(healthKey(domain), { type: 'json' });
    return raw && typeof raw === 'object' ? raw : null;
  } catch {
    return null;
  }
}

/** 批量读。KV 没有 mget，只能逐个读，这里限制并发避免打爆 */
export async function readHealthBatch(kv, domains, options = {}) {
  const list = Array.isArray(domains) ? domains.filter(Boolean) : [];
  const limit = Number.isFinite(options.concurrency) && options.concurrency > 0
    ? options.concurrency
    : 8;

  const out = new Map();
  for (let i = 0; i < list.length; i += limit) {
    const slice = list.slice(i, i + limit);
    const results = await Promise.all(slice.map(name => readHealth(kv, name)));
    slice.forEach((name, index) => {
      if (results[index]) out.set(name, results[index]);
    });
  }
  return out;
}

async function writeHealth(kv, domain, record) {
  if (!kv || !domain) return;
  await kv.put(healthKey(domain), JSON.stringify(record), {
    expirationTtl: HEALTH_TTL_SECONDS
  });
}

/**
 * 把巡检记录归约成 UI / 通知要用的形状。
 *
 * 这份结论会随记录一起写进 KV：UI 只读结论，不再自己判一遍。
 * 否则状态码字典要在 data.js 里复制一份（它不能 import 服务端模块），
 * 两份字典迟早会漂移，出现"通知说异常、页面说正常"这种最难查的错。
 *
 * @param {{dns?: object, registry?: object}} record
 */
export function summarizeRecord(record) {
  if (!record) {
    return { level: 'unknown', dns: 'unknown', dnsLabel: '未探测', registry: null, problems: [] };
  }

  const dnsStatus = record.dns && record.dns.status ? record.dns.status : 'unknown';
  const parsed = record.registry ? parseRegistryStatus(record.registry.status) : null;

  const problems = [];
  if (isDnsProblem(record.dns)) {
    problems.push({ kind: 'dns', label: describeDnsStatus(dnsStatus) });
  }
  if (parsed && isActionable(parsed)) {
    problems.push({ kind: 'registry', label: parsed.labels.join('、'), level: parsed.level });
  }

  let level = 'ok';
  if (parsed && parsed.level === 'danger') level = 'danger';
  else if (isDnsProblem(record.dns)) level = 'danger';
  else if (parsed && parsed.level === 'warn') level = 'warn';
  else if (dnsStatus === 'error') level = 'unknown';

  return {
    level,
    dns: dnsStatus,
    dnsLabel: describeDnsStatus(dnsStatus),
    // 只留 UI 需要的字段，不要把整个解析结果塞进 KV
    registry: parsed
      ? {
        level: parsed.level,
        suspended: parsed.suspended,
        labels: parsed.labels,
        codes: parsed.codes.map(c => c.code)
      }
      : null,
    problems,
    checkedAt: record.checkedAt || null
  };
}

/** 简单并发池：按 CONCURRENCY 分批，批内并行、批间串行 */
async function mapWithConcurrency(items, limit, worker) {
  const results = [];
  for (let i = 0; i < items.length; i += limit) {
    const slice = items.slice(i, i + limit);
    results.push(...await Promise.all(slice.map(worker)));
  }
  return results;
}

/**
 * 跑一轮巡检。
 *
 * @param {object} params
 * @param {object} params.kv
 * @param {Array<{name: string}>} params.domains 待巡检域名
 * @param {object} params.dnsChecker DnsChecker 实例
 * @param {Function} [params.registryLookup] (name) => 原始 status（来自 WHOIS 缓存），可返回 null
 * @param {object} [params.options]
 * @param {number} [params.options.maxDomains]
 * @param {number} [params.options.minIntervalMs]
 * @param {boolean} [params.options.force] 忽略间隔限制
 * @param {number} [params.options.now] 便于测试注入时间
 * @returns {Promise<{checked: number, skipped: number, failed: number, problems: Array}>}
 */
export async function runHealthCheck(params) {
  const { kv, domains, dnsChecker, registryLookup } = params;
  const options = params.options || {};
  const now = Number.isFinite(options.now) ? options.now : Date.now();
  const maxDomains = Number.isFinite(options.maxDomains) && options.maxDomains > 0
    ? options.maxDomains
    : DEFAULT_MAX_DOMAINS;
  const minIntervalMs = Number.isFinite(options.minIntervalMs)
    ? options.minIntervalMs
    : DEFAULT_MIN_INTERVAL_MS;
  const force = Boolean(options.force);

  const names = (Array.isArray(domains) ? domains : [])
    .map(d => (typeof d === 'string' ? d : d && d.name))
    .filter(Boolean);

  if (!names.length || !dnsChecker) {
    return { checked: 0, skipped: 0, failed: 0, problems: [] };
  }

  // 先读已有记录，决定哪些要跳过。一次读不全也没关系，最坏情况是多重测一遍
  const existing = await readHealthBatch(kv, names);

  const todo = [];
  let skipped = 0;
  for (const name of names) {
    const prev = existing.get(name);
    if (!force && prev && prev.checkedAt) {
      const age = now - Date.parse(prev.checkedAt);
      if (Number.isFinite(age) && age >= 0 && age < minIntervalMs) {
        skipped++;
        continue;
      }
    }
    todo.push(name);
  }

  const queue = todo.slice(0, maxDomains);
  skipped += todo.length - queue.length;

  let checked = 0;
  let failed = 0;
  const problems = [];

  await mapWithConcurrency(queue, CONCURRENCY, async (name) => {
    let dns = null;
    try {
      dns = await dnsChecker.check(name);
    } catch (error) {
      dns = {
        status: 'error',
        records: { a: [], aaaa: [], cname: [] },
        error: error && error.message ? error.message : '探测异常',
        checkedAt: new Date(now).toISOString()
      };
    }

    let rawStatus = null;
    if (typeof registryLookup === 'function') {
      try {
        rawStatus = registryLookup(name);
      } catch {
        rawStatus = null;
      }
    }

    const record = {
      dns,
      registry: rawStatus ? { status: rawStatus } : null,
      checkedAt: dns && dns.checkedAt ? dns.checkedAt : new Date(now).toISOString()
    };
    // 结论随记录一起落库，UI 只读不算
    record.summary = summarizeRecord(record);

    checked++;
    if (dns.status === 'error') failed++;

    const summary = summarizeRecord(record);
    if (summary.problems.length) {
      problems.push({
        name,
        level: summary.level,
        problems: summary.problems,
        suspended: Boolean(summary.registry && summary.registry.suspended)
      });
    }

    try {
      await writeHealth(kv, name, record);
    } catch {
      // 写失败不影响本轮结论，下次巡检会补
    }
  });

  return { checked, skipped, failed, problems };
}

/**
 * 从巡检记录集合里挑出需要提醒的。
 * 排序：暂停解析（站点已挂）> 其他注册局危险状态 > 解析丢失
 */
export function collectHealthAlerts(records) {
  const alerts = [];
  for (const [name, record] of records instanceof Map ? records.entries() : []) {
    const summary = summarizeRecord(record);
    if (!summary.problems.length) continue;
    alerts.push({ name, ...summary });
  }

  const rank = item => {
    if (item.registry && item.registry.suspended) return 0;
    if (item.level === 'danger') return 1;
    return 2;
  };
  return alerts.sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
}
