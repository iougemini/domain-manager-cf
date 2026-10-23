// 视图模型：把 state.js 产出的域名记录规范化为 UI 需要的形状
// 状态判定集中在这里，避免渲染与筛选各写一套（旧 ui.js 的 type 字段缺失问题）

const DAY = 86400000;

/**
 * 到期日落在 2900 年以后 = 永久域名的哨兵日期（DNSHE 用 2999-12-31）。
 * 这里与 services/free-domain-lookup.js 的判定保持一致；UI 层单独留一份是为了
 * 让 data.js 保持零依赖（它也会被客户端脚本的构建链引用）。
 */
export function isPermanentDate(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(value || ''));
  return m ? Number(m[1]) >= 2900 : false;
}

export function escapeHtml(value) {
  return String(value === null || value === undefined ? '' : value).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

// 嵌入 <script type="application/json"> 时必须转义，防止 </script> 与 HTML 注入
export function safeJson(value) {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function parseYmd(value) {
  if (typeof value !== 'string') return null;
  const m = value.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return null;
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  return isNaN(d.getTime()) ? null : d;
}

export function daysLeft(expirationDate) {
  const target = parseYmd(expirationDate);
  if (!target) return null;
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  return Math.round((target.getTime() - today.getTime()) / DAY);
}

export function fmtDate(value) {
  if (!value || value === 'Unknown' || value === 'Error') return '—';
  if (value === 'Auto-Renewal') return '自动续期';
  if (isPermanentDate(value)) return '永久';
  const m = String(value).match(/^(\d{4}-\d{2}-\d{2})/);
  return m ? m[1] : String(value);
}

export function statusOf(d) {
  if (d.whoisError) return { key: 'error', label: '查询异常', tone: 'danger', group: 'pending', days: null };
  // 注册局层面的危险状态（clientHold / pendingDelete / redemptionPeriod）优先于到期判定：
  // 域名被暂停时站点已经打不开，此时"还有 200 天到期"是个会让人安心错方向的数字。
  // 结论由 managers/health-store.js 算好放在 d.registryAlert，这里只负责映射成徽标
  if (d.registryAlert) {
    const suspended = Boolean(d.registryAlert.suspended);
    const days = d.expirationDate ? daysLeft(d.expirationDate) : null;
    return {
      key: suspended ? 'suspended' : 'redemption',
      label: suspended ? '已暂停' : (d.registryAlert.labels[0] || '注册局异常'),
      tone: 'danger',
      group: 'suspended',
      days
    };
  }
  // 解析丢失（NXDOMAIN）：域名在 DNS 里已经查不到了。这**不是**"囤着没配解析"
  // —— 后者是 nodata，域名存在但没设地址记录。NXDOMAIN 意味着域名本身不存在，
  // 可能是过期被摘、NS 被改走或注册局删除，属于和"已暂停"同级的事故
  if (d.dnsLost) {
    return {
      key: 'dns-lost',
      label: '解析丢失',
      tone: 'danger',
      group: 'suspended',
      days: d.expirationDate ? daysLeft(d.expirationDate) : null
    };
  }
  // 永久域名由后端 FreeDomainManager.isPermanent() 判定，这里不再写死 eu.org 正则
  if (d.isPermanent) return { key: 'permanent', label: '永久', tone: 'violet', group: 'longterm', days: null };
  if (d.expirationDate === 'Auto-Renewal') return { key: 'auto', label: '自动续期', tone: 'neutral', group: 'longterm', days: null };
  // 页面渲染超时、后台还在补的那批。和"查不到"要分开：前者会自己好，
  // 后者要用户去补配置，混成一个状态会让人白等
  if (d.pending) return { key: 'pending', label: '查询中', tone: 'neutral', group: 'pending', days: null };
  // 没有到期日：免费域名是"还没配查询"，自定义域名是"新增时没查到、等用户补"
  if ((d.isFree || d.isCustom) && (!d.expirationDate || d.expirationDate === 'Unknown')) {
    return { key: 'setup', label: d.isCustom ? '待补充' : '待设置', tone: 'neutral', group: 'pending', days: null };
  }
  // 只看到期日。注册日缺失很常见（很多注册局不返回 creation date），
  // 拿它当"未知"的理由会把有明确到期日的域名也标成未知，提醒就跟着失效了
  if (!d.expirationDate || d.expirationDate === 'Unknown' || d.expirationDate === 'Error') {
    return { key: 'unknown', label: '未知', tone: 'neutral', group: 'pending', days: null };
  }

  const days = daysLeft(d.expirationDate);
  if (days === null) return { key: 'unknown', label: '未知', tone: 'neutral', group: 'pending', days: null };
  if (days < 0) return { key: 'expired', label: '已过期', tone: 'danger', group: 'expired', days };
  if (days <= 30) return { key: 'expiring', label: '临期', tone: 'warn', group: 'expiring', days };
  return { key: 'ok', label: '正常', tone: 'ok', group: 'ok', days };
}

export function normalizeDomains(list) {
  return (list || []).map(raw => {
    const isCustom = Boolean(raw.isCustomDomain);

    // 巡检结论。服务端（managers/health-store.js）已经把 DNS 与注册局状态判完并写进
    // KV 的 summary 字段，这里只做透传 —— 状态码字典不在客户端复制第二份，
    // 否则两份迟早漂移，出现"通知说异常、页面说正常"这种最难查的错
    const healthRecord = raw.health && typeof raw.health === 'object' ? raw.health : null;
    const healthSummary = healthRecord && healthRecord.summary ? healthRecord.summary : null;
    const registryAlert = healthSummary && healthSummary.registry && healthSummary.registry.level === 'danger'
      ? healthSummary.registry
      : null;
    // 只有 NXDOMAIN 算事故。nodata（域名存在但没配地址）与 error（探测本身失败）
    // 都不该改主徽标，否则一堆囤着的域名会天天飘红
    const dnsLost = Boolean(healthSummary && healthSummary.dns === 'nxdomain');

    const d = {
      name: String(raw.name || ''),
      account: isCustom ? '自定义域名' : (raw.username || '未命名账户'),
      username: raw.username || '',
      registrar: raw.registrar || 'Unknown',
      registrationDate: raw.registrationDate || 'Unknown',
      expirationDate: raw.expirationDate || 'Unknown',
      nameServers: Array.isArray(raw.nameServers) ? raw.nameServers : [],
      notes: raw.notes || '',
      isFree: Boolean(raw.isFree),
      // 永久标记有两条来源：注册表规则（eu.org 这类）和接口返回的哨兵日期（2999）
      isPermanent: Boolean(raw.isPermanent) || isPermanentDate(raw.expirationDate),
      // 本次渲染超时未查询，后台还在补
      pending: Boolean(raw.pending),
      isCustom,
      plan: isCustom
        ? (raw.serviceProvider || '外部 DNS')
        : (raw.plan ? 'Cloudflare ' + raw.plan : 'Cloudflare Free'),
      whoisError: raw.whoisError || null,
      // 数据来源：rdap / dnshe / whois / whois-proxy / registry / manual
      // 抽屉里据此显示徽标，让用户一眼看出到期日是查到的还是兜底值
      dataSource: raw.dataSource || null,
      lookupError: raw.lookupError || null,
      // 新增域名时的查询结果：ok 已写入 / manual 手工填的 / missing 查不到待补
      lookupStatus: raw.lookupStatus || null,
      manuallyEdited: Boolean(raw.isManuallyEdited),
      // 巡检结论：{ level, dns, dnsLabel, registry, problems, checkedAt }
      // checkedAt 在记录顶层与 summary 里都有，取到哪个用哪个 —— 只看 summary
      // 的话，某些写入路径会把它丢掉，详情页就只剩一个「—」
      health: healthSummary
        ? { ...healthSummary, checkedAt: healthSummary.checkedAt || healthRecord.checkedAt || null }
        : null,
      registryAlert,
      dnsLost
    };
    d.status = statusOf(d);
    return d;
  }).sort((a, b) => {
    // 注册局异常排最前：这类域名站点已经不可用，比"3 天后到期"更该先处理
    const weight = item => {
      if (item.status.group === 'suspended') return -1e9;
      return item.status.days === null ? 1e9 : item.status.days;
    };
    return weight(a) - weight(b);
  });
}

export function buildStats(list) {
  const stats = {
    total: list.length, ok: 0, expiring: 0, expired: 0, longterm: 0, pending: 0,
    suspended: 0,
    critical: 0, free: 0, paid: 0, custom: 0, errors: 0, unknown: 0
  };
  for (const d of list) {
    stats[d.status.group] = (stats[d.status.group] || 0) + 1;
    if (d.status.group === 'expiring' && d.status.days !== null && d.status.days <= 7) stats.critical++;
    // 注册局异常同样算"必须马上处理"，首页那句"N 个将在 7 天内到期"要把它算进去
    if (d.status.group === 'suspended') stats.critical++;
    if (d.isCustom) stats.custom++;
    else if (d.isFree) stats.free++;
    else stats.paid++;
    if (d.status.key === 'error') stats.errors++;
    if (d.status.key === 'unknown' || d.status.key === 'setup') stats.unknown++;
  }
  return stats;
}

export function groupByAccount(list) {
  const map = new Map();
  for (const d of list) {
    if (!map.has(d.account)) map.set(d.account, { name: d.account, domains: [], expiring: 0, expired: 0, suspended: 0, custom: false });
    const g = map.get(d.account);
    g.domains.push(d);
    g.custom = g.custom || d.isCustom;
    if (d.status.group === 'expiring') g.expiring++;
    if (d.status.group === 'expired') g.expired++;
    if (d.status.group === 'suspended') g.suspended++;
  }
  return Array.from(map.values()).sort((a, b) => b.domains.length - a.domains.length);
}

// 未来 13 周到期分布（0-7、7-14 … 天）
export function weekBuckets(list) {
  const out = [];
  for (let w = 0; w < 13; w++) {
    const start = w * 7;
    const end = start + 7;
    const count = list.filter(d => d.status.days !== null && d.status.days >= start && d.status.days < end).length;
    const dt = new Date();
    dt.setDate(dt.getDate() + start);
    out.push({
      count,
      hot: w < 5,
      label: w === 0 ? '本周' : (dt.getMonth() + 1) + '/' + dt.getDate()
    });
  }
  return out;
}

export function meter(d) {
  const st = d.status;
  if (st.key === 'permanent' || st.key === 'auto') {
    return '<div class="meter"><span class="violet" style="width:100%"></span></div><b>' + (st.key === 'permanent' ? '永久' : '自动') + '</b>';
  }
  if (st.days === null) {
    return '<div class="meter"><span style="width:100%;opacity:.35"></span></div><b>—</b>';
  }
  // 已暂停的域名即使还剩几百天，进度条也要标红：红色徽标配绿色进度条，
  // 扫一眼会以为这个域名没事
  const tone = st.group === 'suspended' || st.days < 0 || st.days <= 7 ? 'danger' : st.days <= 30 ? 'warn' : '';
  const pct = st.days < 0 ? 100 : st.days <= 30 ? Math.max(st.days / 30 * 100, 4) : Math.min(st.days / 365 * 100, 100);
  const text = st.days < 0 ? '超期 ' + Math.abs(st.days) + ' 天' : st.days + ' 天';
  return '<div class="meter"><span class="' + tone + '" style="width:' + pct.toFixed(1) + '%"></span></div><b class="' + tone + '">' + text + '</b>';
}
