// 视图片段（服务端渲染，客户端只做显隐/排序/分页）
import { icon } from './icons.js';
import { escapeHtml, fmtDate, meter, groupByAccount, weekBuckets } from './data.js';
import { LOOKUP_LABELS, SOURCE_LABELS } from '../managers/free-domain.js';

const esc = escapeHtml;

const RENEW_LABELS = { permanent: '永久', auto: '自动续期', manual: '人工维护' };

/** 判断某个域名是否落在给定后缀下（含 apex） */
function underSuffix(name, suffix) {
  return name === suffix || name.endsWith('.' + suffix);
}

/**
 * 自动发现：WHOIS 查不到注册商、且层级 ≥ 3 的域名，很可能是免费二级域名。
 * 这类域名加进白名单后就不再发无意义的 WHOIS 请求，配置成本几乎为零。
 *
 * 建议的后缀取最后两段（免费后缀几乎都是两段，如 us.kg / is-a.dev），
 * 而不是整条域名——否则白名单里会堆满一次性的完整域名。
 */
function discoveryCandidates(domains) {
  const unknown = new Set(['', 'Unknown', 'N/A', 'Error', 'null', 'undefined']);
  const seen = new Map();

  for (const d of domains) {
    if (d.isFree || d.isCustom) continue;
    if (!unknown.has(String(d.registrar).trim())) continue;

    const labels = d.name.split('.');
    if (labels.length < 3) continue;

    const suffix = labels.slice(-2).join('.');
    if (!seen.has(suffix)) seen.set(suffix, d.name);
  }

  return Array.from(seen.entries()).slice(0, 8).map(([suffix, sample]) => ({ suffix, sample }));
}

function pill(d) {
  return '<span class="pill ' + d.status.tone + '"><i></i>' + esc(d.status.label) + '</span>';
}

function expLabel(d) {
  if (d.status.key === 'permanent') return '永久';
  return fmtDate(d.expirationDate);
}

function daysAttr(d) {
  return d.status.days === null ? '' : String(d.status.days);
}

export function rowHtml(d, isAdmin, opts) {
  const o = opts || {};
  const actionButtons = isAdmin
    ? (d.status.days !== null
      ? '<button class="icon-btn" data-action="renew" data-name="' + esc(d.name) + '" title="标记已续费" aria-label="标记已续费">' + icon('check', 14) + '</button>'
      : '') +
      '<button class="icon-btn" data-action="refresh-one" data-name="' + esc(d.name) + '" title="刷新此域名" aria-label="刷新此域名">' + icon('refresh', 14) + '</button>' +
      '<button class="icon-btn" data-action="edit" data-name="' + esc(d.name) + '" title="编辑信息" aria-label="编辑信息">' + icon('edit', 14) + '</button>'
    : '<button class="icon-btn" data-action="open" data-name="' + esc(d.name) + '" title="查看详情" aria-label="查看详情">' + icon('info', 14) + '</button>';

  return '<tr class="row" data-name="' + esc(d.name) + '" data-group="' + d.status.group + '" data-status="' + d.status.key + '"' +
    (d.status.group === 'suspended' ? ' data-alert="1"' : '') +
    ' data-account="' + esc(d.account) + '" data-days="' + daysAttr(d) + '" data-registrar="' + esc(d.registrar) + '">' +
    (o.compact ? '' : '<td class="cb"><input type="checkbox" class="rowcb" data-name="' + esc(d.name) + '" aria-label="选择 ' + esc(d.name) + '"></td>') +
    '<td><div class="dom"><span class="favi">' + esc(d.name.charAt(0)) + '</span><div><b>' + esc(d.name) + '</b>' +
    '<small>' + esc(d.account) + ' · ' + esc(d.plan) + '</small></div></div></td>' +
    '<td>' + pill(d) + '</td>' +
    '<td class="dim col-opt">' + esc(d.registrar) + '</td>' +
    '<td class="mono col-opt">' + esc(expLabel(d)) + '</td>' +
    '<td><div class="meter-cell">' + meter(d) + '</div></td>' +
    '<td class="right"><div class="rowact">' + actionButtons + '</div></td>' +
    '</tr>';
}

function donutSvg(items) {
  const total = items.reduce((a, b) => a + b.value, 0) || 1;
  const R = 52, C = 2 * Math.PI * R;
  let off = 0;
  const arcs = items.filter(i => i.value > 0).map(i => {
    const len = i.value / total * C;
    const dash = Math.max(len - 3, 1);
    const seg = '<circle cx="66" cy="66" r="' + R + '" fill="none" stroke="' + i.color + '" stroke-width="13"' +
      ' stroke-dasharray="' + dash + ' ' + (C - dash) + '" stroke-dashoffset="' + (-off) + '"' +
      ' stroke-linecap="round" transform="rotate(-90 66 66)"/>';
    off += len;
    return seg;
  }).join('');
  return '<svg class="donut" viewBox="0 0 132 132" role="img" aria-label="域名状态分布">' + arcs + '</svg>';
}

export function overviewView(model) {
  const { stats, domains, isAdmin } = model;

  if (!domains.length) {
    return '<div class="card"><div class="empty">' +
      '<span class="ico">' + icon('inbox', 20) + '</span>' +
      '<b>还没有域名数据</b>' +
      '<p>检查 Cloudflare API 密钥是否配置正确，或稍后刷新重试。</p>' +
      (isAdmin ? '<button class="btn sm" data-action="refresh-all">立即刷新</button>' : '') +
      '</div></div>';
  }

  // 需要关注：注册局异常与到期问题合并，异常排前面
  const attention = domains
    .filter(d => d.status.group === 'expired' || d.status.group === 'expiring' || d.status.group === 'suspended')
    .sort((a, b) => {
      // 用 -1e9 而不是 -1：已过期域名的 days 是负数（-37 比 -1 更小），
      // 用 -1 会让"已过期 37 天"排在"已被暂停"前面，而后者才是站点已经挂了的那个
      const rank = item => (item.status.group === 'suspended' ? -1e9 : (item.status.days === null ? 1e9 : item.status.days));
      return rank(a) - rank(b);
    });
  const next = attention.find(d => d.status.days !== null && d.status.days >= 0);
  // 注册局异常比"已过期"更急，但它俩都是红色。用更深的红区分，
  // 而不是省略一项 —— donut 的分项合计必须等于总数，否则看的人会以为数据错了
  const items = [
    { label: '正常', value: stats.ok, color: 'var(--ok)' },
    ...(stats.suspended ? [{ label: '异常', value: stats.suspended, color: '#991b1b' }] : []),
    { label: '临期', value: stats.expiring, color: 'var(--warn)' },
    { label: '已过期', value: stats.expired, color: 'var(--danger)' },
    { label: '长期有效', value: stats.longterm, color: 'var(--violet)' },
    { label: '待完善', value: stats.pending, color: 'var(--text-3)' }
  ];
  const bars = weekBuckets(domains);
  const maxBar = Math.max.apply(null, bars.map(b => b.count).concat([1]));
  const accounts = groupByAccount(domains).slice(0, 4);

  const hasAlert = stats.suspended > 0 || stats.expiring > 0;
  const heroTone = hasAlert ? '' : ' ok';
  // 注册局异常优先于到期提醒：到期是"未来某天会出事"，异常是"现在就不能用了"
  const heroText = stats.suspended > 0
    ? '<b>' + stats.suspended + '</b> 个域名注册局状态异常，站点可能已无法访问'
    : (stats.expiring > 0
      ? '<b>' + stats.critical + '</b> 个将在 7 天内到期' + (next ? ' · 最早 <b>' + next.status.days + '</b> 天后（' + esc(next.name) + '）' : '')
      : '当前没有 30 天内到期的域名，保持关注即可');

  return '<div class="grid">' +
    '<section class="card hero">' +
      '<div class="hero-main">' +
        '<span class="eyebrow' + heroTone + '">' + icon(hasAlert ? 'alert' : 'check', 13) + (stats.suspended > 0 ? ' 注册局异常' : ' 未来 30 天') + '</span>' +
        '<div class="hero-num">' + (stats.suspended > 0 ? stats.suspended : stats.expiring) +
          '<span>' + (stats.suspended > 0 ? '个域名异常' : '个域名需要续费') + '</span></div>' +
        '<p class="hero-sub">' + heroText + '</p>' +
        '<div class="hero-actions">' +
          '<button class="btn primary" data-view-link="' + (stats.suspended > 0 ? 'domains' : 'expiring') + '">' +
            (stats.suspended > 0 ? '查看异常域名' : '查看续费清单') + ' ' + icon('arrow', 14) + '</button>' +
          '<button class="btn ghost" data-action="export">' + icon('download', 14) + ' 导出 CSV</button>' +
        '</div>' +
      '</div>' +
      '<div class="hero-side">' +
        (stats.suspended > 0
          ? '<button class="mini" data-view-link="domains"><span class="dot danger"></span><div><b>' + stats.suspended + '</b><small>异常</small></div></button>'
          : '<button class="mini" data-view-link="expiring"><span class="dot danger"></span><div><b>' + stats.expired + '</b><small>已过期</small></div></button>') +
        '<button class="mini" data-view-link="domains"><span class="dot ok"></span><div><b>' + stats.longterm + '</b><small>长期有效</small></div></button>' +
        '<button class="mini" data-view-link="domains"><span class="dot"></span><div><b>' + stats.pending + '</b><small>待完善</small></div></button>' +
      '</div>' +
    '</section>' +

    '<section class="card">' +
      '<div class="card-head"><h3>状态分布</h3><span class="sub">共 ' + stats.total + '</span></div>' +
      '<div class="card-body donut-body">' +
        '<div class="donut-wrap">' + donutSvg(items) + '<div class="donut-center"><b>' + stats.total + '</b><small>个域名</small></div></div>' +
        '<ul class="legend">' + items.map(i => '<li><i style="background:' + i.color + '"></i>' + i.label + '<b>' + i.value + '</b></li>').join('') + '</ul>' +
      '</div>' +
    '</section>' +

    '<section class="card span2">' +
      '<div class="card-head"><h3>到期分布</h3><span class="sub">未来 13 周</span></div>' +
      '<div class="card-body">' +
        '<div class="bars">' + bars.map(b =>
          '<div class="bar-col" title="' + b.label + ' · ' + b.count + ' 个域名">' +
            '<span class="bar-val">' + (b.count || '') + '</span>' +
            '<div class="bar ' + (b.count === 0 ? 'zero' : b.hot ? 'hot' : '') + '" style="height:' + (b.count ? Math.max(b.count / maxBar * 100, 8) : 3) + '%"></div>' +
            '<span class="bar-label">' + b.label + '</span>' +
          '</div>').join('') + '</div>' +
        '<div class="bars-note"><span><i style="background:var(--warn)"></i>30 天内需处理</span><span><i style="background:var(--text-3);opacity:.35"></i>后续到期</span></div>' +
      '</div>' +
    '</section>' +

    '<section class="card">' +
      '<div class="card-head"><h3>账户</h3><button class="sub" data-view-link="accounts" style="color:var(--accent-2)">全部 ' + icon('arrow', 12) + '</button></div>' +
      '<div class="card-body" style="padding-top:8px"><ul class="acct-list">' +
        accounts.map(a => '<li class="acct-item"><span class="favi">' + esc(a.name.charAt(0)) + '</span>' +
          '<div><b>' + esc(a.name) + '</b><small>' + a.domains.length + ' 个域名</small></div>' +
          '<span class="num">' + (a.expiring + a.expired > 0 ? '<span style="color:var(--warn)">' + (a.expiring + a.expired) + ' 待处理</span>' : '正常') + '</span></li>').join('') +
      '</ul></div>' +
    '</section>' +

    '<section class="card span3">' +
      '<div class="card-head"><h3>需要关注</h3><span class="sub">' + attention.length + ' 个域名</span></div>' +
      (attention.length
        ? '<div class="table-wrap"><table class="table">' +
            '<thead><tr><th>域名</th><th>状态</th><th class="col-opt">到期日期</th><th>剩余</th><th class="right">操作</th></tr></thead>' +
            '<tbody>' + attention.slice(0, 6).map(d => rowHtml(d, isAdmin, { compact: true })).join('') + '</tbody>' +
          '</table></div>' +
          '<div class="table-foot"><span>按紧急程度排序，仅显示前 6 个</span>' +
            '<button class="btn sm ghost" data-view-link="expiring" style="margin-left:auto">查看全部 ' + icon('arrow', 13) + '</button></div>'
        : '<div class="empty"><span class="ico">' + icon('check', 20) + '</span><b>30 天内没有需要续费的域名</b><p>所有域名都在安全期内。</p></div>') +
    '</section>' +
  '</div>';
}

export function domainsView(model) {
  const { stats, domains, isAdmin } = model;
  // 「异常」只在真出事时出现：注册局暂停 / 待删除这类状态一年遇不到几次，
  // 常驻一个恒为 0 的分类只会让工具栏变挤，也让真正有异常的那天不够醒目
  const chips = [
    ['all', '全部', stats.total],
    ...(stats.suspended ? [['suspended', '异常', stats.suspended]] : []),
    ['expiring', '临期', stats.expiring],
    ['expired', '已过期', stats.expired],
    ['ok', '正常', stats.ok],
    ['longterm', '长期有效', stats.longterm],
    ['pending', '待完善', stats.pending]
  ];
  const accounts = groupByAccount(domains);
  const candidates = discoveryCandidates(domains);

  return '<div class="card">' +
    '<div class="toolbar">' +
      '<label class="search">' + icon('search', 15) +
        '<input id="q" placeholder="搜索域名、注册商或账户" autocomplete="off" aria-label="搜索域名">' +
        '<kbd>/</kbd>' +
      '</label>' +
      '<div class="chips">' + chips.map(c =>
        '<button class="chip' + (c[0] === 'all' ? ' on' : '') + '" data-group="' + c[0] + '">' + c[1] + '<span class="n">' + c[2] + '</span></button>').join('') + '</div>' +
      '<div class="toolbar-right">' +
        '<select class="field" id="accountFilter" aria-label="账户筛选"><option value="all">全部账户</option>' +
          accounts.map(a => '<option value="' + esc(a.name) + '">' + esc(a.name) + '（' + a.domains.length + '）</option>').join('') +
        '</select>' +
        '<select class="field" id="sortSelect" aria-label="排序方式">' +
          '<option value="days-asc">到期最近</option>' +
          '<option value="days-desc">到期最远</option>' +
          '<option value="name">域名 A–Z</option>' +
          '<option value="registrar">按注册商</option>' +
        '</select>' +
      '</div>' +
    '</div>' +
    '<div id="tableHost">' +
      (domains.length
        ? '<div id="tableWrap"><div class="table-wrap"><table class="table" id="domainTable">' +
            '<thead><tr>' +
              '<th class="cb"><input type="checkbox" id="selAll" aria-label="全选当前页"></th>' +
              '<th class="sortable" data-sort="name">域名<span class="arw"></span></th>' +
              '<th>状态</th>' +
              '<th class="sortable col-opt" data-sort="registrar">注册商<span class="arw"></span></th>' +
              '<th class="col-opt">到期日期</th>' +
              '<th class="sortable" data-sort="days">剩余<span class="arw">↑</span></th>' +
              '<th class="right">操作</th>' +
            '</tr></thead>' +
            '<tbody id="domainBody">' + domains.map(d => rowHtml(d, isAdmin, {})).join('') + '</tbody>' +
          '</table></div>' +
          '<div class="table-foot"><span id="tableCount"></span><div class="pager" id="pager"></div></div></div>' +
          '<div id="tableEmpty" hidden><div class="empty">' +
            '<span class="ico">' + icon('search', 20) + '</span><b>没有匹配的域名</b>' +
            '<p>试试更换关键词，或清除状态与账户筛选条件。</p>' +
            '<button class="btn sm" data-action="reset-filters">清除全部筛选</button></div></div>'
        : '<div class="empty"><span class="ico">' + icon('inbox', 20) + '</span><b>暂无域名数据</b><p>请检查 API 配置或稍后重试。</p></div>') +
    '</div>' +
  '</div>' +
  (candidates.length
    ? '<div class="callout info" style="margin-top:14px;align-items:flex-start">' + icon('alert', 16) +
        '<div style="flex:1;min-width:0"><b>发现 ' + candidates.length + ' 个可能是免费二级域名</b><br>' +
        '这些域名的 WHOIS 查不到注册商。加入白名单后不再重复查询，改为按注册表规则处理。' +
        '<div class="cand">' + candidates.map(c =>
          '<button class="cand-chip" data-action="fd-discover" data-suffix="' + esc(c.suffix) + '"' +
            ' title="例如 ' + esc(c.sample) + '">' + esc(c.suffix) + icon('plus', 12) + '</button>').join('') + '</div></div>' +
      '</div>'
    : '');
}

export function expiringView(model) {
  const { domains, isAdmin } = model;
  const buckets = [
    { key: 'expired', title: '已过期', desc: '可能进入赎回期，立即处理', test: d => d.status.days !== null && d.status.days < 0 },
    { key: 'week', title: '7 天内到期', desc: '本周内完成续费', test: d => d.status.days !== null && d.status.days >= 0 && d.status.days <= 7 },
    { key: 'month', title: '8–30 天到期', desc: '安排预算与续费', test: d => d.status.days !== null && d.status.days > 7 && d.status.days <= 30 },
    { key: 'quarter', title: '31–90 天到期', desc: '提前规划', test: d => d.status.days !== null && d.status.days > 30 && d.status.days <= 90 }
  ];
  const groups = buckets.map(b => ({ ...b, list: domains.filter(b.test).sort((x, y) => x.status.days - y.status.days) }));
  const total = groups.reduce((a, g) => a + g.list.length, 0);

  if (!total) {
    return '<div class="card"><div class="empty"><span class="ico">' + icon('check', 20) + '</span>' +
      '<b>90 天内没有需要续费的域名</b><p>所有域名都在安全期内，下次检查会在这里提醒你。</p>' +
      '<button class="btn sm" data-view-link="domains">返回域名库</button></div></div>';
  }

  return '<div class="card" style="padding:16px 18px;display:flex;align-items:center;gap:14px;flex-wrap:wrap">' +
      '<div><div style="font-size:12px;color:var(--text-3)">90 天内到期</div>' +
      '<div style="font-size:26px;font-weight:650;letter-spacing:-.03em">' + total +
      ' <span style="font-size:13px;font-weight:500;color:var(--text-2)">个域名</span></div></div>' +
      '<div style="margin-left:auto;display:flex;gap:8px;flex-wrap:wrap">' +
        '<button class="btn" data-action="export">' + icon('download', 14) + ' 导出全部</button>' +
        (isAdmin ? '<button class="btn primary" data-action="renew-expiring">批量标记已续费</button>' : '') +
      '</div>' +
    '</div>' +
    groups.filter(g => g.list.length).map(g =>
      '<div class="section-head"><h2>' + g.title + '</h2><span>' + g.desc + ' · ' + g.list.length + ' 个</span></div>' +
      '<div class="card"><div class="table-wrap"><table class="table">' +
        '<thead><tr><th>域名</th><th>状态</th><th class="col-opt">到期日期</th><th>剩余</th><th class="right">操作</th></tr></thead>' +
        '<tbody>' + g.list.map(d => rowHtml(d, isAdmin, { compact: true })).join('') + '</tbody>' +
      '</table></div></div>').join('');
}

/**
 * 账户页：Cloudflare 账户的增删改查。
 *
 * 这一页取代了原先的「API 密钥」页——两者本来就是同一份数据（一个 Token 对应
 * 一个账户），分成两页只会让人不知道该去哪改。现在 Token 的增删改、启停、
 * 连通性测试都在这里。
 */
export function accountsView(model) {
  const { domains, isAdmin } = model;
  const accounts = model.accounts || [];
  const source = model.accountSource || 'none';
  const activeCount = accounts.filter(a => a.active).length;
  const groups = groupByAccount(domains);

  const sourceNote = source === 'env'
    ? '<div class="callout warn" style="margin-bottom:14px;align-items:flex-start">' + icon('alert', 16) +
        '<div style="flex:1;min-width:0"><b>当前账户来自环境变量</b><br>' +
        '环境变量 <code>CF_API_KEYS</code> / <code>USERNAMES</code> 是只读的，改不了也删不掉。' +
        '导入到 KV 之后就能在这一页自由编辑，环境变量可以保留作为备份。</div>' +
        (isAdmin ? '<button class="btn sm" data-action="acct-import" style="margin-left:auto;flex:none">导入并改为可编辑</button>' : '') +
      '</div>'
    : '';

  if (!accounts.length) {
    return sourceNote + '<div class="card"><div class="empty">' +
      '<span class="ico">' + icon('layers', 20) + '</span>' +
      '<b>还没有配置 Cloudflare 账户</b>' +
      '<p>添加一个具备 Zone:Read 权限的 API Token，就能读到该账户下的全部域名。</p>' +
      (isAdmin ? '<button class="btn primary" data-action="acct-add">' + icon('plus', 14) + ' 添加账户</button>' : '') +
      '</div></div>';
  }

  const row = a => {
    const used = a.lastUsed ? new Date(a.lastUsed).toLocaleString('zh-CN') : '从未';
    const errTone = a.errorCount >= 3 ? 'danger' : a.errorCount > 0 ? 'warn' : '';
    return '<tr data-account-id="' + esc(a.id) + '">' +
      '<td><div class="dom"><span class="favi">' + esc(String(a.label || '?').charAt(0)) + '</span>' +
        '<div><b>' + esc(a.label || a.username) + '</b>' +
        '<small>' + esc(a.username) + (a.note ? ' · ' + esc(a.note) : '') + '</small></div></div></td>' +
      '<td class="mono dim">' + esc(a.tokenMasked || '—') + '</td>' +
      '<td>' + (isAdmin
        ? '<button class="switch ' + (a.active ? 'on' : '') + '" data-action="acct-toggle" data-id="' + esc(a.id) + '" role="switch" aria-checked="' + (!!a.active) + '" aria-label="启用账户"></button>'
        : '<span class="pill ' + (a.active ? 'ok' : 'neutral') + '"><i></i>' + (a.active ? '启用' : '停用') + '</span>') +
      '</td>' +
      '<td class="mono' + (errTone ? ' ' + errTone : '') + '" style="' + (errTone ? 'color:var(--' + errTone + ')' : 'color:var(--text-2)') + '">' + (a.errorCount || 0) + '</td>' +
      '<td class="dim col-opt">' + esc(used) + '</td>' +
      '<td class="right"><div class="rowact">' +
        (isAdmin
          ? '<button class="icon-btn" data-action="acct-test" data-id="' + esc(a.id) + '" title="测试连通性" aria-label="测试连通性">' + icon('check', 14) + '</button>' +
            '<button class="icon-btn" data-action="acct-edit" data-id="' + esc(a.id) + '" title="编辑" aria-label="编辑">' + icon('edit', 14) + '</button>' +
            '<button class="icon-btn" data-action="acct-remove" data-id="' + esc(a.id) + '" title="删除" aria-label="删除">' + icon('trash', 14) + '</button>'
          : '') +
      '</div></td>' +
    '</tr>';
  };

  const acctGroups = groups.filter(g => !g.custom);
  const totalDomains = acctGroups.reduce((sum, g) => sum + g.domains.length, 0);

  return sourceNote +
    '<div class="card">' +
      '<div class="toolbar">' +
        '<div><h3 style="font-size:13.5px;font-weight:600">Cloudflare 账户</h3>' +
        '<p style="font-size:11.5px;color:var(--text-3);margin-top:2px">' +
          accounts.length + ' 个账户 · ' + activeCount + ' 个启用 · 共 ' + totalDomains + ' 个域名</p></div>' +
        '<div class="toolbar-right">' +
          (isAdmin ? '<button class="btn ghost" data-action="acct-test-all">' + icon('check', 14) + ' 全部测试</button>' : '') +
          (isAdmin ? '<button class="btn primary" data-action="acct-add">' + icon('plus', 14) + ' 添加账户</button>' : '') +
        '</div>' +
      '</div>' +
      '<div class="table-wrap"><table class="table">' +
        '<thead><tr><th>账户</th><th>Token</th><th>状态</th><th>错误数</th>' +
          '<th class="col-opt">最近使用</th><th class="right">操作</th></tr></thead>' +
        '<tbody>' + accounts.map(row).join('') + '</tbody>' +
      '</table></div>' +
      '<div class="table-foot"><span>Token 只存于 KV，页面与接口一律返回掩码</span>' +
        '<span style="margin-left:auto">来源：' +
          (source === 'kv' ? 'KV 配置（可编辑）' : source === 'env' ? '环境变量（只读）' : '未配置') +
        '</span></div>' +
    '</div>' +

    '<div class="callout ok" style="margin-top:14px;align-items:flex-start">' + icon('shield', 16) +
      '<div><b>Token 权限与安全</b><br>' +
      '只需要 <code>Zone:Read</code>（Zone → Zone → Read）。建议每个账户单独建一个 Token，' +
      '不要复用全局 API Key。连续失败 3 次的账户会自动熔断停用，修好后手动启用即可。</div>' +
    '</div>' +

    (acctGroups.length
      ? '<div class="section-head"><h2>账户分布</h2><span>按域名数量排序</span></div>' +
        '<div class="acct-grid">' + acctGroups.map(a => {
          const total = a.domains.length;
          const ok = a.domains.filter(d => d.status.group === 'ok').length;
          const lt = a.domains.filter(d => d.status.group === 'longterm').length;
          const pending = a.domains.filter(d => d.status.group === 'pending').length;
          const pct = n => total ? (n / total * 100).toFixed(2) : 0;
          return '<div class="acct-card">' +
            '<div class="acct-top"><span class="favi">' + esc(a.name.charAt(0)) + '</span>' +
              '<div><b>' + esc(a.name) + '</b><small>' + esc((a.domains[0] ? a.domains[0].plan : '').replace('Cloudflare ', '')) + '</small></div>' +
              '<span class="pill neutral"><i></i>Cloudflare</span></div>' +
            '<div class="acct-nums">' +
              '<div><b>' + total + '</b><small>域名</small></div>' +
              '<div><b class="' + (a.expiring ? 'warn' : '') + '">' + a.expiring + '</b><small>临期</small></div>' +
              '<div><b class="' + (a.expired ? 'danger' : '') + '">' + a.expired + '</b><small>已过期</small></div>' +
            '</div>' +
            '<div class="seg">' +
              '<i style="width:' + pct(ok) + '%;background:var(--ok)"></i>' +
              '<i style="width:' + pct(a.expiring) + '%;background:var(--warn)"></i>' +
              '<i style="width:' + pct(a.expired) + '%;background:var(--danger)"></i>' +
              '<i style="width:' + pct(lt) + '%;background:var(--violet)"></i>' +
              '<i style="width:' + pct(pending) + '%;background:var(--text-3);opacity:.4"></i>' +
            '</div>' +
            '<div class="acct-foot"><span>共 ' + total + ' 个域名 · ' + (lt + pending) + ' 个长期/待完善</span></div>' +
          '</div>';
        }).join('') + '</div>'
      : '');
}

/** 设置页：密码、会话、数据源、查询节奏 */
export function settingsView(model) {
  const s = model.settings || {};
  const dnsheCount = (model.dnsheCredentials || []).filter(c => c.enabled !== false).length;
  const dnsheFromEnv = Boolean(model.dnsheEnv && model.dnsheEnv.hasKey && !dnsheCount);

  // publicSettings() 投影出来的是 accessPasswordSet / adminPasswordSet 这类布尔，
  // 不是 accessPassword 本体（哈希永远不出后端）。所以「是否已设置」必须读 *Set 字段，
  // 读 s[field] 会永远是 undefined，页面就会一直显示「未设置」。
  const pwdRow = (field, label, setKey, sourceKey, hint) => {
    const set = Boolean(s[setKey]);
    const src = s[sourceKey];
    const badge = !set
      ? '<span class="pill danger"><i></i>未设置</span>'
      : src === 'kv'
        ? '<span class="pill ok"><i></i>已设置（KV）</span>'
        : '<span class="pill neutral"><i></i>来自环境变量</span>';

    return '<label class="frow"><span>' + label + ' ' + badge + '</span>' +
      '<input class="input" type="password" name="' + field + '" autocomplete="new-password" ' +
        'placeholder="' + (set ? '留空表示不修改' : '设置一个密码') + '">' +
      '<span class="hint">' + hint + '</span></label>';
  };

  return '<form data-form="settings" class="stack-form">' +
    '<section class="card">' +
      '<div class="card-head"><h3>访问控制</h3><span class="sub">保存后立即生效</span></div>' +
      '<div class="card-body grid2">' +
        pwdRow('accessPassword', '访问密码', 'accessPasswordSet', 'accessPasswordSource', '访客打开首页需要输入的密码，留空则任何人都能访问。') +
        pwdRow('adminPassword', '管理员密码', 'adminPasswordSet', 'adminPasswordSource', '进入管理后台、修改配置需要输入的密码。') +
        '<label class="frow"><span>会话有效期（小时）</span>' +
          '<input class="input" type="number" name="sessionHours" min="1" max="720" value="' + esc(s.sessionHours || 24) + '">' +
          '<span class="hint">登录一次保持多久。默认 24 小时。</span></label>' +
        '<label class="frow"><span>Token 签名密钥</span>' +
          '<input class="input" type="password" name="tokenSecret" autocomplete="new-password" ' +
            'placeholder="' + (s.tokenSecretSet ? '已设置，留空不修改' : '留空则自动派生') + '">' +
          '<span class="hint">改动会让所有已登录会话失效。留空由系统派生。</span></label>' +
      '</div>' +
    '</section>' +

    '<section class="card" style="margin-top:14px">' +
      '<div class="card-head"><h3>数据源</h3><span class="sub">WHOIS 与免费域名查询</span></div>' +
      '<div class="card-body grid2">' +
        '<label class="frow"><span>WHOIS 代理地址 ' +
          (s.whoisProxySource === 'kv' ? '<span class="pill ok"><i></i>KV</span>'
            : s.whoisProxySource === 'env' ? '<span class="pill neutral"><i></i>环境变量</span>'
            : '<span class="pill danger"><i></i>未配置</span>') + '</span>' +
          '<input class="input" name="whoisProxy" placeholder="https://your-whois-proxy.example.com" value="' + esc(s.whoisProxy || '') + '">' +
          '<span class="hint">普通域名（非免费后缀）的 WHOIS 查询走这里。留空则这些域名按「未知」处理。</span></label>' +
        '<label class="frow"><span>查询超时（毫秒）</span>' +
          '<input class="input" type="number" name="freeDomainLookupTimeout" min="1000" max="30000" value="' + esc(s.freeDomainLookupTimeout || 8000) + '">' +
          '<span class="hint">单次第三方查询的最长等待时间。</span></label>' +
        '<label class="frow" style="grid-column:1/-1"><span>免费域名实时查询</span>' +
          '<label class="inline-check"><input type="checkbox" name="freeDomainLiveLookup"' + (s.freeDomainLiveLookup ? ' checked' : '') + '>' +
          '<span>启用（关闭后所有免费域名只用内置注册表元数据，不再请求第三方接口）</span></label></label>' +
        '<label class="frow" style="grid-column:1/-1"><span>查询 UA（可选）</span>' +
          '<input class="input" name="freeDomainLookupUa" placeholder="留空使用内置浏览器 UA" value="' + esc(s.freeDomainLookupUa || '') + '">' +
          '<span class="hint">DigitalPlat 的 RDAP 前置了 WAF，默认 UA 会被 403。只有排障时才需要改。</span></label>' +
      '</div>' +
    '</section>' +

    '<section class="card" style="margin-top:14px">' +
      '<div class="card-head"><h3>查询节奏</h3><span class="sub">按服务商限速，避免被拉黑</span></div>' +
      '<div class="card-body grid2">' +
        '<label class="frow"><span>DNSHE 间隔（毫秒）</span>' +
          '<input class="input" type="number" name="paceDnshe" min="0" max="10000" value="' + esc(s.paceDnshe) + '">' +
          '<span class="hint">DNSHE 官方限速 60 次/分钟，2000ms 约等于 30 次/分钟，留了余量。</span></label>' +
        '<label class="frow"><span>WHOIS/TCP 间隔（毫秒）</span>' +
          '<input class="input" type="number" name="paceWhois" min="0" max="10000" value="' + esc(s.paceWhois) + '">' +
          '<span class="hint">pp.ua 这类 43 端口查询，逐个连接。</span></label>' +
        '<label class="frow"><span>RDAP 间隔（毫秒）</span>' +
          '<input class="input" type="number" name="paceRdap" min="0" max="5000" value="' + esc(s.paceRdap) + '">' +
          '<span class="hint">DigitalPlat 相对宽松，300ms 足够。</span></label>' +
        '<div class="frow"><span>当前生效</span>' +
          '<div class="stack">' +
            '<span>DNSHE ' + esc(s.paceDnshe) + 'ms</span>' +
            '<span>WHOIS ' + esc(s.paceWhois) + 'ms</span>' +
            '<span>RDAP ' + esc(s.paceRdap) + 'ms</span>' +
          '</div>' +
          '<span class="hint">命中缓存的域名不参与排队，所以全量刷新不会白等。</span></div>' +
      '</div>' +
    '</section>' +

    '<div class="form-actions">' +
      '<p class="err-text" data-error hidden></p>' +
      '<button type="submit" class="btn primary">保存设置</button>' +
    '</div>' +
  '</form>' +

  '<div class="section-head"><h2>外部服务凭证</h2><span>状态一览</span></div>' +
  '<div class="grid">' +
    '<section class="card"><div class="card-head"><h3>DNSHE</h3><span class="sub">平台级 WHOIS</span></div>' +
      '<div class="card-body"><div class="kv">' +
        '<dt>凭证数量</dt><dd>' + (dnsheFromEnv ? '1 条（环境变量）' : dnsheCount + ' 条启用') + '</dd>' +
        '<dt>作用范围</dt><dd>全部 DNSHE 域名</dd>' +
      '</div><p class="hint" style="margin-top:10px">一把 Key 能查全部域名，多把时自动故障切换。</p></div>' +
    '</section>' +
    '<section class="card"><div class="card-head"><h3>WHOIS 代理</h3></div>' +
      '<div class="card-body"><div class="kv">' +
        '<dt>状态</dt><dd>' + (s.whoisProxy ? '已配置' : '未配置') + '</dd>' +
        '<dt>来源</dt><dd>' + esc(s.whoisProxySource === 'kv' ? 'KV' : s.whoisProxySource === 'env' ? '环境变量' : '—') + '</dd>' +
      '</div><p class="hint" style="margin-top:10px">只影响非免费后缀的普通域名。</p></div>' +
    '</section>' +
    '<section class="card"><div class="card-head"><h3>缓存</h3></div>' +
      '<div class="card-body"><p class="hint">清空后下次访问会重新查询全部域名，耗时较长。</p>' +
      '<button class="btn sm ghost" data-action="clear-cache" style="margin-top:12px">清除 WHOIS 缓存</button></div>' +
    '</section>' +
  '</div>' +

  // DNSHE 凭证并进设置页：它本质上是"数据源配置"，独立成页后
  // 用户要先想"这个配置在哪一页"，而设置页正是找配置的地方
  '<div class="section-head"><h2>DNSHE 查询凭证</h2><span>' +
    (dnsheFromEnv ? '当前使用环境变量' : dnsheCount + ' 条启用') + '</span></div>' +
  dnsheView(model);
}

/**
 * DNSHE 页：查询凭证管理。
 *
 * 单独一页而不是塞进设置，是因为 DNSHE 的 Key 有两层含义：
 * whois 端点是平台级公开数据（一把 Key 能查全部域名），
 * 而 subdomains / dns_records / quota 是账户级（只能看自己账户下的东西）。
 * 做成"可多条 + 自动切换"，两种情形都能覆盖。
 */
export function dnsheView(model) {
  const credentials = model.dnsheCredentials || [];
  const enabled = credentials.filter(c => c.enabled !== false);

  const row = c => {
    const used = c.updatedAt ? new Date(c.updatedAt).toLocaleString('zh-CN') : '—';
    return '<tr data-credential-id="' + esc(c.id) + '">' +
      '<td><div class="dom"><span class="favi">' + esc(String(c.label || 'D').charAt(0)) + '</span>' +
        '<div><b>' + esc(c.label) + '</b><small>' + esc(c.keyMasked) + '</small></div></div></td>' +
      '<td class="mono dim col-opt">' + esc(c.secretMasked || '—') + '</td>' +
      '<td><button class="switch ' + (c.enabled !== false ? 'on' : '') + '" data-action="dnshe-toggle" data-id="' + esc(c.id) + '" role="switch" aria-checked="' + (c.enabled !== false) + '" aria-label="启用凭证"></button></td>' +
      '<td class="dim col-opt">' + esc(used) + '</td>' +
      '<td class="right"><div class="rowact">' +
        '<button class="icon-btn" data-action="dnshe-test" data-id="' + esc(c.id) + '" title="测试凭证" aria-label="测试凭证">' + icon('check', 14) + '</button>' +
        '<button class="icon-btn" data-action="dnshe-edit" data-id="' + esc(c.id) + '" title="编辑" aria-label="编辑">' + icon('edit', 14) + '</button>' +
        '<button class="icon-btn" data-action="dnshe-remove" data-id="' + esc(c.id) + '" title="删除" aria-label="删除">' + icon('trash', 14) + '</button>' +
      '</div></td>' +
    '</tr>';
  };

  return '<div class="card">' +
      '<div class="toolbar">' +
        '<div><h3 style="font-size:13.5px;font-weight:600">凭证列表</h3>' +
          '<p style="font-size:11.5px;color:var(--text-3);margin-top:2px">' +
          enabled.length + ' 条启用 / 共 ' + credentials.length + ' 条 · 按添加顺序依次尝试</p></div>' +
        '<div class="toolbar-right">' +
          '<button class="btn primary" data-action="dnshe-add">' + icon('plus', 14) + ' 添加凭证</button>' +
        '</div>' +
      '</div>' +
      (credentials.length
        ? '<div class="table-wrap"><table class="table">' +
            '<thead><tr><th>凭证</th><th class="col-opt">Secret</th><th>状态</th>' +
              '<th class="col-opt">更新时间</th><th class="right">操作</th></tr></thead>' +
            '<tbody>' + credentials.map(row).join('') + '</tbody>' +
          '</table></div>'
        : '<div class="empty"><span class="ico">' + icon('cloud', 20) + '</span>' +
            '<b>还没有 DNSHE 凭证</b>' +
            '<p>DNSHE 的所有接口（包括 whois）现在都要求 X-API-Key / X-API-Secret，' +
            '不配的话这 10 个免费后缀会静默降级到兜底值。</p>' +
            '<button class="btn primary" data-action="dnshe-add">' + icon('plus', 14) + ' 添加凭证</button></div>') +
      '<div class="table-foot"><span>凭证在 KV 中明文存储，接口只返回掩码</span></div>' +
    '</div>' +

    (model.dnsheEnv && model.dnsheEnv.hasKey && !credentials.length
      ? '<div class="callout warn" style="margin-top:14px;align-items:flex-start">' + icon('alert', 16) +
        '<div><b>当前在用环境变量里的凭证</b><br>' +
        '检测到 <code>DNSHE_API_KEY</code>' +
        (model.dnsheEnv.hasSecret
          ? ' + <code>DNSHE_API_SECRET</code>。'
          : '，但缺少 <code>DNSHE_API_SECRET</code> —— Key 与 Secret 必须成对发送，否则 whois 接口一律返回 401。') +
        '<br>在这里添加一条凭证后，页面配置会立刻接管（优先级高于环境变量）。</div></div>'
      : '') +

    '<div class="callout info" style="margin-top:14px;align-items:flex-start">' + icon('info', 16) +
      '<div><b>一个 Key 能查多少域名？</b><br>' +
      'DNSHE 的 <code>whois</code> 端点按域名查询，属于平台级公开数据 —— <b>任意一把有效凭证都能查平台上所有 DNSHE 域名</b>，' +
      '不需要按账户分别配置。而 <code>subdomains</code> / <code>dns_records</code> / <code>quota</code> 这些是账户级的，' +
      '只能看到自己账户下的东西。<br>' +
      '所以这里按「可多条 + 自动切换」设计：只有一把时等同于一个全局 Key；有多把时，前一把返回 401/403 会自动换下一把，' +
      '不会因为某个账户的 Key 过期就让所有 DNSHE 域名一起掉到兜底值。</div>' +
    '</div>' +

    '<div class="callout ok" style="margin-top:12px;align-items:flex-start">' + icon('key', 16) +
      '<div><b>怎么拿凭证</b><br>' +
      '登录 DNSHE 客户区 →「我的域名管理」→ 左侧「API 管理」→ 创建 API 密钥。' +
      'Key 形如 <code>cfsd_xxx</code>，创建时会同时给出 Secret。</div>' +
    '</div>';
}

/**
 * 通知页：到期提醒的渠道与规则。
 *
 * 渠道表单是动态生成的——类型定义（字段、占位符）由后端下发，
 * 前端只负责按 fields 渲染，加新渠道不用改这一页的代码。
 */
export function notifyView(model) {
  const config = model.notify || { enabled: false, rules: {}, channels: [] };
  const rules = config.rules || {};
  const channels = config.channels || [];
  const state = model.notifyState || {};
  const lastResults = state.lastResult || [];
  const lastOk = lastResults.filter(r => r.ok).length;

  const chRow = c => {
    const target = c.config
      ? (c.config.url || c.config.webhook || c.config.chatId || c.config.to || c.config.key || c.config.token || '—')
      : '—';
    return '<tr data-channel-id="' + esc(c.id) + '">' +
      '<td><div class="dom"><span class="favi">' + esc(String(c.typeLabel || '?').charAt(0)) + '</span>' +
        '<div><b>' + esc(c.label) + '</b><small>' + esc(c.typeLabel) + '</small></div></div></td>' +
      '<td class="dim col-opt"><span class="mono" style="font-size:11px">' + esc(String(target).slice(0, 42)) + '</span></td>' +
      '<td>' + (c.ready
        ? '<span class="pill ok"><i></i>已配置</span>'
        : '<span class="pill warn"><i></i>缺少字段</span>') + '</td>' +
      '<td><button class="switch ' + (c.enabled ? 'on' : '') + '" data-action="ch-toggle" data-id="' + esc(c.id) + '" role="switch" aria-checked="' + (!!c.enabled) + '" aria-label="启用渠道"></button></td>' +
      '<td class="right"><div class="rowact">' +
        '<button class="icon-btn" data-action="ch-test" data-id="' + esc(c.id) + '" title="发送测试" aria-label="发送测试">' + icon('send', 14) + '</button>' +
        '<button class="icon-btn" data-action="ch-edit" data-id="' + esc(c.id) + '" title="编辑" aria-label="编辑">' + icon('edit', 14) + '</button>' +
        '<button class="icon-btn" data-action="ch-remove" data-id="' + esc(c.id) + '" title="删除" aria-label="删除">' + icon('trash', 14) + '</button>' +
      '</div></td>' +
    '</tr>';
  };

  const lastLine = state.lastRunAt
    ? '上次运行：' + new Date(state.lastRunAt).toLocaleString('zh-CN') +
      (lastResults.length ? ' · ' + lastOk + '/' + lastResults.length + ' 个渠道成功' : '')
    : '还没有运行过';

  return '<form data-form="notify-rules" class="stack-form">' +
    '<section class="card">' +
      '<div class="card-head"><h3>到期提醒</h3>' +
        '<span class="sub">' + esc(lastLine) + '</span></div>' +
      '<div class="card-body">' +
        '<label class="inline-check" style="margin-bottom:14px">' +
          '<input type="checkbox" name="enabled"' + (config.enabled ? ' checked' : '') + '>' +
          '<span><b>启用定时提醒</b>（由 Cloudflare Cron 触发，默认每天一次）</span></label>' +
        '<div class="grid2">' +
          '<label class="frow"><span>提前多少天开始提醒</span>' +
            '<select class="input" name="daysBefore">' +
              [7, 15, 30, 60, 90].map(d =>
                '<option value="' + d + '"' + (Number(rules.daysBefore) === d ? ' selected' : '') + '>' + d + ' 天</option>').join('') +
            '</select></label>' +
          '<label class="frow"><span>时区偏移</span>' +
            '<select class="input" name="timezoneOffset">' +
              [8, 0, -5, -8, 9, 1].map(h =>
                '<option value="' + h + '"' + (Number(rules.timezoneOffset) === h ? ' selected' : '') + '>UTC' + (h >= 0 ? '+' : '') + h + '</option>').join('') +
            '</select></label>' +
        '</div>' +
        '<label class="inline-check" style="margin-top:12px">' +
          '<input type="checkbox" name="includeExpired"' + (rules.includeExpired !== false ? ' checked' : '') + '>' +
          '<span>包含已过期的域名</span></label>' +
        '<p class="hint" style="margin-top:12px">内容没变化时不会重复推送——同样的清单天天发只会让人把机器人静音。' +
        '需要立刻确认效果，用下面的「立即发送」。</p>' +
        '<p class="hint" style="margin-top:8px">这里配的渠道同时接收两类消息：<b>到期提醒</b>（按上面的提前天数）与' +
        '<b>健康告警</b>（域名被暂停解析、解析丢失等）。两者独立推送、各自去重——' +
        '告警不会因为到期清单没变化而被一起跳过。</p>' +
      '</div>' +
      '<div class="form-actions">' +
        '<p class="err-text" data-error hidden></p>' +
        '<button type="button" class="btn ghost" data-action="notify-send-now">' + icon('send', 14) + ' 立即发送</button>' +
        '<button type="submit" class="btn primary">保存设置</button>' +
      '</div>' +
    '</section>' +
  '</form>' +

  '<div class="section-head"><h2>通知渠道</h2><span>' + channels.length + ' 个渠道</span>' +
    '<button class="btn sm primary" data-action="ch-add">' + icon('plus', 13) + ' 添加渠道</button></div>' +

  (channels.length
    ? '<div class="card"><div class="table-wrap"><table class="table">' +
        '<thead><tr><th>渠道</th><th class="col-opt">目标</th><th>配置</th><th>状态</th>' +
          '<th class="right">操作</th></tr></thead>' +
        '<tbody>' + channels.map(chRow).join('') + '</tbody>' +
      '</table></div></div>'
    : '<div class="card"><div class="empty"><span class="ico">' + icon('bell', 20) + '</span>' +
        '<b>还没有通知渠道</b><p>支持飞书、钉钉、企业微信、Telegram、Server酱、PushPlus、Bark、邮件与通用 Webhook。</p>' +
        '<button class="btn primary" data-action="ch-add">' + icon('plus', 14) + ' 添加渠道</button></div></div>') +

  (lastResults.length
    ? '<div class="section-head"><h2>上次发送结果</h2><span>' + lastOk + '/' + lastResults.length + ' 成功</span></div>' +
      '<div class="card"><div class="table-wrap"><table class="table"><tbody>' +
        lastResults.map(r =>
          '<tr><td><b>' + esc(r.label || r.type) + '</b>' + (r.test ? ' <span class="pill neutral"><i></i>测试</span>' : '') + '</td>' +
          '<td>' + (r.ok
            ? '<span class="pill ok"><i></i>成功</span>'
            : '<span class="pill danger"><i></i>失败</span>') + '</td>' +
          '<td class="dim" style="font-size:11.5px">' + esc(r.error || '—') + '</td></tr>').join('') +
      '</tbody></table></div></div>'
    : '') +

  '<div class="callout info" style="margin-top:14px;align-items:flex-start">' + icon('clock', 16) +
    '<div><b>定时任务说明</b><br>' +
    '提醒跑在 Cloudflare Cron 上（<code>wrangler.toml</code> 的 <code>[triggers] crons</code>），默认每天一次。' +
    '为了不让定时任务超时，它只读 KV 缓存、最多补查 12 个域名，不会做全量刷新。' +
    '所以提醒反映的是"最近一次已知状态"——日常打开页面就会把缓存刷新。</div>' +
  '</div>';
}

/**
 * 免费域名白名单管理。
 * 三层配置（内置 / 环境变量 / KV）在这里被摊平成一个表，用「来源」列区分，
 * 用户改的其实只有 KV 这一层：内置项只能禁用，KV 项可以删除。
 */
export function freeDomainsView(model) {
  const { domains, freeDomains, isAdmin } = model;
  const all = freeDomains || [];
  const active = all.filter(e => !e.disabled);
  const disabled = all.filter(e => e.disabled);
  const candidates = discoveryCandidates(domains);
  const freeHits = domains.filter(d => d.isFree).length;

  const hitsOf = entry => domains.filter(d => d.isFree && underSuffix(d.name, entry.suffix)).length;

  const row = entry => {
    const hits = hitsOf(entry);
    const lookupText = entry.lookup
      ? (LOOKUP_LABELS[entry.lookup.type] || entry.lookup.type)
      : '仅元数据';
    const categoryPill = entry.category === 'public'
      ? '<span class="pill violet"><i></i>公益</span>'
      : '<span class="pill neutral"><i></i>免费</span>';
    const renewPill = entry.renew === 'permanent'
      ? '<span class="pill violet"><i></i>永久</span>'
      : entry.renew === 'auto'
        ? '<span class="pill ok"><i></i>自动</span>'
        : '<span class="pill warn"><i></i>人工</span>';

    return '<tr data-suffix="' + esc(entry.suffix) + '">' +
      '<td><div class="dom"><span class="favi">' + esc(entry.suffix.charAt(0)) + '</span>' +
        '<div><b class="mono" style="font-size:12.5px">' + esc(entry.suffix) + '</b>' +
        '<small>' + esc(entry.provider || '—') + '</small></div></div></td>' +
      '<td>' + categoryPill + '</td>' +
      '<td class="dim col-opt">' + esc(entry.registrar || 'Unknown') + '</td>' +
      '<td>' + renewPill + '</td>' +
      '<td class="dim col-opt">' + esc(lookupText) + '</td>' +
      '<td class="mono">' + (hits ? hits + ' 个' : '<span class="dim">—</span>') + '</td>' +
      '<td class="dim col-opt">' + esc(SOURCE_LABELS[entry.source] || entry.source || '—') + '</td>' +
      '<td class="right"><div class="rowact">' +
        (isAdmin
          ? '<button class="icon-btn" data-action="fd-edit" data-suffix="' + esc(entry.suffix) + '" title="编辑" aria-label="编辑">' + icon('edit', 14) + '</button>' +
            '<button class="icon-btn" data-action="fd-remove" data-suffix="' + esc(entry.suffix) + '" title="停用" aria-label="停用">' + icon('trash', 14) + '</button>'
          : '') +
      '</div></td>' +
    '</tr>';
  };

  return '<div class="card">' +
    '<div class="toolbar">' +
      '<div><h3 style="font-size:13.5px;font-weight:600">免费域名白名单</h3>' +
        '<p style="font-size:11.5px;color:var(--text-3);margin-top:2px">命中后缀的域名不再查询 WHOIS，改为按注册表规则处理 · 共 ' + active.length + ' 个生效后缀，' + freeHits + ' 个域名命中</p></div>' +
      '<div class="toolbar-right">' +
        (isAdmin ? '<button class="btn primary" data-action="fd-add">' + icon('plus', 14) + ' 添加后缀</button>' : '') +
      '</div>' +
    '</div>' +
    (active.length
      ? '<div class="table-wrap"><table class="table">' +
          '<thead><tr><th>后缀</th><th>类型</th><th class="col-opt">注册商</th><th>续期</th>' +
            '<th class="col-opt">查询方式</th><th>命中</th><th class="col-opt">来源</th><th class="right">操作</th></tr></thead>' +
          '<tbody>' + active.map(row).join('') + '</tbody>' +
        '</table></div>'
      : '<div class="empty"><span class="ico">' + icon('tag', 20) + '</span><b>白名单是空的</b><p>添加后缀后，对应的免费域名会被自动识别。</p></div>') +
    '<div class="table-foot"><span>公益类域名（eu.org / is-a.dev / js.org）按永久处理，不参与到期告警</span></div>' +
  '</div>' +

  (disabled.length
    ? '<div class="section-head"><h2>已停用</h2><span>仍保留在表中，可随时恢复</span></div>' +
      '<div class="card"><div class="table-wrap"><table class="table"><tbody>' +
        disabled.map(e => '<tr><td><b class="mono" style="font-size:12.5px">' + esc(e.suffix) + '</b></td>' +
          '<td class="dim">' + esc(SOURCE_LABELS[e.source] || e.source || '—') + '</td>' +
          '<td class="right">' + (isAdmin
            ? '<button class="btn sm ghost" data-action="fd-restore" data-suffix="' + esc(e.suffix) + '">恢复</button>'
            : '') + '</td></tr>').join('') +
      '</tbody></table></div></div>'
    : '') +

  (candidates.length
    ? '<div class="callout info" style="margin-top:14px;align-items:flex-start">' + icon('alert', 16) +
        '<div style="flex:1;min-width:0"><b>发现 ' + candidates.length + ' 个可能是免费二级域名</b><br>' +
        'WHOIS 查不到注册商，通常是免费二级域名。加入白名单可以避免每次都发起无效查询。' +
        '<div class="cand">' + candidates.map(c =>
          '<button class="cand-chip" data-action="fd-discover" data-suffix="' + esc(c.suffix) + '" title="例如 ' + esc(c.sample) + '">' +
            esc(c.suffix) + icon('plus', 12) + '</button>').join('') + '</div></div>' +
      '</div>'
    : '') +

  '<div class="callout ok" style="margin-top:14px;align-items:flex-start">' + icon('database', 16) +
    '<div><b>配置优先级</b><br>内置表 &lt; 环境变量 <code>FREE_DOMAIN_SUFFIXES</code> &lt; KV <code>config:free-domains</code>。' +
    '本页的修改写入 KV，60 秒内全节点生效，不需要重新部署；同后缀会覆盖内置项，改坏了点「恢复」即可回到默认。</div>' +
  '</div>';
}

/** 关于页：项目介绍、仓库、社群、数据来源 */
export function aboutView(model) {
  const { project, version, freeDomains } = model;
  const p = project || {};
  const activeSuffixes = (freeDomains || []).filter(e => !e.disabled).length;

  const link = (href, label, iconName, desc) =>
    '<a class="link-row" href="' + esc(href) + '" target="_blank" rel="noopener noreferrer">' +
      '<span class="link-ico">' + icon(iconName, 16) + '</span>' +
      '<div><b>' + esc(label) + '</b><small>' + esc(desc) + '</small></div>' +
      icon('external', 14) +
    '</a>';

  return '<div class="about-hero card">' +
      '<div class="about-mark">' + icon('shield', 24) + '</div>' +
      '<div class="about-id">' +
        '<div class="about-name">' + esc(p.NAME || 'DSMC') +
          '<span class="ver">v' + esc(version) + '</span></div>' +
        '<div class="about-full">' + esc(p.FULL_NAME || '') + '</div>' +
        '<p class="about-desc">' + esc(p.DESCRIPTION || '') +
          '。汇总多个 Cloudflare 账户下的域名，统一计算到期状态、生成续费清单，' +
          '并对免费二级域名自动匹配注册商与查询接口。</p>' +
        '<div class="about-actions">' +
          '<a class="btn primary" href="' + esc(p.GITHUB || '#') + '" target="_blank" rel="noopener noreferrer">' +
            icon('github', 15) + ' GitHub 仓库</a>' +
          '<a class="btn" href="' + esc(p.COMMUNITY || '#') + '" target="_blank" rel="noopener noreferrer">' +
            icon('chat', 15) + ' 交流社群</a>' +
        '</div>' +
      '</div>' +
    '</div>' +

    '<div class="grid" style="margin-top:14px">' +
      '<section class="card span2">' +
        '<div class="card-head"><h3>核心能力</h3></div>' +
        '<div class="card-body"><ul class="about-list">' +
          '<li><b>到期风险雷达</b>把「30 天内要续费多少个、最早几天后」放在首页第一屏，而不是让你自己数表格。</li>' +
          '<li><b>多账户聚合</b>一份配置管理多个 Cloudflare 账户的 Zone，按账户分组统计与筛选。</li>' +
          '<li><b>免费域名识别</b>内置 ' + activeSuffixes + ' 个免费/公益后缀，命中后自动匹配注册商，并尽量拉取真实到期日。</li>' +
          '<li><b>手动兜底</b>WHOIS 拿不到的域名可以手工维护，标记后不再被自动覆盖。</li>' +
          '<li><b>无外部依赖</b>样式与图标全部内联，不加载任何 CDN，单次响应即可完整渲染。</li>' +
        '</ul></div>' +
      '</section>' +

      '<section class="card">' +
        '<div class="card-head"><h3>联系与关注</h3></div>' +
        '<div class="card-body" style="display:grid;gap:8px">' +
          link(p.COMMUNITY || '#', '交流社群', 'chat', 'niege.app') +
          '<div class="link-row static">' +
            '<span class="link-ico">' + icon('info', 16) + '</span>' +
            '<div><b>微信公众号</b><small>' + esc(p.WECHAT || '') + '</small></div>' +
            '<button class="btn sm ghost" data-action="copy-text" data-copy="' + esc(p.WECHAT || '') + '">复制</button>' +
          '</div>' +
          link(p.GITHUB || '#', 'GitHub', 'github', '源码 / 问题反馈') +
        '</div>' +
      '</section>' +

      '<section class="card span2">' +
        '<div class="card-head"><h3>数据来源</h3><span class="sub">按优先级降级</span></div>' +
        '<div class="card-body"><ul class="about-list">' +
          '<li><b>Cloudflare API</b>读取各账户的 Zone 列表与套餐信息，只依赖 Zone:Read 权限。</li>' +
          '<li><b>DigitalPlat RDAP</b><code>rdap.digitalplat.org</code>，覆盖 us.kg / dpdns.org / xx.kg / qzz.io / qd.je。</li>' +
          '<li><b>DNSHE WHOIS API</b><code>api005.dnshe.com</code>，覆盖 us.ci / cc.cd / new.tg 等 10 个后缀，按 IP 限速。</li>' +
          '<li><b>pp.ua WHOIS</b><code>whois.pp.ua:43</code>，通过 TCP 直接查询注册局原始文本。</li>' +
          '<li><b>通用 WHOIS 代理</b>其余域名走 <code>WHOIS_PROXY</code>，未配置时按「未知」处理。</li>' +
        '</ul>' +
        '<p class="hint" style="margin-top:10px">所有查询结果写入 KV 缓存 7 天；第三方接口失败只降级、不报错，不影响页面可用性。</p>' +
        '</div>' +
      '</section>' +

      '<section class="card">' +
        '<div class="card-head"><h3>技术栈</h3></div>' +
        '<div class="card-body">' +
          '<div class="stack">' + ['Cloudflare Workers', 'KV', 'ES Modules', 'itty-router', '原生 CSS/JS']
            .map(t => '<span>' + esc(t) + '</span>').join('') + '</div>' +
          '<dl class="kv" style="margin-top:14px">' +
            '<dt>版本</dt><dd>v' + esc(version) + '</dd>' +
            '<dt>许可证</dt><dd>' + esc(p.LICENSE || 'MIT') + '</dd>' +
            '<dt>运行方式</dt><dd>Module Worker</dd>' +
          '</dl>' +
        '</div>' +
      '</section>' +
    '</div>';
}
