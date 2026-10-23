// 页面外壳：head / 侧栏 / 顶栏 / 视图容器 / 抽屉 / 弹窗 / 数据注入
import { icon } from './icons.js';
import { CSS } from './styles.js';
import { escapeHtml, safeJson } from './data.js';
import { FAVICON_LINK, THEME_COLOR_META } from './favicon.js';
import {
  overviewView, domainsView, expiringView, accountsView,
  freeDomainsView, settingsView, notifyView, aboutView
} from './views.js';
import { formsHtml } from './forms.js';
import { clientScript } from './client.js';
import { FOOTER_CSS, footerHtml } from './footer.js';

const esc = escapeHtml;

function navItem(view, iconName, label, badge, active) {
  return '<button class="nav-item' + (active ? ' active' : '') + '" data-view-link="' + view + '">' +
    icon(iconName, 17) + '<span>' + label + '</span>' +
    (badge !== null && badge !== undefined ? '<em class="badge' + (view === 'expiring' && badge > 0 ? ' warn' : '') + '">' + badge + '</em>' : '') +
    '</button>';
}

export function renderPage(model) {
  const { domains, stats, isAdmin, version, project, freeDomains } = model;
  const alertCount = stats.expiring + stats.expired;
  const title = project.NAME + ' · ' + project.FULL_NAME;
  // 没设访问密码时前台是公开的，没有"登录"可退；管理员页永远有会话可退
  const showLogout = isAdmin || Boolean(model.authEnabled);
  const logoutHref = isAdmin ? '/admin-logout' : '/logout';

  const head = '<!DOCTYPE html>\n<html lang="zh-CN" data-theme="dark">\n<head>\n' +
    '<meta charset="UTF-8">\n' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
    '<meta name="color-scheme" content="dark light">\n' +
    '<meta name="description" content="' + esc(project.DESCRIPTION) + '">\n' +
    '<title>' + (isAdmin ? '管理后台' : '域名监控') + ' · ' + esc(title) + '</title>\n' +
    FAVICON_LINK + THEME_COLOR_META +
    '<script>try{var t=localStorage.getItem("dsmc-theme")||localStorage.getItem("dk-theme");if(t)document.documentElement.dataset.theme=t;}catch(e){}</script>\n' +
    '<style>' + CSS + FOOTER_CSS + '</style>\n</head>\n<body>\n';

  const rail = '<div class="app">' +
    '<aside class="rail">' +
      '<div class="brand" title="' + esc(project.FULL_NAME) + '"><span class="mark">' + icon('shield', 17) + '</span>' +
        '<div><b>' + esc(project.NAME) + '</b><small>v' + esc(version) + '</small></div></div>' +
      '<div class="nav-label">工作台</div>' +
      navItem('overview', 'grid', '概览', null, true) +
      navItem('domains', 'globe', '域名', stats.total, false) +
      navItem('expiring', 'clock', '续费', alertCount, false) +
      '<div class="nav-label">管理</div>' +
      navItem('accounts', 'layers', '账户', null, false) +
      navItem('freedomains', 'tag', '免费', null, false) +
      (isAdmin ? navItem('notify', 'bell', '通知', null, false) : '') +
      (isAdmin ? navItem('settings', 'sliders', '设置', null, false) : '') +
      '<div class="nav-label">项目</div>' +
      navItem('about', 'info', '关于', null, false) +
      '<div class="rail-foot">' +
        '<div class="theme-toggle" role="group" aria-label="主题切换">' +
          '<button data-theme-set="dark" class="on" aria-pressed="true">' + icon('moon', 13) + '深色</button>' +
          '<button data-theme-set="light" aria-pressed="false">' + icon('sun', 13) + '浅色</button>' +
        '</div>' +
        '<div class="user"><span class="avatar">' + (isAdmin ? 'A' : 'G') + '</span>' +
          '<div><b>' + (isAdmin ? '管理员' : '访客') + '</b><small>' + (isAdmin ? '可编辑' : '只读') + '</small></div></div>' +
      '</div>' +
    '</aside>';

  // 有域名没查完时给一条明确说明。用户看到"查询中"的徽标不至于以为是坏了，
  // 也知道点一下就能拿到完整结果
  const pendingNote = model.pending > 0
    ? '<div class="callout info" id="pendingNote" style="margin-bottom:14px;align-items:flex-start">' + icon('refresh', 16) +
        '<div style="flex:1;min-width:0"><b>' + model.pending + ' 个域名正在后台查询</b><br>' +
        '为了不让页面一直等，这里先显示已缓存的数据；其余的在后台继续查，稍后重新加载即可看到完整结果。</div>' +
        '<button class="btn sm" data-action="reload-page" style="flex:none">重新加载</button>' +
      '</div>'
    : '';

  const topbar = '<div class="main">' +
    '<header class="topbar">' +
      '<div><h1 id="pageTitle">概览</h1><p id="pageSub">全部账户 · 共 ' + stats.total + ' 个域名</p></div>' +
      '<div class="topbar-actions">' +
        '<button class="btn ghost icon" data-action="focus-search" title="搜索域名（/）" aria-label="搜索域名">' + icon('search', 16) + '</button>' +
        (isAdmin ? '<button class="btn icon" data-action="manual-query" title="手动 WHOIS 查询" aria-label="手动 WHOIS 查询">' + icon('globe', 16) + '</button>' : '') +
        (isAdmin ? '<button class="btn icon" id="btnRefresh" data-action="refresh-all" title="刷新全部" aria-label="刷新全部">' + icon('refresh', 16) + '</button>' : '') +
        (isAdmin ? '<button class="btn primary" id="btnAdd" data-action="add-domain">' + icon('plus', 15) + '添加域名</button>' : '') +
        (showLogout ? '<a class="btn icon" href="' + logoutHref + '" title="退出登录" aria-label="退出登录">' + icon('logout', 16) + '</a>' : '') +
      '</div>' +
    '</header>' +
    '<div class="content">' +
      pendingNote +
      '<section data-view="overview">' + overviewView(model) + '</section>' +
      '<section data-view="domains" hidden>' + domainsView(model) + '</section>' +
      '<section data-view="expiring" hidden>' + expiringView(model) + '</section>' +
      '<section data-view="accounts" hidden>' + accountsView(model) + '</section>' +
      '<section data-view="freedomains" hidden>' + freeDomainsView(model) + '</section>' +
      (isAdmin ? '<section data-view="notify" hidden>' + notifyView(model) + '</section>' : '') +
      (isAdmin ? '<section data-view="settings" hidden>' + settingsView(model) + '</section>' : '') +
      '<section data-view="about" hidden>' + aboutView(model) + '</section>' +
    '</div>' +
    footerHtml({ version, project }) +
  '</div></div>';

  const overlays = '<div class="backdrop" id="backdrop" data-action="close-drawer"></div>' +    '<aside class="drawer" id="drawer" role="dialog" aria-modal="true" aria-label="域名详情"></aside>' +
    '<dialog class="modal" id="modal"></dialog>' +
    '<div class="bulkbar" id="bulkbar"></div>' +
    '<div class="toasts" id="toasts" aria-live="polite"></div>';

  const data = '<script type="application/json" id="dsmc-data">' + safeJson({
    admin: isAdmin,
    total: stats.total,
    freeDomains: (freeDomains || []).map(e => ({
      suffix: e.suffix,
      category: e.category,
      registrar: e.registrar,
      renew: e.renew,
      provider: e.provider,
      note: e.note,
      source: e.source,
      disabled: Boolean(e.disabled),
      lookup: e.lookup || null
    })),
    // 管理页数据：账户 / DNSHE 凭证 / 设置 / 通知渠道
    accounts: model.accounts || [],
    accountSource: model.accountSource || 'none',
    dnshe: model.dnsheCredentials || [],
    dnsheEnv: model.dnsheEnv || { hasKey: false, hasSecret: false },
    settings: model.settings || {},
    notify: model.notify || { enabled: false, rules: {}, channels: [] },
    notifyState: model.notifyState || null,
    notifyTypes: model.notifyTypes || [],
    domains: domains.map(d => ({
      name: d.name, account: d.account, registrar: d.registrar,
      registrationDate: d.registrationDate, expirationDate: d.expirationDate,
      nameServers: d.nameServers, notes: d.notes, plan: d.plan,
      isCustom: d.isCustom, isFree: d.isFree, isPermanent: d.isPermanent, manuallyEdited: d.manuallyEdited,
      dataSource: d.dataSource || null, lookupError: d.lookupError || null,
      lookupStatus: d.lookupStatus || null,
      // group 必须带出来：抽屉靠它区分"已暂停"与其他状态，缺了不会报错，
      // 只是 isSuspended 恒为 false，于是已暂停的域名仍然主推「标记已续费」
      status: {
        key: d.status.key,
        label: d.status.label,
        tone: d.status.tone,
        days: d.status.days,
        group: d.status.group
      },
      // 巡检结论。抽屉要显示 DNS 与注册局状态，字段必须在这一层显式带出来 ——
      // 视图读的是投影结果，漏一个字段不会报错，只会恒为 undefined
      health: d.health
        ? {
          level: d.health.level,
          dns: d.health.dns,
          dnsLabel: d.health.dnsLabel,
          registry: d.health.registry || null,
          checkedAt: d.health.checkedAt || null
        }
        : null
    }))
  }) + '</script>\n';

  const script = '<script>' + clientScript() + '</script>\n';

  return head + rail + topbar + overlays + formsHtml() + data + script + '</body>\n</html>';
}
