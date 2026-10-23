// 客户端脚本（原生 JS，无框架）。注意：本文件内容会被内联进 <script>，
// 因此这里不使用反引号与 ${} 插值，避免与外层模板字符串冲突。
export function clientScript() {
  return `
(function () {
  'use strict';

  var DATA = JSON.parse(document.getElementById('dsmc-data').textContent);
  var IS_ADMIN = !!DATA.admin;
  var DOMAINS = DATA.domains || [];
  var FREE = DATA.freeDomains || [];
  var ACCOUNTS = DATA.accounts || [];
  var DNSHE = DATA.dnshe || [];
  var NOTIFY = DATA.notify || { enabled: false, rules: {}, channels: [] };
  var CHANNELS = NOTIFY.channels || [];
  var TYPES = DATA.notifyTypes || [];
  var MAP = {};
  DOMAINS.forEach(function (d) { MAP[d.name] = d; });

  // 数据来源徽标：让「这个到期日是查到的还是兜底值」一眼可见
  var SOURCE_BADGE = {
    'rdap': ['ok', 'RDAP 实时查询'],
    'dnshe': ['ok', 'DNSHE 接口'],
    'whois': ['ok', 'WHOIS 实时查询'],
    'whois-proxy': ['neutral', 'WHOIS 代理'],
    'registry': ['neutral', '内置注册表'],
    'manual': ['violet', '手动维护']
  };

  var PAGE_SIZE = 25;
  var state = { view: 'overview', q: '', group: 'all', account: 'all', sort: 'days-asc', page: 1, sel: [] };
  var rows = [];

  var ICO = {
    ok: '<svg class="i" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>',
    info: '<svg class="i" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>',
    warn: '<svg class="i" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4l9 16H3l9-16z"/><path d="M12 10v4M12 17h.01"/></svg>',
    x: '<svg class="i" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6L6 18M6 6l12 12"/></svg>',
    alert: '<svg class="i" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4l9 16H3l9-16z"/><path d="M12 10v4M12 17h.01"/></svg>',
    check: '<svg class="i" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>'
  };

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function esc(v) {
    return String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function pad(n) { return n < 10 ? '0' + n : '' + n; }
  function fmtDate(d) { return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); }
  function isoDate(v) {
    if (!v || v === 'Unknown' || v === 'Auto-Renewal' || v === 'Error') return '';
    var m = String(v).match(/^[0-9]{4}-[0-9]{2}-[0-9]{2}/);
    return m ? m[0] : '';
  }

  /* 巡检时间用相对时间：用户关心的是"这条结论有多新"，而不是具体到哪一天。
     抽屉是客户端渲染的，不参与页面 ETag，所以这里用 Date.now() 是安全的。 */
  function relTime(v) {
    if (!v) return '—';
    var t = Date.parse(v);
    if (isNaN(t)) return '—';
    var diff = Date.now() - t;
    if (diff < 60000) return '刚刚';
    var min = Math.floor(diff / 60000);
    if (min < 60) return min + ' 分钟前';
    var hr = Math.floor(min / 60);
    if (hr < 24) return hr + ' 小时前';
    return Math.floor(hr / 24) + ' 天前';
  }

  function toast(type, msg) {
    var box = document.getElementById('toasts');
    if (!box) return;
    var el = document.createElement('div');
    el.className = 'toast ' + type;
    el.innerHTML = (type === 'ok' ? ICO.ok : type === 'warn' ? ICO.warn : ICO.info) + '<span></span>';
    el.querySelector('span').textContent = msg;
    box.appendChild(el);
    setTimeout(function () {
      el.style.opacity = '0';
      el.style.transition = 'opacity 200ms';
      setTimeout(function () { el.remove(); }, 220);
    }, 3200);
  }

  function fetchJSON(url, options) {
    return fetch(url, options || {}).then(function (res) {
      return res.text().then(function (text) {
        var data = {};
        try { data = text ? JSON.parse(text) : {}; } catch (e) { data = {}; }
        if (!res.ok) {
          var err = data && data.error;
          var msg = (err && (err.message || err)) || data.message || ('请求失败（' + res.status + '）');
          throw new Error(msg);
        }
        return data;
      });
    });
  }

  function postJSON(url, body) {
    return fetchJSON(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  }

  /* ---------------- 视图切换 ---------------- */
  var COUNTS = { total: DOMAINS.length, expiring: 0, expired: 0, accounts: 0 };
  DOMAINS.forEach(function (d) {
    if (d.status.key === 'expiring') COUNTS.expiring++;
    if (d.status.key === 'expired') COUNTS.expired++;
  });
  var acctSet = {};
  DOMAINS.forEach(function (d) { acctSet[d.account] = 1; });
  COUNTS.accounts = Object.keys(acctSet).length;

  var META = {
    overview: ['概览', '全部账户 · 共 ' + COUNTS.total + ' 个域名'],
    domains: ['域名', COUNTS.total + ' 个域名 · ' + COUNTS.accounts + ' 个账户'],
    expiring: ['续费', '按紧急程度排序，先处理最近到期的'],
    accounts: ['账户', ACCOUNTS.length + ' 个 Cloudflare 账户 · 可增删改'],
    freedomains: ['免费', '白名单后缀与查询方式'],
    notify: ['通知', '到期提醒的渠道与规则'],
    settings: ['设置', '访问密码、数据源、DNSHE 凭证与查询节奏'],
    about: ['关于', 'DSMC · Domain Status Manager for Cloudflare']
  };

  function showView(view) {
    if (!META[view]) view = 'overview';
    state.view = view;
    $$('[data-view]').forEach(function (section) {
      section.hidden = section.getAttribute('data-view') !== view;
    });
    $$('.nav-item').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-view-link') === view);
    });
    var title = document.getElementById('pageTitle');
    var sub = document.getElementById('pageSub');
    if (title) title.textContent = META[view][0];
    if (sub) sub.textContent = META[view][1];
    if (view === 'domains') applyTable();
    updateBulk();
    try { history.replaceState(null, '', '#' + view); } catch (e) {}
    window.scrollTo(0, 0);
  }

  /* ---------------- 主题 ---------------- */
  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    $$('[data-theme-set]').forEach(function (b) {
      var on = b.getAttribute('data-theme-set') === theme;
      b.classList.toggle('on', on);
      b.setAttribute('aria-pressed', String(on));
    });
    try { localStorage.setItem('dsmc-theme', theme); } catch (e) {}
  }

  /* ---------------- 域名表 ---------------- */
  function initRows() { rows = $$('#domainBody tr.row'); }

  function filteredRows() {
    var q = state.q.toLowerCase();
    return rows.filter(function (r) {
      if (state.group !== 'all' && r.getAttribute('data-group') !== state.group) return false;
      if (state.account !== 'all' && r.getAttribute('data-account') !== state.account) return false;
      if (q) {
        var hay = (r.getAttribute('data-name') + ' ' + r.getAttribute('data-registrar') + ' ' + r.getAttribute('data-account')).toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });
  }

  function sortRows(list) {
    var s = state.sort;
    return list.sort(function (a, b) {
      // 注册局异常的域名在任何排序下都置顶：排序是浏览偏好，
      // 而"这个域名已经打不开了"是必须马上看见的事
      var aa = a.getAttribute('data-alert') === '1' ? 0 : 1;
      var ba = b.getAttribute('data-alert') === '1' ? 0 : 1;
      if (aa !== ba) return aa - ba;

      if (s === 'name') return a.getAttribute('data-name').localeCompare(b.getAttribute('data-name'));
      if (s === 'registrar') return a.getAttribute('data-registrar').localeCompare(b.getAttribute('data-registrar'));
      var av = a.getAttribute('data-days');
      var bv = b.getAttribute('data-days');
      av = av === '' ? 1e9 : parseFloat(av);
      bv = bv === '' ? 1e9 : parseFloat(bv);
      return s === 'days-desc' ? bv - av : av - bv;
    });
  }

  function applyTable() {
    if (!rows.length) return;
    var list = sortRows(filteredRows());
    var pages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
    if (state.page > pages) state.page = pages;
    var start = (state.page - 1) * PAGE_SIZE;
    var page = list.slice(start, start + PAGE_SIZE);
    var body = document.getElementById('domainBody');
    if (!body) return;

    rows.forEach(function (r) { r.hidden = true; });
    page.forEach(function (r) { r.hidden = false; body.appendChild(r); });

    var count = document.getElementById('tableCount');
    if (count) {
      count.textContent = list.length
        ? '显示 ' + (start + 1) + '–' + Math.min(start + PAGE_SIZE, list.length) + ' / ' + list.length + ' 个域名'
        : '没有匹配的域名';
    }

    var pager = document.getElementById('pager');
    if (pager) {
      var html = '<button data-page="prev"' + (state.page === 1 ? ' disabled' : '') + ' aria-label="上一页">←</button>';
      var last = 0;
      for (var i = 1; i <= pages; i++) {
        if (i === 1 || i === pages || Math.abs(i - state.page) <= 1) {
          if (i - last > 1) html += '<button disabled>…</button>';
          html += '<button data-page="' + i + '"' + (i === state.page ? ' class="on"' : '') + '>' + i + '</button>';
          last = i;
        }
      }
      html += '<button data-page="next"' + (state.page === pages ? ' disabled' : '') + ' aria-label="下一页">→</button>';
      pager.innerHTML = html;
    }

    var selAll = document.getElementById('selAll');
    if (selAll) selAll.checked = page.length > 0 && page.every(function (r) { return state.sel.indexOf(r.getAttribute('data-name')) !== -1; });

    var empty = document.getElementById('tableEmpty');
    if (empty) empty.hidden = list.length > 0;
    var wrap = document.getElementById('tableWrap');
    if (wrap) wrap.hidden = list.length === 0;
  }

  function syncCheckboxes() {
    $$('.rowcb').forEach(function (cb) {
      cb.checked = state.sel.indexOf(cb.getAttribute('data-name')) !== -1;
    });
  }

  function updateBulk() {
    var bar = document.getElementById('bulkbar');
    if (!bar) return;
    var n = state.sel.length;
    bar.classList.toggle('on', n > 0 && state.view === 'domains');
    if (!n) { bar.innerHTML = ''; return; }
    bar.innerHTML = '<span class="cnt">已选 <b>' + n + '</b> 个域名</span>' +
      '<button class="btn sm ghost" data-action="export-selected">导出 CSV</button>' +
      (IS_ADMIN ? '<button class="btn sm primary" data-action="renew-selected">标记已续费</button>' : '') +
      '<button class="icon-btn" data-action="clear-selection" aria-label="取消选择">' + ICO.x + '</button>';
  }

  /* ---------------- 抽屉 ---------------- */
  function statusCallout(d) {
    var st = d.status;
    // 注册局异常必须排在到期判断之前。已暂停的域名往往还剩几百天到期，
    // 落到下面的"状态正常，距到期还有 N 天"分支就成了最误导人的一句话
    if (st.key === 'suspended') {
      return '<div class="callout danger">' + ICO.alert + '<div><b>域名已被暂停解析</b><br>' +
        '注册商或注册局暂停了该域名，站点现在无法访问。常见原因是注册邮箱未验证、账户欠费或资料争议；' +
        '处理后可恢复，不影响到期日。</div></div>';
    }
    if (st.key === 'redemption') {
      return '<div class="callout danger">' + ICO.alert + '<div><b>' + esc(st.label) + '</b><br>' +
        '域名已进入删除或赎回流程，请立刻到 ' + esc(d.registrar) + ' 处理，逾期将彻底释放。</div></div>';
    }
    if (st.key === 'dns-lost') {
      return '<div class="callout danger">' + ICO.alert + '<div><b>域名解析已丢失</b><br>' +
        'DNS 查询返回 NXDOMAIN，这个域名在 DNS 里已经不存在了。可能是 NS 被改走、' +
        '域名过期后被摘除，或注册局已删除。请到 ' + esc(d.registrar) + ' 核查。</div></div>';
    }
    if (st.key === 'expired') {
      return '<div class="callout danger">' + ICO.alert + '<div><b>已过期 ' + Math.abs(st.days) + ' 天</b><br>域名可能进入赎回期，请尽快在 ' + esc(d.registrar) + ' 处理。</div></div>';
    }
    if (st.key === 'expiring') {
      return '<div class="callout warn">' + ICO.alert + '<div><b>距到期 ' + st.days + ' 天</b><br>建议在 7 天内完成续费，避免解析中断。</div></div>';
    }
    if (st.key === 'permanent' || st.key === 'auto') {
      return '<div class="callout ok">' + ICO.check + '<div><b>' + esc(st.label) + '</b><br>长期有效，无需续费。</div></div>';
    }
    if (st.key === 'error') {
      return '<div class="callout danger">' + ICO.alert + '<div><b>WHOIS 查询失败</b><br>' + esc(d.notes || '请点击下方「刷新 WHOIS」重试。') + '</div></div>';
    }
    if (st.days === null) {
      return '<div class="callout warn">' + ICO.alert + '<div><b>缺少到期信息</b><br>建议补充到期日期，否则无法参与续费提醒。</div></div>';
    }
    return '<div class="callout ok">' + ICO.check + '<div><b>状态正常</b><br>距到期还有 ' + st.days + ' 天。</div></div>';
  }

  function sourceBadge(d) {
    var src = d.dataSource || (d.manuallyEdited ? 'manual' : null);
    if (!src) return '<span class="pill neutral"><i></i>未查询</span>';
    var m = SOURCE_BADGE[src];
    if (!m) return '<span class="pill neutral"><i></i>' + esc(src) + '</span>';
    return '<span class="pill ' + m[0] + '"><i></i>' + m[1] + '</span>';
  }

  /* 健康巡检区块。
     结论由服务端算好（managers/health-store.js），这里只做展示 ——
     客户端不复制状态码字典，否则两份判断迟早不一致。 */
  function healthBlock(d) {
    if (!d.health) {
      return '<h4>健康巡检</h4><p style="font-size:12.5px;color:var(--text-3)">' +
        '还没有巡检记录。定时任务每天会探测一次解析与注册局状态。</p>';
    }

    var h = d.health;
    var tone = h.dns === 'ok' ? 'ok' : (h.dns === 'nxdomain' ? 'danger' : (h.dns === 'nodata' ? 'neutral' : 'warn'));
    var rows = '<dt>DNS 解析</dt><dd><span class="pill ' + tone + '"><i></i>' + esc(h.dnsLabel || '未探测') + '</span></dd>';

    if (h.registry && h.registry.labels && h.registry.labels.length) {
      var regTone = h.registry.level === 'danger' ? 'danger' : (h.registry.level === 'warn' ? 'warn' : 'neutral');
      rows += '<dt>注册局状态</dt><dd><span class="pill ' + regTone + '"><i></i>' +
        esc(h.registry.labels.join('、')) + '</span></dd>';
    }

    rows += '<dt>探测时间</dt><dd>' + esc(relTime(h.checkedAt)) + '</dd>';

    var hint = '';
    if (h.registry && h.registry.suspended) {
      // 顶部 statusCallout 已经用大白话解释过"域名被暂停"，这里只补技术细节，
      // 两处写一样的文案会让用户以为自己看错了行
      var codes = (h.registry.codes || []).join('、') || 'clienthold';
      hint = '<div class="callout info" style="margin-top:10px">' + ICO.info +
        '<div>注册局返回的状态码：<code>' + esc(codes) + '</code>。' +
        '这是注册商或注册局侧的操作，通常在验证邮箱或结清欠费后自动解除。</div></div>';
    } else if (h.dns === 'nxdomain') {
      // 顶部已经解释过后果，这里只说明技术判定，避免两处说同一句话
      hint = '<div class="callout info" style="margin-top:10px">' + ICO.info +
        '<div>DNS 返回 <code>NXDOMAIN</code>：域名在解析体系里不存在，' +
        '而不是"存在但没配地址记录"。这两者的处置方式完全不同。</div></div>';
    } else if (h.dns === 'nodata') {
      hint = '<div class="callout info" style="margin-top:10px">' + ICO.info +
        '<div>域名存在但没有任何地址记录。囤着未启用的域名属于正常现象。</div></div>';
    }

    return '<h4>健康巡检</h4><dl class="kv">' + rows + '</dl>' + hint;
  }

  function openDrawer(name) {
    var d = MAP[name];
    if (!d) return;
    var drawer = document.getElementById('drawer');
    var backdrop = document.getElementById('backdrop');
    var expText = d.status.key === 'permanent' ? '永久'
      : (d.expirationDate === 'Auto-Renewal' ? '自动续期' : isoDate(d.expirationDate) || '—');
    var ns = (d.nameServers || []).length
      ? (d.nameServers || []).map(function (n) { return '<span>' + esc(n) + '</span>'; }).join('')
      : '<span>未获取</span>';
    var foot = '<button class="btn ghost" data-action="whois-refresh" data-name="' + esc(d.name) + '">刷新 WHOIS</button>';
    if (IS_ADMIN) {
      // 没有到期信息时，"补数据"才是主操作；这时候还让人点「标记已续费」
      // 等于用续费的名义改数据，语义全错
      var needsInfo = d.status.key === 'setup' || d.status.key === 'unknown';
      // 已暂停的域名同理：续费解决不了注册局暂停，把「标记已续费」做成主按钮
      // 会让人以为续费能救回来
      var isSuspended = d.status.group === 'suspended';
      var editPrimary = needsInfo || isSuspended;
      foot += '<button class="btn' + (editPrimary ? ' primary' : '') + '" data-action="edit" data-name="' + esc(d.name) + '">' +
        (needsInfo ? '补充信息' : '编辑') + '</button>';
      if (d.status.days !== null && !isSuspended) foot += '<button class="btn primary" data-action="renew" data-name="' + esc(d.name) + '">标记已续费</button>';
      if (d.isCustom) foot += '<button class="btn ghost" data-action="delete" data-name="' + esc(d.name) + '" style="color:var(--danger)">删除</button>';
    }

    drawer.innerHTML =
      '<div class="drawer-head"><div class="dom"><span class="favi">' + esc(d.name.charAt(0)) + '</span>' +
        '<div><b>' + esc(d.name) + '</b><small>' + esc(d.account) + ' · ' + esc(d.plan) + '</small></div></div>' +
        '<span class="pill ' + d.status.tone + '"><i></i>' + esc(d.status.label) + '</span>' +
        '<button class="icon-btn" data-action="close-drawer" aria-label="关闭">' + ICO.x + '</button></div>' +
      '<div class="drawer-body">' +
        statusCallout(d) +
        (d.lookupError
          ? '<div class="callout warn" style="margin-top:10px">' + ICO.warn +
            '<div><b>实时查询失败</b><br>已回退到注册表兜底值：' + esc(d.lookupError) + '</div></div>'
          : '') +
        '<h4>基本信息</h4><dl class="kv">' +
          '<dt>注册商</dt><dd>' + esc(d.registrar) + '</dd>' +
          '<dt>注册日期</dt><dd>' + (isoDate(d.registrationDate) || '—') + '</dd>' +
          '<dt>到期日期</dt><dd>' + expText + '</dd>' +
          '<dt>剩余天数</dt><dd>' + (d.status.days === null ? '—' : d.status.days + ' 天') + '</dd>' +
          '<dt>所属账户</dt><dd>' + esc(d.account) + '</dd>' +
          '<dt>服务商</dt><dd>' + esc(d.plan) + '</dd>' +
          '<dt>数据来源</dt><dd>' + sourceBadge(d) + '</dd>' +
        '</dl>' +
        '<h4>名称服务器</h4><div class="ns">' + ns + '</div>' +
        healthBlock(d) +
        '<h4>时间线</h4><ul class="tl">' +
          '<li class="ok"><b>域名注册</b>' + (isoDate(d.registrationDate) || '未知') + '</li>' +
          '<li><b>最近一次查看</b>本次会话</li>' +
          '<li class="' + (d.status.key === 'expired' ? 'danger' : d.status.key === 'expiring' ? 'warn' : 'ok') + '"><b>到期</b>' + expText + '</li>' +
        '</ul>' +
        (d.notes ? '<h4>备注</h4><p style="font-size:12.5px;color:var(--text-2);line-height:1.6">' + esc(d.notes) + '</p>' : '') +
        '<div data-whois hidden style="margin-top:18px"><h4>WHOIS 结果</h4><div class="result" data-whois-body></div></div>' +
      '</div>' +
      '<div class="drawer-foot">' + foot + '</div>';

    drawer.classList.add('on');
    drawer.setAttribute('data-name', name);
    backdrop.classList.add('on');
    syncScrollLock();
  }

  function closeDrawer() {
    var drawer = document.getElementById('drawer');
    var backdrop = document.getElementById('backdrop');
    if (drawer) { drawer.classList.remove('on'); drawer.removeAttribute('data-name'); }
    if (backdrop) backdrop.classList.remove('on');
    syncScrollLock();
  }

  /* 抽屉和弹窗都会盖住页面，但都不阻止背景滚动。抽屉里还能再开弹窗，
     所以锁/解锁要按"当前是否还有遮罩"统一算，不能各管各的。 */
  function syncScrollLock() {
    var drawer = document.getElementById('drawer');
    var modal = document.getElementById('modal');
    var locked = Boolean(
      (drawer && drawer.classList.contains('on')) ||
      (modal && modal.open)
    );
    document.documentElement.classList.toggle('no-scroll', locked);
  }

  /* ---------------- 弹窗 ---------------- */
  function openModal(tplId, fill) {
    var tpl = document.getElementById(tplId);
    var modal = document.getElementById('modal');
    if (!tpl || !modal) return null;
    modal.innerHTML = '';
    modal.appendChild(tpl.content.cloneNode(true));
    if (fill) fill(modal);
    if (typeof modal.showModal === 'function') modal.showModal();
    else modal.setAttribute('open', '');
    var first = modal.querySelector('input, textarea, select');
    if (first) setTimeout(function () { first.focus(); }, 30);
    syncScrollLock();
    return modal;
  }

  function closeModal() {
    var modal = document.getElementById('modal');
    if (!modal) return;
    if (modal.open && typeof modal.close === 'function') modal.close();
    else modal.removeAttribute('open');
    modal.innerHTML = '';
    syncScrollLock();
  }

  function confirmAction(title, text, okText, onOk) {
    openModal('tpl-confirm', function (m) {
      m.querySelector('[data-confirm-title]').textContent = title;
      m.querySelector('[data-confirm-text]').textContent = text;
      var ok = m.querySelector('[data-confirm-ok]');
      ok.textContent = okText || '确认';
      ok.addEventListener('click', function () { closeModal(); onOk(); });
    });
  }

  function showFormError(form, msg) {
    var el = form.querySelector('[data-error]');
    if (!el) return;
    el.textContent = msg;
    el.hidden = false;
  }

  function reloadSoon(ms) {
    setTimeout(function () { location.reload(); }, ms || 700);
  }

  /* ---------------- 业务动作 ---------------- */
  function refreshAll() {
    confirmAction('刷新全部域名', '将重新查询所有域名的 WHOIS 信息，可能需要几分钟。', '开始刷新', function () {
      toast('info', '正在刷新，请稍候…');
      postJSON('/api/update', { action: 'refresh', force: true }).then(function (data) {
        toast('ok', data.message || '刷新完成');
        reloadSoon(1200);
      }).catch(function (err) { toast('warn', err.message); });
    });
  }

  function refreshOne(name) {
    toast('info', '正在刷新 ' + name + '…');
    postJSON('/api/update', { action: 'refresh', domain: name, force: true }).then(function (data) {
      toast('ok', data.message || (name + ' 已更新'));
      reloadSoon(900);
    }).catch(function (err) { toast('warn', err.message); });
  }

  function nextYear(exp) {
    var base = new Date();
    var iso = isoDate(exp);
    if (iso) {
      var p = iso.split('-');
      var old = new Date(Number(p[0]), Number(p[1]) - 1, Number(p[2]));
      if (old.getTime() > Date.now()) base = old;
    }
    base.setFullYear(base.getFullYear() + 1);
    return fmtDate(base);
  }

  function renewOne(name) {
    var d = MAP[name];
    if (!d) return;
    var target = nextYear(d.expirationDate);
    confirmAction('标记已续费', name + ' 的到期日期将更新为 ' + target + '，并关闭该域名的 WHOIS 自动更新。', '确认续费', function () {
      postJSON('/api/custom-domains', {
        action: 'update',
        domain: name,
        info: { expirationDate: target, notes: d.notes || '' }
      }).then(function () {
        toast('ok', name + ' 已标记续费至 ' + target);
        reloadSoon(900);
      }).catch(function (err) { toast('warn', err.message); });
    });
  }

  function renewMany(names) {
    if (!names.length) { toast('warn', '请先选择域名'); return; }
    confirmAction('批量标记已续费', '将为 ' + names.length + ' 个域名各延长一年（到期日期 +1 年）。', '确认', function () {
      toast('info', '正在处理 ' + names.length + ' 个域名…');
      var chain = Promise.resolve();
      var failed = 0;
      names.forEach(function (name) {
        chain = chain.then(function () {
          var d = MAP[name];
          if (!d) return null;
          return postJSON('/api/custom-domains', {
            action: 'update',
            domain: name,
            info: { expirationDate: nextYear(d.expirationDate), notes: d.notes || '' }
          }).catch(function () { failed++; });
        });
      });
      chain.then(function () {
        toast(failed ? 'warn' : 'ok', '已处理 ' + (names.length - failed) + ' 个域名' + (failed ? '，' + failed + ' 个失败' : ''));
        reloadSoon(1100);
      });
    });
  }

  function editDomain(name, seed) {
    // seed 用于"刚添加完、列表里还没刷新"的场景：MAP 里还没有这条记录
    var d = seed || MAP[name];
    if (!d) return;
    openModal('tpl-edit-domain', function (m) {
      var form = m.querySelector('form');
      form.setAttribute('data-domain', name);
      m.querySelector('[data-field="name"]').textContent = name;
      m.querySelector('[name="registrar"]').value = d.registrar === 'Unknown' ? '' : (d.registrar || '');
      m.querySelector('[name="serviceProvider"]').value = d.isCustom ? (d.plan || '') : '';
      m.querySelector('[name="registrationDate"]').value = isoDate(d.registrationDate);
      m.querySelector('[name="expirationDate"]').value = isoDate(d.expirationDate);
      m.querySelector('[name="notes"]').value = d.notes || '';

      var notice = m.querySelector('[data-notice]');
      if (notice && d.lookupStatus === 'missing') {
        notice.hidden = false;
        notice.innerHTML = ICO.warn + '<div><b>没查到到期信息</b><br>' +
          esc(d.lookupError || 'WHOIS 没有返回可用的到期日期，请手动填写，否则无法参与续费提醒。') + '</div>';
      }
    });
  }

  function addDomain() { openModal('tpl-add-domain', null); }

  function deleteDomain(name) {
    confirmAction('删除域名', '将从自定义域名列表中移除 ' + name + '。若它来自 Cloudflare，刷新后会重新出现。', '删除', function () {
      postJSON('/api/custom-domains', { action: 'remove', domain: name }).then(function () {
        toast('ok', name + ' 已删除');
        closeDrawer();
        reloadSoon(800);
      }).catch(function (err) { toast('warn', err.message); });
    });
  }

  function manualQuery() { openModal('tpl-manual-query', null); }

  function refreshWhois(name) {
    var box = document.querySelector('[data-whois]');
    var body = document.querySelector('[data-whois-body]');
    if (!box || !body) return;
    box.hidden = false;
    body.textContent = '查询中…';
    fetchJSON('/whois/' + encodeURIComponent(name)).then(function (resp) {
      // 接口外层是 { error, queriedDomain, data, rawData }。
      // 早前这里直接把外层当域名对象读，字段全是 undefined，结果只能看到整段 JSON，
      // 反而看不出"这条数据到底属于哪个域名"。
      var data = (resp && resp.data) ? resp.data : (resp || {});
      var lines = ['查询域名: ' + ((resp && resp.queriedDomain) || name)];
      ['registrar', 'registrationDate', 'expirationDate', 'status'].forEach(function (k) {
        if (data[k]) lines.push(k + ': ' + data[k]);
      });
      if (data.dataSource) lines.push('dataSource: ' + data.dataSource);
      if (data.lookupError) lines.push('lookup: ' + data.lookupError);
      if (data.whoisError) lines.push('error: ' + data.whoisError);
      if (resp && resp.rawData) lines.push('', String(resp.rawData).slice(0, 2000));
      body.textContent = lines.join('\\n');
      toast('ok', name + ' WHOIS 已更新');
    }).catch(function (err) {
      body.textContent = '查询失败：' + err.message;
      toast('warn', 'WHOIS 查询失败：' + err.message);
    });
  }

  /* ---------------- 账户 ---------------- */
  function findAccount(id) {
    for (var i = 0; i < ACCOUNTS.length; i++) {
      if (ACCOUNTS[i].id === id) return ACCOUNTS[i];
    }
    return null;
  }

  function acctAdd() {
    openModal('tpl-account', function (m) {
      m.querySelector('[data-field="mode"]').textContent = '添加 Cloudflare 账户';
    });
  }

  function acctEdit(id) {
    var a = findAccount(id);
    if (!a) return;
    openModal('tpl-account', function (m) {
      var form = m.querySelector('form');
      form.setAttribute('data-account-id', id);
      m.querySelector('[data-field="mode"]').textContent = '编辑 ' + (a.label || a.username);
      form.querySelector('[name="label"]').value = a.label || '';
      form.querySelector('[name="username"]').value = a.username || '';
      form.querySelector('[name="note"]').value = a.note || '';
      var token = form.querySelector('[name="token"]');
      token.placeholder = '留空表示不修改（当前 ' + (a.tokenMasked || '') + '）';
      var req = form.querySelector('[data-token-req]');
      if (req) req.hidden = true;
      var hint = form.querySelector('[data-token-hint]');
      if (hint) hint.textContent = '留空保持原 Token；填写则会先验证再保存。';
    });
  }

  function acctRemove(id) {
    var a = findAccount(id);
    if (!a) return;
    confirmAction('删除账户', '将删除「' + (a.label || a.username) + '」及其 Token，该账户下的域名会从列表中消失。', '删除', function () {
      postJSON('/api/accounts', { action: 'remove', id: id }).then(function (data) {
        toast('ok', data.message || '已删除');
        reloadSoon();
      }).catch(function (err) { toast('warn', err.message); });
    });
  }

  function acctToggle(id) {
    postJSON('/api/accounts', { action: 'toggle', id: id }).then(function (data) {
      toast('ok', data.message || '已更新');
      reloadSoon();
    }).catch(function (err) { toast('warn', err.message); });
  }

  function acctTest(id) {
    toast('info', '正在测试连接…');
    postJSON('/api/accounts', { action: 'test', id: id }).then(function (data) {
      var r = data.result || {};
      toast(r.ok ? 'ok' : 'warn', (r.ok ? '连接正常：' : '连接失败：') + (r.username || '') + (r.error ? '（' + r.error + '）' : ''));
    }).catch(function (err) { toast('warn', err.message); });
  }

  function acctTestAll() {
    toast('info', '正在逐个测试…');
    postJSON('/api/accounts', { action: 'test-all' }).then(function (data) {
      var list = data.results || [];
      var bad = list.filter(function (r) { return !r.ok; });
      if (!bad.length) toast('ok', '全部 ' + list.length + ' 个账户连接正常');
      else toast('warn', bad.length + '/' + list.length + ' 个异常：' + bad.map(function (r) { return r.username; }).join('、'));
    }).catch(function (err) { toast('warn', err.message); });
  }

  function acctImport() {
    confirmAction('导入环境变量账户', '将把 CF_API_KEYS / USERNAMES 里的账户复制到 KV，之后即可在页面上编辑。已存在的不会重复导入。', '导入', function () {
      postJSON('/api/accounts', { action: 'import' }).then(function (data) {
        toast('ok', data.message || '已导入');
        reloadSoon();
      }).catch(function (err) { toast('warn', err.message); });
    });
  }

  /* ---------------- DNSHE ---------------- */
  function findDnshe(id) {
    for (var i = 0; i < DNSHE.length; i++) {
      if (DNSHE[i].id === id) return DNSHE[i];
    }
    return null;
  }

  function dnsheAdd() {
    openModal('tpl-dnshe', function (m) {
      m.querySelector('[data-field="mode"]').textContent = '添加 DNSHE 凭证';
    });
  }

  function dnsheEdit(id) {
    var c = findDnshe(id);
    if (!c) return;
    openModal('tpl-dnshe', function (m) {
      var form = m.querySelector('form');
      form.setAttribute('data-credential-id', id);
      m.querySelector('[data-field="mode"]').textContent = '编辑 ' + c.label;
      form.querySelector('[name="label"]').value = c.label || '';
      form.querySelector('[name="key"]').value = c.keyMasked || '';
      var secret = form.querySelector('[name="secret"]');
      secret.placeholder = '留空表示不修改（当前 ' + (c.secretMasked || '') + '）';
      var req = form.querySelector('[data-secret-req]');
      if (req) req.hidden = true;
      var hint = form.querySelector('[data-secret-hint]');
      if (hint) hint.textContent = '留空保持原 Secret；填写则替换。';
    });
  }

  function dnsheRemove(id) {
    var c = findDnshe(id);
    if (!c) return;
    confirmAction('删除凭证', '删除后「' + c.label + '」不再参与 DNSHE 查询。', '删除', function () {
      postJSON('/api/dnshe', { action: 'remove', id: id }).then(function (data) {
        toast('ok', data.message || '已删除');
        reloadSoon();
      }).catch(function (err) { toast('warn', err.message); });
    });
  }

  function dnsheToggle(id) {
    postJSON('/api/dnshe', { action: 'toggle', id: id }).then(function (data) {
      toast('ok', data.message || '已更新');
      reloadSoon();
    }).catch(function (err) { toast('warn', err.message); });
  }

  function dnsheTest(id) {
    toast('info', '正在验证凭证…');
    postJSON('/api/dnshe', { action: 'test', id: id }).then(function (data) {
      var r = data.result || {};
      toast(r.ok ? 'ok' : 'warn', r.ok ? '凭证可用' : ('凭证不可用：' + (r.error || '未知原因')));
    }).catch(function (err) { toast('warn', err.message); });
  }

  /* ---------------- 通知 ---------------- */
  function typeDef(key) {
    for (var i = 0; i < TYPES.length; i++) {
      if (TYPES[i].key === key) return TYPES[i];
    }
    return null;
  }

  function renderChannelFields(modal, type, values) {
    var box = modal.querySelector('[data-channel-fields]');
    var desc = modal.querySelector('[data-channel-desc]');
    if (!box) return;
    box.innerHTML = '';
    var def = typeDef(type);
    if (!def) { if (desc) desc.textContent = ''; return; }
    if (desc) desc.textContent = def.desc || '';

    def.fields.forEach(function (f) {
      var wrap = document.createElement('label');
      wrap.className = 'frow';
      var label = document.createElement('span');
      label.textContent = f.label + (f.required ? ' *' : '');
      var input = document.createElement('input');
      input.className = 'input';
      input.name = 'cfg_' + f.name;
      input.autocomplete = 'off';

      var current = values ? values[f.name] : '';
      if (current && String(current).indexOf('••') !== -1) {
        // 掩码值不能回填：回填后再提交等于把掩码当成真值
        input.placeholder = '已设置，留空不修改';
      } else {
        input.placeholder = f.placeholder || '';
        if (current) input.value = current;
      }

      wrap.appendChild(label);
      wrap.appendChild(input);
      box.appendChild(wrap);
    });
  }

  function chAdd() {
    openModal('tpl-channel', function (m) {
      var select = m.querySelector('[data-channel-type]');
      select.innerHTML = TYPES.map(function (t) {
        return '<option value="' + esc(t.key) + '">' + esc(t.label) + '</option>';
      }).join('');
      m.querySelector('[data-field="mode"]').textContent = '添加通知渠道';
      renderChannelFields(m, select.value, null);
    });
  }

  function findChannel(id) {
    for (var i = 0; i < CHANNELS.length; i++) {
      if (CHANNELS[i].id === id) return CHANNELS[i];
    }
    return null;
  }

  function chEdit(id) {
    var c = findChannel(id);
    if (!c) return;
    openModal('tpl-channel', function (m) {
      var form = m.querySelector('form');
      form.setAttribute('data-channel-id', id);
      m.querySelector('[data-field="mode"]').textContent = '编辑 ' + c.label;

      var select = m.querySelector('[data-channel-type]');
      select.innerHTML = TYPES.map(function (t) {
        return '<option value="' + esc(t.key) + '"' + (t.key === c.type ? ' selected' : '') + '>' + esc(t.label) + '</option>';
      }).join('');

      form.querySelector('[name="label"]').value = c.label || '';
      var enabled = form.querySelector('[name="enabled"]');
      if (enabled) enabled.checked = c.enabled !== false;

      renderChannelFields(m, c.type, c.config || {});
    });
  }

  function chRemove(id) {
    var c = findChannel(id);
    if (!c) return;
    confirmAction('删除渠道', '删除后「' + c.label + '」不再接收到期提醒。', '删除', function () {
      postJSON('/api/notify', { action: 'channel-remove', id: id }).then(function (data) {
        toast('ok', data.message || '已删除');
        reloadSoon();
      }).catch(function (err) { toast('warn', err.message); });
    });
  }

  function chToggle(id) {
    postJSON('/api/notify', { action: 'channel-toggle', id: id }).then(function (data) {
      toast('ok', data.message || '已更新');
      reloadSoon();
    }).catch(function (err) { toast('warn', err.message); });
  }

  function chTest(id) {
    toast('info', '正在发送测试消息…');
    postJSON('/api/notify', { action: 'test', id: id }).then(function (data) {
      var r = data.result || {};
      toast(r.ok ? 'ok' : 'warn', r.ok ? '测试消息已发送，请查看接收端' : ('发送失败：' + (r.error || '未知原因')));
      if (r.ok) reloadSoon(1200);
    }).catch(function (err) { toast('warn', err.message); });
  }

  function notifySendNow() {
    confirmAction('立即发送提醒', '将按当前规则生成摘要并推送到所有启用的渠道，忽略「内容未变」去重。', '发送', function () {
      toast('info', '正在收集域名并发送…');
      postJSON('/api/notify', { action: 'send-now' }).then(function (data) {
        var r = data.result || {};
        if (r.skipped) toast('warn', '未发送：' + (r.reason || '无内容'));
        else toast(r.failed ? 'warn' : 'ok', data.message || '已发送');
        reloadSoon(1400);
      }).catch(function (err) { toast('warn', err.message); });
    });
  }

  /* ---------------- 免费域名白名单 ---------------- */
  function fdEntry(suffix) {
    for (var i = 0; i < FREE.length; i++) {
      if (FREE[i].suffix === suffix) return FREE[i];
    }
    return null;
  }

  function toggleEndpoint(form) {
    var type = form.querySelector('[name="lookupType"]').value;
    var row = form.querySelector('[data-endpoint-row]');
    var hint = form.querySelector('[data-endpoint-hint]');
    if (!row) return;
    row.hidden = !type;
    if (hint) {
      hint.hidden = !type;
      hint.textContent = type === 'whois'
        ? 'WHOIS/TCP 端点，格式 host 或 host:port，例如 whois.pp.ua:43'
        : type === 'rdap'
          ? 'RDAP 端点，用 {domain} 占位，例如 https://rdap.example.org/domain/{domain}'
          : 'HTTP 接口，用 {domain} 占位';
    }
  }

  function fdAdd(prefill) {
    openModal('tpl-free-domain', function (m) {
      m.querySelector('[data-field="mode"]').textContent = '添加免费域名后缀';
      if (prefill) m.querySelector('[name="suffix"]').value = prefill;
      toggleEndpoint(m.querySelector('form'));
    });
  }

  function fdEdit(suffix) {
    var e = fdEntry(suffix);
    if (!e) return;
    openModal('tpl-free-domain', function (m) {
      var form = m.querySelector('form');
      form.setAttribute('data-suffix', suffix);
      m.querySelector('[data-field="mode"]').textContent = '编辑 ' + suffix;
      var sfx = form.querySelector('[name="suffix"]');
      sfx.value = e.suffix;
      sfx.readOnly = true;
      form.querySelector('[name="registrar"]').value = e.registrar === 'Unknown' ? '' : e.registrar;
      form.querySelector('[name="provider"]').value = e.provider || '';
      form.querySelector('[name="renew"]').value = e.renew;
      form.querySelector('[name="category"]').value = e.category || 'free';
      form.querySelector('[name="lookupType"]').value = e.lookup ? e.lookup.type : '';
      form.querySelector('[name="endpoint"]').value = e.lookup ? e.lookup.endpoint : '';
      form.querySelector('[name="note"]').value = e.note || '';
      toggleEndpoint(form);
    });
  }

  function fdRemove(suffix) {
    confirmAction('停用后缀', '停用 ' + suffix + ' 后，这类域名会重新按普通域名查询 WHOIS。内置项不会被删除，可随时恢复。', '停用', function () {
      postJSON('/api/free-domains', { action: 'remove', suffix: suffix }).then(function (data) {
        toast('ok', data.message || '已停用');
        reloadSoon();
      }).catch(function (err) { toast('warn', err.message); });
    });
  }

  function fdRestore(suffix) {
    postJSON('/api/free-domains', { action: 'restore', suffix: suffix }).then(function (data) {
      toast('ok', data.message || '已恢复');
      reloadSoon();
    }).catch(function (err) { toast('warn', err.message); });
  }

  function copyText(text) {
    if (!text) return;
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (e) {}
      ta.remove();
      toast('ok', '已复制：' + text);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        toast('ok', '已复制：' + text);
      }).catch(fallback);
    } else {
      fallback();
    }
  }

  /* ---------------- 导出 ---------------- */
  function exportCSV(names) {
    var list = (names && names.length) ? names.map(function (n) { return MAP[n]; }).filter(Boolean) : DOMAINS;
    if (!list.length) { toast('warn', '没有可导出的域名'); return; }
    var lines = [['域名', '账户', '注册商', '注册日期', '到期日期', '剩余天数', '状态'].join(',')];
    list.forEach(function (d) {
      var row = [d.name, d.account, d.registrar, d.registrationDate, d.expirationDate, d.status.days === null ? '' : d.status.days, d.status.label];
      lines.push(row.map(function (v) { return '"' + String(v === null || v === undefined ? '' : v).replace(/"/g, '""') + '"'; }).join(','));
    });
    var blob = new Blob(['\\ufeff' + lines.join('\\r\\n')], { type: 'text/csv;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'domains-' + fmtDate(new Date()) + '.csv';
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    toast('ok', '已导出 ' + list.length + ' 个域名');
  }

  /* ---------------- 事件 ---------------- */
  document.addEventListener('click', function (e) {
    var nav = e.target.closest('[data-view-link]');
    if (nav) { showView(nav.getAttribute('data-view-link')); return; }

    var themeBtn = e.target.closest('[data-theme-set]');
    if (themeBtn) { setTheme(themeBtn.getAttribute('data-theme-set')); return; }

    var actEl = e.target.closest('[data-action]');
    if (actEl) {
      var action = actEl.getAttribute('data-action');
      var name = actEl.getAttribute('data-name');
      var id = actEl.getAttribute('data-id');

      if (action === 'close-drawer') { closeDrawer(); return; }
      if (action === 'close-modal') { closeModal(); return; }
      if (action === 'focus-search') {
        showView('domains');
        var input = document.getElementById('q');
        if (input) setTimeout(function () { input.focus(); }, 40);
        return;
      }
      if (action === 'refresh-all') { refreshAll(); return; }
      if (action === 'reload-page') { location.reload(); return; }
      if (action === 'refresh-one') { refreshOne(name); return; }
      if (action === 'renew') { renewOne(name); return; }
      if (action === 'edit') { closeDrawer(); editDomain(name); return; }
      if (action === 'delete') { deleteDomain(name); return; }
      if (action === 'add-domain') { addDomain(); return; }
      if (action === 'manual-query') { manualQuery(); return; }
      if (action === 'whois-refresh') { refreshWhois(name); return; }
      if (action === 'export') { exportCSV(); return; }
      if (action === 'export-selected') { exportCSV(state.sel); return; }
      if (action === 'renew-selected') { renewMany(state.sel.slice()); return; }
      if (action === 'renew-expiring') {
        var names = DOMAINS.filter(function (d) { return d.status.days !== null && d.status.days >= 0 && d.status.days <= 90; })
          .map(function (d) { return d.name; });
        renewMany(names);
        return;
      }
      if (action === 'clear-selection') { state.sel = []; syncCheckboxes(); updateBulk(); return; }
      if (action === 'fd-add') { fdAdd(''); return; }
      if (action === 'fd-edit') { fdEdit(actEl.getAttribute('data-suffix')); return; }
      if (action === 'fd-remove') { fdRemove(actEl.getAttribute('data-suffix')); return; }
      if (action === 'fd-restore') { fdRestore(actEl.getAttribute('data-suffix')); return; }
      if (action === 'fd-discover') { fdAdd(actEl.getAttribute('data-suffix')); return; }
      if (action === 'copy-text') { copyText(actEl.getAttribute('data-copy')); return; }
      if (action === 'open') { openDrawer(name); return; }

      // 账户
      if (action === 'acct-add') { acctAdd(); return; }
      if (action === 'acct-edit') { acctEdit(id); return; }
      if (action === 'acct-remove') { acctRemove(id); return; }
      if (action === 'acct-toggle') { acctToggle(id); return; }
      if (action === 'acct-test') { acctTest(id); return; }
      if (action === 'acct-test-all') { acctTestAll(); return; }
      if (action === 'acct-import') { acctImport(); return; }

      // DNSHE
      if (action === 'dnshe-add') { dnsheAdd(); return; }
      if (action === 'dnshe-edit') { dnsheEdit(id); return; }
      if (action === 'dnshe-remove') { dnsheRemove(id); return; }
      if (action === 'dnshe-toggle') { dnsheToggle(id); return; }
      if (action === 'dnshe-test') { dnsheTest(id); return; }

      // 通知
      if (action === 'ch-add') { chAdd(); return; }
      if (action === 'ch-edit') { chEdit(id); return; }
      if (action === 'ch-remove') { chRemove(id); return; }
      if (action === 'ch-toggle') { chToggle(id); return; }
      if (action === 'ch-test') { chTest(id); return; }
      if (action === 'notify-send-now') { notifySendNow(); return; }

      if (action === 'clear-cache') {
        confirmAction('清除全部缓存', '将清空 WHOIS 缓存，下次访问会重新查询，耗时较长。', '清除', function () {
          postJSON('/api/update', { action: 'clear-cache' }).then(function (data) {
            toast('ok', data.message || '缓存已清除');
          }).catch(function (err) { toast('warn', err.message); });
        });
        return;
      }
      if (action === 'reset-filters') {
        state.q = ''; state.group = 'all'; state.account = 'all'; state.page = 1;
        var q = document.getElementById('q'); if (q) q.value = '';
        var acc = document.getElementById('accountFilter'); if (acc) acc.value = 'all';
        $$('.chip').forEach(function (c) { c.classList.toggle('on', c.getAttribute('data-group') === 'all'); });
        applyTable();
        return;
      }
      return;
    }

    var chip = e.target.closest('.chip[data-group]');
    if (chip) {
      state.group = chip.getAttribute('data-group');
      state.page = 1;
      $$('.chip').forEach(function (c) { c.classList.toggle('on', c === chip); });
      applyTable();
      return;
    }

    var th = e.target.closest('th[data-sort]');
    if (th) {
      var key = th.getAttribute('data-sort');
      if (key === 'days') state.sort = state.sort === 'days-asc' ? 'days-desc' : 'days-asc';
      else state.sort = key;
      state.page = 1;
      applyTable();
      return;
    }

    var pg = e.target.closest('[data-page]');
    if (pg) {
      var v = pg.getAttribute('data-page');
      var pages = Math.max(1, Math.ceil(filteredRows().length / PAGE_SIZE));
      if (v === 'prev') state.page = Math.max(1, state.page - 1);
      else if (v === 'next') state.page = Math.min(pages, state.page + 1);
      else state.page = Number(v);
      applyTable();
      return;
    }

    var row = e.target.closest('tr.row');
    if (row) {
      if (e.target.closest('.rowcb') || e.target.closest('.rowact') || e.target.closest('button')) return;
      openDrawer(row.getAttribute('data-name'));
    }
  });

  document.addEventListener('input', function (e) {
    if (e.target.id === 'q') {
      state.q = e.target.value.trim();
      state.page = 1;
      applyTable();
    }
  });

  document.addEventListener('change', function (e) {
    var t = e.target;
    if (t.id === 'accountFilter') { state.account = t.value; state.page = 1; applyTable(); return; }
    if (t.id === 'sortSelect') { state.sort = t.value; state.page = 1; applyTable(); return; }
    if (t.name === 'lookupType' && t.form) { toggleEndpoint(t.form); return; }
    if (t.hasAttribute('data-channel-type')) {
      var modal = document.getElementById('modal');
      if (modal) renderChannelFields(modal, t.value, null);
      return;
    }
    if (t.name === 'renew' && t.form) {
      // 永久域名一定属于公益类，切换续期模式时同步类型，避免出现「免费 + 永久」这种矛盾组合
      var cat = t.form.querySelector('[name="category"]');
      if (cat) cat.value = t.value === 'permanent' ? 'public' : 'free';
      return;
    }
    if (t.id === 'selAll') {
      var pageRows = rows.filter(function (r) { return !r.hidden; });
      pageRows.forEach(function (r) {
        var n = r.getAttribute('data-name');
        var idx = state.sel.indexOf(n);
        if (t.checked && idx === -1) state.sel.push(n);
        if (!t.checked && idx !== -1) state.sel.splice(idx, 1);
      });
      syncCheckboxes();
      updateBulk();
      return;
    }
    if (t.classList.contains('rowcb')) {
      var name = t.getAttribute('data-name');
      var i = state.sel.indexOf(name);
      if (t.checked && i === -1) state.sel.push(name);
      if (!t.checked && i !== -1) state.sel.splice(i, 1);
      updateBulk();
    }
  });

  document.addEventListener('submit', function (e) {
    var form = e.target.closest('form[data-form]');
    if (!form) return;
    e.preventDefault();
    var type = form.getAttribute('data-form');
    var btn = form.querySelector('button[type="submit"]');
    if (btn) { btn.disabled = true; }

    function done() { if (btn) btn.disabled = false; }
    function fail(err) { done(); showFormError(form, err.message || String(err)); }

    if (type === 'add-domain') {
      var domain = form.querySelector('[name="domain"]').value.trim().toLowerCase();
      if (!domain) { fail(new Error('请输入域名')); return; }
      var notes = form.querySelector('[name="notes"]').value.trim();
      // 这一步会真去查 WHOIS，DNSHE 那边可能要等一两秒，按钮得给个反馈
      if (btn) btn.textContent = '查询中…';
      postJSON('/api/custom-domains', {
        action: 'add',
        domain: domain,
        info: { notes: notes }
      }).then(function (data) {
        done();
        if (btn) btn.textContent = '添加并查询';
        closeModal();
        var rec = data.record || {};
        if (data.needsManual) {
          // 查不到就别让人对着空列表猜：直接把补填表单弹出来
          toast('warn', '已添加 ' + domain + '，没查到到期信息');
          editDomain(domain, {
            registrar: rec.registrar || 'Unknown',
            registrationDate: rec.registrationDate || 'Unknown',
            expirationDate: rec.expirationDate || 'Unknown',
            notes: rec.notes || notes,
            lookupStatus: rec.lookupStatus || 'missing',
            lookupError: rec.lookupError || '',
            isCustom: true,
            plan: ''
          });
        } else {
          toast('ok', data.message || ('已添加 ' + domain));
          reloadSoon(900);
        }
      }).catch(function (err) {
        if (btn) btn.textContent = '添加并查询';
        fail(err);
      });
      return;
    }

    if (type === 'edit-domain') {
      var target = form.getAttribute('data-domain');
      postJSON('/api/custom-domains', {
        action: 'update',
        domain: target,
        info: {
          registrar: form.querySelector('[name="registrar"]').value.trim() || 'Unknown',
          serviceProvider: form.querySelector('[name="serviceProvider"]').value.trim(),
          registrationDate: form.querySelector('[name="registrationDate"]').value || 'Unknown',
          expirationDate: form.querySelector('[name="expirationDate"]').value || 'Unknown',
          notes: form.querySelector('[name="notes"]').value.trim()
        }
      }).then(function () {
        toast('ok', target + ' 已更新');
        reloadSoon(800);
      }).catch(fail);
      return;
    }

    if (type === 'manual-query') {
      var qd = form.querySelector('[name="domain"]').value.trim();
      var force = form.querySelector('[name="force"]').checked;
      if (!qd) { fail(new Error('请输入域名')); return; }
      postJSON('/api/manual-query', { domain: qd, forceRefresh: force }).then(function (data) {
        done();
        var box = form.querySelector('[data-result]');
        var body = form.querySelector('[data-result-body]');
        box.hidden = false;
        var lines = [];
        ['registrar', 'registrationDate', 'expirationDate'].forEach(function (k) {
          if (data[k]) lines.push(k + ': ' + data[k]);
        });
        if (data.whoisError) lines.push('error: ' + data.whoisError);
        body.textContent = lines.length ? lines.join('\\n') : JSON.stringify(data, null, 2);
      }).catch(fail);
      return;
    }

    if (type === 'account') {
      var acctId = form.getAttribute('data-account-id');
      var payload = {
        action: acctId ? 'update' : 'add',
        id: acctId || undefined,
        label: form.querySelector('[name="label"]').value.trim(),
        username: form.querySelector('[name="username"]').value.trim(),
        token: form.querySelector('[name="token"]').value.trim(),
        note: form.querySelector('[name="note"]').value.trim()
      };
      if (!payload.username) { fail(new Error('请填写账户标识')); return; }
      if (!acctId && !payload.token) { fail(new Error('请填写 API Token')); return; }
      postJSON('/api/accounts', payload).then(function (data) {
        toast('ok', data.message || '已保存');
        closeModal();
        reloadSoon();
      }).catch(fail);
      return;
    }

    if (type === 'dnshe') {
      var credId = form.getAttribute('data-credential-id');
      postJSON('/api/dnshe', {
        action: credId ? 'update' : 'add',
        id: credId || undefined,
        label: form.querySelector('[name="label"]').value.trim(),
        key: form.querySelector('[name="key"]').value.trim(),
        secret: form.querySelector('[name="secret"]').value.trim()
      }).then(function (data) {
        var msg = data.message || '已保存';
        // 服务端会顺手清掉这些域名的旧缓存，告诉用户一声，免得以为没生效
        if (data.purged) msg += '，已清掉 ' + data.purged + ' 条旧缓存';
        toast('ok', msg);
        closeModal();
        reloadSoon();
      }).catch(fail);
      return;
    }

    if (type === 'channel') {
      var chId = form.getAttribute('data-channel-id');
      var chType = form.querySelector('[name="type"]').value;
      var config = {};
      $$('[data-channel-fields] input', form).forEach(function (input) {
        var key = input.name.replace(/^cfg_/, '');
        var value = input.value.trim();
        // 留空不提交，服务端会保留原值（编辑时用于"不修改密钥"）
        if (value) config[key] = value;
      });
      postJSON('/api/notify', {
        action: chId ? 'channel-update' : 'channel-add',
        id: chId || undefined,
        type: chType,
        label: form.querySelector('[name="label"]').value.trim(),
        enabled: form.querySelector('[name="enabled"]').checked,
        config: config
      }).then(function (data) {
        toast('ok', data.message || '已保存');
        closeModal();
        reloadSoon();
      }).catch(fail);
      return;
    }

    if (type === 'settings') {
      var settings = {
        whoisProxy: form.querySelector('[name="whoisProxy"]').value.trim(),
        freeDomainLookupTimeout: form.querySelector('[name="freeDomainLookupTimeout"]').value,
        freeDomainLookupUa: form.querySelector('[name="freeDomainLookupUa"]').value.trim(),
        freeDomainLiveLookup: form.querySelector('[name="freeDomainLiveLookup"]').checked,
        sessionHours: form.querySelector('[name="sessionHours"]').value,
        paceDnshe: form.querySelector('[name="paceDnshe"]').value,
        paceWhois: form.querySelector('[name="paceWhois"]').value,
        paceRdap: form.querySelector('[name="paceRdap"]').value
      };
      var ap = form.querySelector('[name="accessPassword"]').value;
      var adm = form.querySelector('[name="adminPassword"]').value;
      var ts = form.querySelector('[name="tokenSecret"]').value;
      if (ap) settings.accessPassword = ap;
      if (adm) settings.adminPassword = adm;
      if (ts) settings.tokenSecret = ts;

      postJSON('/api/settings', { action: 'save', settings: settings }).then(function (data) {
        done();
        toast('ok', data.message || '设置已保存');
        reloadSoon(900);
      }).catch(fail);
      return;
    }

    if (type === 'notify-rules') {
      postJSON('/api/notify', {
        action: 'save-rules',
        enabled: form.querySelector('[name="enabled"]').checked,
        daysBefore: form.querySelector('[name="daysBefore"]').value,
        includeExpired: form.querySelector('[name="includeExpired"]').checked,
        timezoneOffset: form.querySelector('[name="timezoneOffset"]').value
      }).then(function (data) {
        done();
        toast('ok', data.message || '已保存');
      }).catch(fail);
      return;
    }

    if (type === 'free-domain') {
      var sfx = form.querySelector('[name="suffix"]').value.trim().toLowerCase();
      if (!sfx) { fail(new Error('请输入后缀')); return; }
      var existing = form.getAttribute('data-suffix');
      postJSON('/api/free-domains', {
        action: existing ? 'update' : 'add',
        suffix: sfx,
        registrar: form.querySelector('[name="registrar"]').value.trim(),
        provider: form.querySelector('[name="provider"]').value.trim(),
        renew: form.querySelector('[name="renew"]').value,
        category: form.querySelector('[name="category"]').value,
        lookupType: form.querySelector('[name="lookupType"]').value,
        endpoint: form.querySelector('[name="endpoint"]').value.trim(),
        note: form.querySelector('[name="note"]').value.trim()
      }).then(function (data) {
        toast('ok', data.message || '已保存');
        reloadSoon();
      }).catch(fail);
    }
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      var drawer = document.getElementById('drawer');
      if (drawer && drawer.classList.contains('on')) { closeDrawer(); return; }
      if (state.q) {
        state.q = '';
        var q = document.getElementById('q');
        if (q) q.value = '';
        applyTable();
      }
      return;
    }
    var tag = document.activeElement ? document.activeElement.tagName : '';
    if (e.key === '/' && ['INPUT', 'TEXTAREA', 'SELECT'].indexOf(tag) === -1) {
      e.preventDefault();
      showView('domains');
      setTimeout(function () { var q = document.getElementById('q'); if (q) q.focus(); }, 40);
    }
  });

  /* ---------------- 初始化 ---------------- */
  function init() {
    try {
      var params = new URLSearchParams(location.search);
      var forced = params.get('theme');
      var saved = localStorage.getItem('dsmc-theme') || localStorage.getItem('dk-theme');
      if (forced) setTheme(forced);
      else if (saved) setTheme(saved);
      else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) setTheme('light');
    } catch (e) {}

    initRows();
    applyTable();

    // 弹窗按 Esc 或点遮罩由浏览器自己关闭，不会走 closeModal，这里兜底解锁滚动
    var dlg = document.getElementById('modal');
    if (dlg) dlg.addEventListener('close', syncScrollLock);

    var hash = (location.hash || '').replace('#', '');
    if (META[hash]) showView(hash);
    else showView('overview');

    try {
      var open = new URLSearchParams(location.search).get('open');
      if (open && MAP[open]) openDrawer(open);
    } catch (e) {}
  }

  window.addEventListener('hashchange', function () {
    var hash = (location.hash || '').replace('#', '');
    if (META[hash] && hash !== state.view) showView(hash);
  });

  init();
})();
`;
}
