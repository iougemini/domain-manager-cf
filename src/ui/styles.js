// 设计令牌 + 组件样式（自包含，不依赖 Bootstrap / FontAwesome）
export const CSS = `
*,*::before,*::after{box-sizing:border-box}
:root{
  --font:"Inter","SF Pro Text",-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  --mono:"SFMono-Regular",ui-monospace,"JetBrains Mono",Consolas,monospace;
  --r-lg:14px;--r-md:10px;--r-sm:8px;
  --t:160ms cubic-bezier(.2,.7,.3,1);
}
html[data-theme="dark"]{
  --bg:#070A0F;--bg-2:#0B1017;--surface:#0F1620;--surface-2:#131C27;--surface-3:#18222F;
  --border:rgba(255,255,255,.07);--border-2:rgba(255,255,255,.13);
  --text:#E8EFF7;--text-2:#9BAABC;--text-3:#7C8CA0;
  --accent:#4C8DFF;--accent-2:#7FAEFF;--accent-soft:rgba(76,141,255,.13);
  --ok:#3DDC97;--ok-soft:rgba(61,220,151,.12);
  --warn:#F5B942;--warn-soft:rgba(245,185,66,.13);
  --danger:#FB7185;--danger-soft:rgba(251,113,133,.13);
  --violet:#A78BFA;--violet-soft:rgba(167,139,250,.13);
  --shadow:0 20px 44px -20px rgba(0,0,0,.9);
  --glow:radial-gradient(1100px 520px at 72% -12%,rgba(76,141,255,.10),transparent 62%);
  --hero-glow:radial-gradient(520px 200px at 0% 0%,rgba(245,185,66,.10),transparent 72%);
  --topbar:rgba(7,10,15,.78);
  --chevron:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%237C8CA0' stroke-width='2'><path d='M6 9l6 6 6-6'/></svg>");
  color-scheme:dark;
}
html[data-theme="light"]{
  --bg:#F5F7FA;--bg-2:#FFFFFF;--surface:#FFFFFF;--surface-2:#F7F9FC;--surface-3:#EDF1F7;
  --border:#E4EAF2;--border-2:#D3DDEA;
  --text:#0E1A2B;--text-2:#586A7E;--text-3:#6B7B8E;
  --accent:#2563EB;--accent-2:#1D4ED8;--accent-soft:rgba(37,99,235,.08);
  --ok:#0E9F6E;--ok-soft:rgba(14,159,110,.10);
  --warn:#B45309;--warn-soft:rgba(245,158,11,.14);
  --danger:#DC2626;--danger-soft:rgba(220,38,38,.09);
  --violet:#7C3AED;--violet-soft:rgba(124,58,237,.09);
  --shadow:0 12px 30px -14px rgba(15,26,43,.22);
  --glow:radial-gradient(900px 420px at 80% -10%,rgba(37,99,235,.07),transparent 62%);
  --hero-glow:radial-gradient(520px 200px at 0% 0%,rgba(245,158,11,.07),transparent 72%);
  --topbar:rgba(255,255,255,.82);
  --chevron:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%236B7B8E' stroke-width='2'><path d='M6 9l6 6 6-6'/></svg>");
  color-scheme:light;
}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
body::before{content:'';position:fixed;inset:0;background:var(--glow);pointer-events:none;z-index:0}
button{font:inherit;color:inherit;background:none;border:0;cursor:pointer;padding:0}
input,select,textarea{font:inherit;color:inherit}
a{color:inherit;text-decoration:none}
h1,h2,h3,h4,p{margin:0}
[hidden]{display:none!important}
::selection{background:var(--accent-soft)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:6px}
.i{flex:none;display:block}
.mono{font-family:var(--mono);font-size:12px;font-variant-numeric:tabular-nums}
.dim{color:var(--text-2)}
.right{text-align:right}

/* Shell */
.app{position:relative;z-index:1;display:grid;grid-template-columns:232px minmax(0,1fr);min-height:100vh}
.rail{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;padding:18px 12px 14px;border-right:1px solid var(--border);background:linear-gradient(180deg,var(--bg-2),var(--bg));overflow-y:auto;overscroll-behavior:contain}
.brand{display:flex;align-items:center;gap:10px;padding:2px 8px 16px}
.mark{width:32px;height:32px;border-radius:9px;display:grid;place-items:center;color:#fff;background:linear-gradient(160deg,#5F9BFF,#2F6BE8);box-shadow:0 8px 18px -8px rgba(76,141,255,.9)}
.brand b{display:block;font-size:13.5px;font-weight:600;letter-spacing:-.01em}
.brand small{display:block;font-size:10px;color:var(--text-3);letter-spacing:.06em}
.nav-label{font-size:10px;color:var(--text-3);letter-spacing:.09em;text-transform:uppercase;padding:14px 10px 6px;font-weight:500}
.nav-item{display:flex;align-items:center;gap:10px;width:100%;padding:9px 10px;border-radius:9px;color:var(--text-2);font-size:13.5px;transition:background var(--t),color var(--t);text-align:left}
.nav-item svg{color:var(--text-3);transition:color var(--t)}
.nav-item:hover{background:var(--surface-2);color:var(--text)}
.nav-item:hover svg{color:var(--text-2)}
.nav-item.active{background:var(--accent-soft);color:var(--text);box-shadow:inset 0 0 0 1px rgba(76,141,255,.22)}
.nav-item.active svg{color:var(--accent-2)}
.badge{margin-left:auto;font-style:normal;font-size:11px;padding:1px 6px;border-radius:999px;background:var(--surface-3);color:var(--text-2);font-variant-numeric:tabular-nums;font-weight:500}
.badge.warn{background:var(--warn-soft);color:var(--warn)}
.rail-foot{margin-top:auto;display:grid;gap:10px}
.theme-toggle{display:grid;grid-template-columns:1fr 1fr;gap:3px;background:var(--surface-2);border:1px solid var(--border);padding:3px;border-radius:9px}
.theme-toggle button{display:flex;align-items:center;justify-content:center;gap:6px;padding:6px 0;border-radius:6px;font-size:11.5px;color:var(--text-3);transition:all var(--t)}
.theme-toggle button.on{background:var(--surface-3);color:var(--text)}
.user{display:flex;align-items:center;gap:9px;padding:6px 8px;border-radius:9px}
.avatar{width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,#7C5CFF,#4C8DFF);display:grid;place-items:center;font-size:11px;font-weight:600;color:#fff;flex:none}
.user b{display:block;font-size:12.5px;font-weight:500}
.user small{display:block;font-size:10.5px;color:var(--text-3)}

.main{min-width:0;display:flex;flex-direction:column}
.topbar{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:16px;padding:14px 26px;border-bottom:1px solid var(--border);background:var(--topbar);backdrop-filter:blur(14px) saturate(140%)}
.topbar h1{font-size:16.5px;font-weight:600;letter-spacing:-.015em}
.topbar p{margin-top:2px;font-size:11.5px;color:var(--text-3)}
.topbar-actions{margin-left:auto;display:flex;align-items:center;gap:8px}
.content{padding:20px 26px 8px;width:100%;max-width:1560px;margin:0 auto;flex:1 1 auto}

/* Buttons */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;height:34px;padding:0 13px;border-radius:8px;font-size:13px;font-weight:500;border:1px solid var(--border-2);background:var(--surface-2);color:var(--text);transition:background var(--t),border-color var(--t);white-space:nowrap;text-decoration:none}
.btn:hover{background:var(--surface-3)}
.btn.primary{background:linear-gradient(180deg,#5A97FF,#3C7CF5);border-color:#3C7CF5;color:#fff;box-shadow:0 8px 20px -10px rgba(76,141,255,.95)}
.btn.primary:hover{filter:brightness(1.07)}
.btn.ghost{background:transparent}
.btn.ghost:hover{background:var(--surface-2)}
.btn.sm{height:28px;padding:0 10px;font-size:12px;border-radius:7px}
.btn.icon{width:34px;padding:0}
.icon-btn{width:28px;height:28px;border-radius:7px;display:inline-grid;place-items:center;color:var(--text-3);transition:all var(--t)}
.icon-btn:hover{background:var(--surface-3);color:var(--text)}

/* Cards */
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.span2{grid-column:span 2}
.span3{grid-column:span 3}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);overflow:hidden}
.card-head{display:flex;align-items:center;gap:10px;padding:15px 18px 0}
.card-head h3{font-size:13.5px;font-weight:600;letter-spacing:-.01em}
.card-head .sub{margin-left:auto;font-size:11.5px;color:var(--text-3);display:inline-flex;align-items:center;gap:4px}
.card-body{padding:14px 18px 18px}

/* Hero */
.hero{grid-column:span 2;display:grid;grid-template-columns:1.3fr .7fr;background:var(--hero-glow),var(--surface)}
.hero-main{padding:20px 22px}
.eyebrow{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;font-weight:500;color:var(--warn);background:var(--warn-soft);padding:3px 9px;border-radius:999px}
.eyebrow.ok{color:var(--ok);background:var(--ok-soft)}
.hero-num{font-size:42px;line-height:1.05;font-weight:650;letter-spacing:-.035em;margin:14px 0 4px;font-variant-numeric:tabular-nums}
.hero-num span{font-size:13px;font-weight:500;color:var(--text-2);margin-left:9px;letter-spacing:0}
.hero-sub{font-size:12.5px;color:var(--text-2);max-width:430px}
.hero-sub b{color:var(--text);font-weight:600}
.hero-actions{display:flex;gap:8px;margin-top:18px;flex-wrap:wrap}
.hero-side{border-left:1px solid var(--border);display:grid;align-content:center;gap:1px;padding:14px}
.mini{display:flex;align-items:center;gap:11px;padding:10px 12px;border-radius:9px;cursor:pointer;transition:background var(--t);text-align:left;width:100%}
.mini:hover{background:var(--surface-2)}
.mini b{display:block;font-size:15px;font-weight:600;font-variant-numeric:tabular-nums;line-height:1.25}
.mini small{display:block;font-size:11.5px;color:var(--text-3)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--text-3);flex:none}
.dot.ok{background:var(--ok);box-shadow:0 0 0 3px var(--ok-soft)}
.dot.warn{background:var(--warn);box-shadow:0 0 0 3px var(--warn-soft)}
.dot.danger{background:var(--danger);box-shadow:0 0 0 3px var(--danger-soft)}
.dot.violet{background:var(--violet);box-shadow:0 0 0 3px var(--violet-soft)}

/* Donut */
.donut-body{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.donut-wrap{position:relative;width:132px;height:132px;flex:none}
.donut{width:132px;height:132px;display:block}
.donut-center{position:absolute;inset:0;display:grid;place-content:center;text-align:center}
.donut-center b{display:block;font-size:22px;font-weight:650;letter-spacing:-.03em;font-variant-numeric:tabular-nums;line-height:1.1}
.donut-center small{font-size:10.5px;color:var(--text-3)}
.legend{list-style:none;margin:0;padding:0;display:grid;gap:7px;flex:1;min-width:120px}
.legend li{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text-2)}
.legend i{width:7px;height:7px;border-radius:2px;flex:none}
.legend b{margin-left:auto;color:var(--text);font-weight:550;font-variant-numeric:tabular-nums}

/* Bars */
.bars{display:flex;align-items:flex-end;gap:6px;height:150px;padding-top:14px}
.bar-col{flex:1;min-width:0;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;gap:6px;height:100%}
.bar-val{font-size:10.5px;color:var(--text-2);font-variant-numeric:tabular-nums;line-height:1}
.bar{width:100%;max-width:26px;border-radius:4px 4px 2px 2px;background:var(--text-3);opacity:.24;min-height:3px;transition:background var(--t)}
.bar.hot{background:linear-gradient(180deg,var(--warn),rgba(245,185,66,.35));opacity:1}
.bar.zero{opacity:.12}
.bar-label{font-size:10px;color:var(--text-3);font-variant-numeric:tabular-nums;white-space:nowrap}
.bars-note{display:flex;align-items:center;gap:14px;margin-top:12px;font-size:11px;color:var(--text-3)}
.bars-note span{display:inline-flex;align-items:center;gap:5px}
.bars-note i{width:8px;height:8px;border-radius:2px}

/* Account list */
.acct-list{list-style:none;margin:0;padding:0;display:grid;gap:2px}
.acct-item{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:10px;padding:9px 8px;border-radius:9px}
.acct-item:hover{background:var(--surface-2)}
.acct-item b{font-size:12.5px;font-weight:500;display:block}
.acct-item small{font-size:10.5px;color:var(--text-3)}
.acct-item .num{font-size:12px;color:var(--text-2);font-variant-numeric:tabular-nums}

/* Table */
.table-wrap{overflow-x:auto}
.table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px}
.table thead th{text-align:left;font-size:10.5px;font-weight:500;letter-spacing:.06em;text-transform:uppercase;color:var(--text-3);padding:9px 12px;background:var(--surface-2);border-bottom:1px solid var(--border);white-space:nowrap}
.table thead th.sortable{cursor:pointer;user-select:none}
.table thead th.sortable:hover{color:var(--text-2)}
.table thead th .arw{display:inline-block;margin-left:4px;opacity:.55;font-size:9px}
.table tbody td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:middle}
.table tbody tr{transition:background var(--t);cursor:pointer}
.table tbody tr:hover td{background:var(--surface-2)}
.table tbody tr:last-child td{border-bottom:0}
.table .cb{width:36px;padding-right:0}
input[type="checkbox"]{width:15px;height:15px;accent-color:var(--accent);cursor:pointer;margin:0}
.dom{display:flex;align-items:center;gap:10px;min-width:0}
.dom>div{min-width:0}
.favi{width:26px;height:26px;border-radius:7px;display:grid;place-items:center;font-size:11px;font-weight:600;background:var(--surface-3);color:var(--text-2);border:1px solid var(--border);flex:none;text-transform:uppercase}
.dom b{display:block;font-size:13px;font-weight:550;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dom small{display:block;font-size:10.5px;color:var(--text-3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pill{display:inline-flex;align-items:center;gap:5px;height:21px;padding:0 8px;border-radius:999px;font-size:11.5px;font-weight:500;border:1px solid transparent;white-space:nowrap}
.pill i{width:5px;height:5px;border-radius:50%;background:currentColor;flex:none}
.pill.ok{color:var(--ok);background:var(--ok-soft);border-color:rgba(61,220,151,.22)}
.pill.warn{color:var(--warn);background:var(--warn-soft);border-color:rgba(245,185,66,.26)}
.pill.danger{color:var(--danger);background:var(--danger-soft);border-color:rgba(251,113,133,.24)}
.pill.neutral{color:var(--text-2);background:var(--surface-3);border-color:var(--border)}
.pill.violet{color:var(--violet);background:var(--violet-soft);border-color:rgba(167,139,250,.24)}
.meter-cell{display:flex;align-items:center;gap:9px;min-width:128px}
.meter{flex:1;height:4px;border-radius:999px;background:var(--surface-3);overflow:hidden;min-width:42px}
.meter span{display:block;height:100%;border-radius:999px;background:var(--ok)}
.meter span.warn{background:var(--warn)}
.meter span.danger{background:var(--danger)}
.meter span.violet{background:var(--violet)}
.meter-cell b{font-size:11.5px;font-weight:500;color:var(--text-2);min-width:58px;text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.meter-cell b.warn{color:var(--warn)}
.meter-cell b.danger{color:var(--danger)}
.rowact{display:flex;gap:2px;justify-content:flex-end;opacity:.7;transition:opacity var(--t)}
.rowact .icon-btn{color:var(--text-2)}
tr:hover .rowact{opacity:1}

/* Toolbar */
.toolbar{display:flex;align-items:center;gap:10px;padding:13px 16px;border-bottom:1px solid var(--border);flex-wrap:wrap}
.search{display:flex;align-items:center;gap:8px;height:34px;padding:0 10px;border-radius:8px;border:1px solid var(--border);background:var(--surface-2);flex:1;min-width:200px;max-width:300px;transition:border-color var(--t),box-shadow var(--t)}
.search svg{color:var(--text-3)}
.search input{flex:1;background:none;border:0;outline:0;font-size:13px;min-width:0}
.search input::placeholder{color:var(--text-3)}
.search kbd{font:inherit;font-size:10.5px;padding:1px 5px;border-radius:4px;border:1px solid var(--border-2);color:var(--text-3);background:var(--surface)}
.search:focus-within{border-color:rgba(76,141,255,.55);box-shadow:0 0 0 3px var(--accent-soft)}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{height:30px;padding:0 11px;border-radius:999px;border:1px solid var(--border);background:transparent;color:var(--text-2);font-size:12.5px;display:inline-flex;align-items:center;gap:6px;transition:all var(--t)}
.chip:hover{background:var(--surface-2);color:var(--text)}
.chip.on{background:var(--text);color:var(--bg);border-color:var(--text)}
.chip[data-group="suspended"]{border-color:rgba(251,113,133,.45);color:var(--danger)}
.chip[data-group="suspended"]:hover{background:var(--danger-soft);color:var(--danger)}
.chip[data-group="suspended"].on{background:var(--danger);border-color:var(--danger);color:#fff}
.chip .n{font-size:10.5px;opacity:.62;font-variant-numeric:tabular-nums}
.field{height:34px;border-radius:8px;border:1px solid var(--border);background:var(--surface-2);padding:0 28px 0 10px;font-size:12.5px;color:var(--text-2);appearance:none;background-image:var(--chevron);background-repeat:no-repeat;background-position:right 9px center;cursor:pointer;max-width:180px}
.toolbar-right{margin-left:auto;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.table-foot{display:flex;align-items:center;gap:12px;padding:11px 16px;border-top:1px solid var(--border);font-size:12px;color:var(--text-3);flex-wrap:wrap}
.pager{margin-left:auto;display:flex;gap:4px;align-items:center}
.pager button{min-width:28px;height:28px;padding:0 8px;border-radius:7px;font-size:12px;color:var(--text-2);border:1px solid transparent}
.pager button:hover{background:var(--surface-2);color:var(--text)}
.pager button.on{background:var(--surface-3);border-color:var(--border-2);color:var(--text)}
.pager button:disabled{opacity:.35;cursor:not-allowed}

/* Accounts view */
.acct-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}
.acct-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:16px 16px 14px;display:grid;gap:14px}
.acct-top{display:flex;align-items:center;gap:10px}
.acct-top .favi{width:30px;height:30px;border-radius:8px}
.acct-top b{display:block;font-size:13.5px;font-weight:600}
.acct-top small{display:block;font-size:11px;color:var(--text-3)}
.acct-top .pill{margin-left:auto}
.acct-nums{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.acct-nums div{background:var(--surface-2);border:1px solid var(--border);border-radius:9px;padding:9px 10px}
.acct-nums b{display:block;font-size:18px;font-weight:600;letter-spacing:-.02em;font-variant-numeric:tabular-nums;line-height:1.2}
.acct-nums b.warn{color:var(--warn)}
.acct-nums b.danger{color:var(--danger)}
.acct-nums small{font-size:10.5px;color:var(--text-3)}
.acct-foot{display:flex;align-items:center;gap:8px;font-size:11.5px;color:var(--text-3);border-top:1px solid var(--border);padding-top:12px}
.acct-foot .btn{margin-left:auto}
.seg{display:flex;gap:2px;height:4px;border-radius:999px;overflow:hidden}
.seg i{display:block;height:100%}

/* Switch */
.switch{width:34px;height:19px;border-radius:999px;background:var(--surface-3);border:1px solid var(--border-2);position:relative;transition:background var(--t),border-color var(--t);flex:none}
.switch::after{content:'';position:absolute;top:2px;left:2px;width:13px;height:13px;border-radius:50%;background:var(--text-3);transition:left var(--t),background var(--t)}
.switch.on{background:var(--ok-soft);border-color:rgba(61,220,151,.42)}
.switch.on::after{left:17px;background:var(--ok)}

/* Drawer */
.backdrop{position:fixed;inset:0;background:rgba(3,6,10,.55);backdrop-filter:blur(2px);opacity:0;pointer-events:none;transition:opacity 200ms;z-index:40}
.backdrop.on{opacity:1;pointer-events:auto}
.drawer{position:fixed;top:0;right:0;height:100vh;height:100dvh;width:min(448px,94vw);background:var(--surface);border-left:1px solid var(--border);transform:translateX(102%);transition:transform 280ms cubic-bezier(.22,.8,.3,1);z-index:41;display:flex;flex-direction:column;box-shadow:var(--shadow)}
.drawer.on{transform:none}
.drawer-head{display:flex;align-items:flex-start;gap:10px;padding:16px 16px 14px;border-bottom:1px solid var(--border)}
.drawer-head .dom b{font-size:14.5px}
.drawer-head .pill{margin-left:auto}
.drawer-head .icon-btn{margin-left:2px}
.drawer-body{padding:16px;overflow-y:auto;flex:1}
.drawer-body h4{font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--text-3);font-weight:500;margin:20px 0 9px}
.drawer-body h4:first-child{margin-top:0}
.kv{display:grid;grid-template-columns:auto 1fr;gap:8px 14px;margin:0;font-size:12.5px}
.kv dt{color:var(--text-3)}
.kv dd{margin:0;text-align:right;color:var(--text);font-variant-numeric:tabular-nums;word-break:break-all}
.ns{display:flex;flex-wrap:wrap;gap:6px}
.ns span{font-family:var(--mono);font-size:11px;padding:4px 8px;border-radius:6px;background:var(--surface-2);border:1px solid var(--border);color:var(--text-2)}
.tl{list-style:none;margin:0;padding:0 0 0 16px;position:relative}
.tl::before{content:'';position:absolute;left:3px;top:6px;bottom:8px;width:1px;background:var(--border-2)}
.tl li{position:relative;padding-bottom:13px;font-size:11.5px;color:var(--text-3)}
.tl li:last-child{padding-bottom:0}
.tl li::before{content:'';position:absolute;left:-16px;top:4px;width:7px;height:7px;border-radius:50%;background:var(--surface-3);border:1px solid var(--border-2)}
.tl li.ok::before{background:var(--ok);border-color:transparent}
.tl li.warn::before{background:var(--warn);border-color:transparent}
.tl li.danger::before{background:var(--danger);border-color:transparent}
.tl b{display:block;color:var(--text);font-weight:500;font-size:12.5px;margin-bottom:1px}
.drawer-foot{display:flex;gap:8px;padding:12px 16px;border-top:1px solid var(--border);background:var(--surface-2)}
.drawer-foot .primary{flex:1}
.callout{display:flex;gap:9px;padding:11px 12px;border-radius:9px;font-size:12px;line-height:1.55;border:1px solid transparent}
.callout.warn{background:var(--warn-soft);border-color:rgba(245,185,66,.24);color:var(--warn)}
.callout.danger{background:var(--danger-soft);border-color:rgba(251,113,133,.22);color:var(--danger)}
.callout.ok{background:var(--ok-soft);border-color:rgba(61,220,151,.22);color:var(--ok)}
.callout.info{background:var(--accent-soft);border-color:rgba(76,141,255,.24);color:var(--accent-2)}
.callout svg{margin-top:1px}
.callout code{font-family:var(--mono);font-size:11px;padding:1px 5px;border-radius:4px;background:rgba(128,128,128,.16);color:inherit}
.cand{display:flex;flex-wrap:wrap;gap:6px;margin-top:9px}
.cand-chip{display:inline-flex;align-items:center;gap:5px;height:24px;padding:0 8px;border-radius:7px;font-size:11.5px;font-family:var(--mono);color:inherit;background:rgba(128,128,128,.14);border:1px solid rgba(128,128,128,.22);transition:background var(--t)}
.cand-chip:hover{background:rgba(128,128,128,.24)}

/* Modal */
dialog.modal{border:0;padding:0;background:transparent;color:var(--text);width:min(520px,94vw);max-width:100%;max-height:92vh}
dialog.modal::backdrop{background:rgba(3,6,10,.64);backdrop-filter:blur(2px)}
.modal-panel{background:var(--surface);border:1px solid var(--border-2);border-radius:14px;overflow:hidden;box-shadow:var(--shadow)}
.m-head{display:flex;align-items:center;gap:10px;padding:15px 18px;border-bottom:1px solid var(--border)}
.m-head h3{font-size:14.5px;font-weight:600}
.m-head .icon-btn{margin-left:auto}
.m-body{padding:16px 18px;display:grid;gap:12px;max-height:70vh;overflow:auto}
.m-foot{display:flex;justify-content:flex-end;gap:8px;padding:12px 18px;border-top:1px solid var(--border);background:var(--surface-2)}
.frow{display:grid;gap:6px}
.frow>span{font-size:12px;color:var(--text-2)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.input{width:100%;height:36px;border-radius:8px;border:1px solid var(--border-2);background:var(--surface-2);padding:0 10px;font-size:13px;outline:0;color:var(--text)}
select.input{appearance:none;background-image:var(--chevron);background-repeat:no-repeat;background-position:right 9px center;padding-right:26px;cursor:pointer}
.input[readonly]{opacity:.7;cursor:default}
textarea.input{height:auto;min-height:72px;padding:8px 10px;resize:vertical;line-height:1.5}
.input:focus{border-color:rgba(76,141,255,.55);box-shadow:0 0 0 3px var(--accent-soft)}
.hint{font-size:11.5px;color:var(--text-3);line-height:1.6}
.err-text{font-size:12px;color:var(--danger)}
.result{font-family:var(--mono);font-size:11.5px;line-height:1.6;background:var(--surface-2);border:1px solid var(--border);border-radius:9px;padding:10px 12px;white-space:pre-wrap;word-break:break-all;color:var(--text-2);max-height:240px;overflow:auto}

/* Bulk bar / toast */
.bulkbar{position:fixed;left:50%;bottom:22px;transform:translate(-50%,90px);opacity:0;display:flex;align-items:center;gap:10px;padding:8px 9px 8px 16px;border-radius:12px;background:var(--surface-3);border:1px solid var(--border-2);box-shadow:var(--shadow);z-index:30;transition:transform 240ms cubic-bezier(.2,.8,.3,1),opacity 200ms;pointer-events:none}
.bulkbar.on{transform:translate(-50%,0);opacity:1;pointer-events:auto}
.bulkbar .cnt{font-size:12.5px;color:var(--text-2)}
.bulkbar .cnt b{color:var(--text)}
.toasts{position:fixed;right:22px;bottom:22px;display:grid;gap:8px;z-index:50;max-width:340px}
.toast{display:flex;gap:9px;align-items:center;padding:11px 14px;border-radius:10px;background:var(--surface-3);border:1px solid var(--border-2);box-shadow:var(--shadow);font-size:12.5px;animation:toastIn 240ms cubic-bezier(.2,.8,.3,1)}
.toast.ok svg{color:var(--ok)}
.toast.info svg{color:var(--accent-2)}
.toast.warn svg{color:var(--warn)}
@keyframes toastIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}

/* Empty */
.empty{display:grid;place-items:center;text-align:center;gap:8px;padding:56px 20px;color:var(--text-3)}
.empty b{font-size:14px;color:var(--text-2);font-weight:550}
.empty p{font-size:12.5px;max-width:340px}
.empty .ico{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;background:var(--surface-2);border:1px solid var(--border);color:var(--text-3)}
.section-head{display:flex;align-items:baseline;gap:10px;margin:22px 0 10px}
.section-head h2{font-size:13px;font-weight:600}
.section-head span{font-size:11.5px;color:var(--text-3)}
.section-head .btn{margin-left:auto}

/* About */
.about-hero{display:flex;gap:18px;padding:24px 22px;align-items:flex-start;background:var(--hero-glow),var(--surface)}
.about-mark{width:52px;height:52px;border-radius:14px;display:grid;place-items:center;color:#fff;background:linear-gradient(160deg,#5F9BFF,#2F6BE8);box-shadow:0 12px 26px -12px rgba(76,141,255,.95);flex:none}
.about-id{min-width:0}
.about-name{display:flex;align-items:center;gap:9px;font-size:24px;font-weight:650;letter-spacing:-.03em;line-height:1.2}
.about-name .ver{font-size:11px;font-weight:500;letter-spacing:0;color:var(--text-3);background:var(--surface-2);border:1px solid var(--border);border-radius:999px;padding:2px 8px}
.about-full{font-size:12px;color:var(--accent-2);letter-spacing:.04em;margin-top:3px;font-weight:500}
.about-desc{font-size:13px;color:var(--text-2);line-height:1.7;margin-top:10px;max-width:720px}
.about-actions{display:flex;gap:8px;margin-top:16px;flex-wrap:wrap}
.about-list{list-style:none;margin:0;padding:0;display:grid;gap:10px}
.about-list li{font-size:12.5px;color:var(--text-2);line-height:1.65;padding-left:14px;position:relative}
.about-list li::before{content:'';position:absolute;left:0;top:7px;width:5px;height:5px;border-radius:50%;background:var(--accent);opacity:.7}
.about-list b{color:var(--text);font-weight:600;margin-right:6px}
.about-list code{font-family:var(--mono);font-size:11px;padding:1px 5px;border-radius:4px;background:var(--surface-2);border:1px solid var(--border);color:var(--text-2)}
.link-row{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:9px;border:1px solid var(--border);background:var(--surface-2);transition:border-color var(--t),background var(--t)}
.link-row:hover{border-color:var(--border-2);background:var(--surface-3)}
.link-row.static{cursor:default}
.link-row.static:hover{background:var(--surface-2);border-color:var(--border)}
.link-row>div{min-width:0;flex:1}
.link-row b{display:block;font-size:12.5px;font-weight:550}
.link-row small{display:block;font-size:11px;color:var(--text-3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.link-row>svg{color:var(--text-3);flex:none}
.link-ico{width:28px;height:28px;border-radius:8px;display:grid;place-items:center;background:var(--surface-3);color:var(--text-2);flex:none}
.stack{display:flex;flex-wrap:wrap;gap:6px}
.stack span{font-size:11.5px;padding:3px 9px;border-radius:999px;background:var(--surface-2);border:1px solid var(--border);color:var(--text-2)}

/* 设置 / 通知页的表单 */
.stack-form{display:block}
.stack-form .grid2{align-items:start}
.inline-check{display:flex;align-items:flex-start;gap:8px;font-size:12.5px;color:var(--text-2);line-height:1.6;cursor:pointer}
.inline-check input{margin-top:2px;flex:none}
.inline-check b{color:var(--text);font-weight:550}
.form-actions{display:flex;align-items:center;gap:10px;margin-top:14px;padding:12px 16px;border:1px solid var(--border);border-radius:var(--r-lg);background:var(--surface-2);flex-wrap:wrap}
.form-actions .err-text{margin-right:auto}
.form-actions .btn.primary{margin-left:auto}
.req{color:var(--danger);font-style:normal;font-size:11px}
.frow .pill{margin-left:6px;height:18px;font-size:10.5px}
.frow .hint{font-size:11px;color:var(--text-3);line-height:1.55}

@media (max-width:1180px){
  .grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .span2,.hero{grid-column:span 2}
  .span3{grid-column:span 2}
  .hero{grid-template-columns:1fr .8fr}
}
@media (max-width:980px){
  .app{grid-template-columns:72px minmax(0,1fr)}
  .rail{padding:14px 10px;align-items:center}
  .brand{padding:2px 0 14px}
  .brand div,.nav-item span,.nav-item .badge,.rail-foot .theme-toggle,.user div,.nav-label{display:none}
  .nav-item{justify-content:center;padding:10px 0}
  .user{justify-content:center}
  .hero{grid-template-columns:1fr}
  .hero-side{border-left:0;border-top:1px solid var(--border);grid-template-columns:repeat(3,1fr)}
  .mini{flex-direction:column;align-items:flex-start;gap:4px}
}
@media (max-width:760px){
  .app{grid-template-columns:1fr}
  .rail{position:fixed;top:auto;bottom:0;left:0;right:0;height:60px;flex-direction:row;justify-content:space-around;align-items:center;padding:0 8px;border-right:0;border-top:1px solid var(--border);background:var(--bg-2);z-index:30}
  .brand,.rail-foot,.nav-label{display:none}
  .nav-item{flex-direction:column;gap:3px;font-size:9px;padding:6px 2px;width:auto;flex:1;min-width:0}
  .nav-item span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
  .nav-item span{display:block}
  .nav-item .badge{display:none}
  .main{padding-bottom:60px}
  .topbar{padding:12px 16px}
  .content{padding:14px 14px 6px}
  .grid{grid-template-columns:1fr}
  .span2,.span3,.hero{grid-column:span 1}
  .hero{grid-template-columns:1fr}
  .hero-side{grid-template-columns:repeat(3,1fr)}
  .toolbar{padding:10px 12px;gap:8px}
  .search{max-width:none;width:100%}
  .chips{width:100%;overflow-x:auto;flex-wrap:nowrap;padding-bottom:2px}
  .chip{flex:none}
  .toolbar-right{width:100%;margin-left:0}
  .field{max-width:none;flex:1}
  .table .col-opt{display:none}
  .table .cb{display:none}
  .table th.right,.table td.right{display:none}
  .table tbody td{padding:10px 8px}
  .table thead th{padding:8px}
  .meter{display:none}
  .meter-cell{min-width:auto;gap:0}
  .meter-cell b{min-width:auto;text-align:left}
  #btnAdd{width:34px;padding:0;font-size:0}
  #btnAdd svg{margin:0}
  .toasts{left:14px;right:14px;bottom:74px;max-width:none}
  .bulkbar{left:14px;right:14px;transform:translate(0,90px);bottom:70px}
  .bulkbar.on{transform:none}
  .about-hero{flex-direction:column;gap:14px;padding:18px 16px}
  .about-name{font-size:21px}
}
/* 抽屉 / 弹窗打开时锁住背景滚动。
   之前抽屉是 position:fixed，底下页面还能滚，手机上滑一下就会把背景滑走，
   关掉抽屉后位置全乱了。 */
html.no-scroll,body.no-scroll{overflow:hidden}

/* 触摸设备：26px 的图标按钮手指点不准，统一放大到 32px */
@media (pointer:coarse){
  .icon-btn{width:32px;height:32px}
  .rowact{gap:4px}
  .pager button{min-width:32px;height:32px}
}

/* 窄屏顶栏：副标题挤占按钮空间，直接收起来 */
@media (max-width:520px){
  .topbar{padding:11px 14px;gap:10px}
  .topbar p{display:none}
  .topbar h1{font-size:15.5px}
  .topbar-actions{gap:6px}
}

/* 窄屏的 13 周柱状图：默认间距和字号会把最后两根柱子挤出卡片 */
@media (max-width:760px){
  .bars{gap:3px;height:126px;padding-top:10px}
  .bar-label{font-size:9px}
  .bar-val{font-size:9.5px}
  .bar-col{gap:4px}
}

@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
`;
