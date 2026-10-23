// 登录页（访问密码 / 管理员密码共用）
import { escapeHtml } from './data.js';
import { FAVICON_LINK, THEME_COLOR_META } from './favicon.js';
import { FOOTER_CSS, footerHtml } from './footer.js';

// 导出给测试用（校验大括号配平、居中规则），运行时不依赖外部引用
export const LOGIN_CSS = `
*,*::before,*::after{box-sizing:border-box}
:root{--font:"Inter","SF Pro Text",-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;--t:160ms cubic-bezier(.2,.7,.3,1)}
html[data-theme="dark"]{
  --bg:#070A0F;--surface:#0F1620;--surface-2:#131C27;--border:rgba(255,255,255,.08);--border-2:rgba(255,255,255,.14);
  --text:#E8EFF7;--text-2:#9BAABC;--text-3:#7C8CA0;--accent:#4C8DFF;--accent-soft:rgba(76,141,255,.14);
  --danger:#FB7185;--danger-soft:rgba(251,113,133,.12);
  --grid:rgba(255,255,255,.035);--glow1:rgba(76,141,255,.18);
  color-scheme:dark;
}
html[data-theme="light"]{
  --bg:#F5F7FA;--surface:#FFFFFF;--surface-2:#F7F9FC;--border:#E4EAF2;--border-2:#D3DDEA;
  --text:#0E1A2B;--text-2:#586A7E;--text-3:#6B7B8E;--accent:#2563EB;--accent-soft:rgba(37,99,235,.08);
  --danger:#DC2626;--danger-soft:rgba(220,38,38,.08);
  --grid:rgba(15,26,43,.04);--glow1:rgba(37,99,235,.10);
  color-scheme:light;
}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;-webkit-font-smoothing:antialiased;display:grid;place-items:center;padding:24px;position:relative;overflow:hidden}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);background-size:44px 44px;mask-image:radial-gradient(circle at 50% 40%,#000 0%,transparent 78%);-webkit-mask-image:radial-gradient(circle at 50% 40%,#000 0%,transparent 78%)}
body::after{content:'';position:fixed;width:900px;height:900px;left:50%;top:-420px;transform:translateX(-50%);background:radial-gradient(circle,var(--glow1),transparent 62%);pointer-events:none}
.wrap{position:relative;z-index:1;width:100%;max-width:400px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:18px;padding:30px 28px 24px;box-shadow:0 30px 70px -40px rgba(0,0,0,.85)}
html[data-theme="light"] .card{box-shadow:0 24px 60px -34px rgba(15,26,43,.28)}
/* 头部（logo / 品牌 / 标题 / 说明）居中，表单区保持左对齐——
   标签与输入框左对齐才好扫读，把整张卡片都居中反而更难填 */
.hd{text-align:center}
.mark{width:44px;height:44px;border-radius:13px;display:grid;place-items:center;color:#fff;background:linear-gradient(160deg,#5F9BFF,#2F6BE8);box-shadow:0 10px 24px -10px rgba(76,141,255,.95);margin:0 auto 16px}
h1{font-size:20px;font-weight:650;letter-spacing:-.025em;margin:0 0 7px}
.brand{font-size:11px;font-weight:600;letter-spacing:.16em;text-transform:uppercase;color:var(--accent);margin-bottom:7px}
.sub{font-size:12.5px;color:var(--text-2);line-height:1.6;margin:0 auto 22px;text-wrap:pretty}
label.fl{display:block;font-size:12px;color:var(--text-2);margin-bottom:7px;font-weight:500}
.input{display:flex;align-items:center;gap:9px;height:42px;padding:0 12px;border-radius:10px;border:1px solid var(--border-2);background:var(--surface-2);transition:border-color var(--t),box-shadow var(--t)}
.input svg{color:var(--text-3);flex:none}
.input input{flex:1;min-width:0;background:none;border:0;outline:0;font-size:14px;color:var(--text)}
.input input::placeholder{color:var(--text-3)}
input[type="password"]::-ms-reveal,input[type="password"]::-ms-clear{display:none}
input::-webkit-credentials-auto-fill-button{display:none!important;visibility:hidden;pointer-events:none}
.input:focus-within{border-color:rgba(76,141,255,.6);box-shadow:0 0 0 3px var(--accent-soft)}
.input.err{border-color:rgba(251,113,133,.6);box-shadow:0 0 0 3px var(--danger-soft)}
.eye{width:26px;height:26px;display:grid;place-items:center;border-radius:6px;color:var(--text-3);flex:none;background:none;border:0;padding:0;cursor:pointer}
.eye:hover{color:var(--text);background:var(--surface-3,rgba(128,128,128,.12))}
.msg{display:none;align-items:center;gap:6px;font-size:12px;color:var(--danger);margin-top:8px}
.msg.on{display:flex}
button.submit{width:100%;height:42px;margin-top:18px;border:1px solid #3C7CF5;border-radius:10px;background:linear-gradient(180deg,#5A97FF,#3C7CF5);color:#fff;font:inherit;font-weight:600;font-size:14px;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px;box-shadow:0 12px 26px -14px rgba(76,141,255,1);transition:filter var(--t)}
button.submit:hover{filter:brightness(1.07)}
button.submit[disabled]{opacity:.7;cursor:default}
.foot{margin-top:20px;padding-top:16px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:center;gap:8px;font-size:11.5px;color:var(--text-3);flex-wrap:wrap}
.foot .sep{padding-left:9px;border-left:1px solid var(--border-2)}
.foot a{color:var(--text-2);text-decoration:none}
.foot a:hover{color:var(--text)}
.theme{position:fixed;top:18px;right:18px;z-index:2;width:34px;height:34px;border-radius:9px;border:1px solid var(--border);background:var(--surface);color:var(--text-2);display:grid;place-items:center;cursor:pointer}
.theme:hover{color:var(--text)}
.brandline{position:fixed;bottom:20px;left:0;right:0;text-align:center;font-size:11px;color:var(--text-3);z-index:1}
.spinner{width:15px;height:15px;border-radius:50%;border:2px solid rgba(255,255,255,.35);border-top-color:#fff;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.shake{animation:shake .32s}
@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-4px)}75%{transform:translateX(4px)}}
@media(max-width:420px){.card{padding:24px 20px 20px}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
`;

const SHIELD = '<svg width="23" height="23" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>';
const LOCK = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>';
const EYE = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z"/><circle cx="12" cy="12" r="2.6"/></svg>';
const ALERT = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>';
const MOON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z"/></svg>';

export function renderLogin(title, action, errorMessage) {
  const isAdmin = String(action).indexOf('admin') !== -1;
  const err = errorMessage ? String(errorMessage) : '';

  return '<!DOCTYPE html>\n<html lang="zh-CN" data-theme="dark">\n<head>\n' +
    '<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
    '<meta name="color-scheme" content="dark light">\n' +
    '<title>' + escapeHtml(title) + ' · DSMC</title>\n' +
    FAVICON_LINK + THEME_COLOR_META +
    '<script>try{var t=localStorage.getItem("dsmc-theme")||localStorage.getItem("dk-theme");if(t)document.documentElement.dataset.theme=t;else if(window.matchMedia&&window.matchMedia("(prefers-color-scheme: light)").matches)document.documentElement.dataset.theme="light";}catch(e){}</script>\n' +
    '<style>' + LOGIN_CSS + FOOTER_CSS + '</style>\n</head>\n<body>\n' +
    '<button class="theme" id="themeBtn" aria-label="切换主题">' + MOON + '</button>' +
    '<div class="wrap"><div class="card" id="card">' +
      '<div class="hd">' +
        '<div class="mark" aria-hidden="true">' + SHIELD + '</div>' +
        '<div class="brand">DSMC</div>' +
        '<h1>' + escapeHtml(title) + '</h1>' +
        '<p class="sub">' + (isAdmin ? '输入管理员密码，管理 API 密钥与域名信息。' : '输入访问密码，查看所有账户的域名状态与到期提醒。') + '</p>' +
      '</div>' +
      '<form method="POST" action="' + escapeHtml(action) + '" id="form">' +
        '<label class="fl" for="pwd">' + (isAdmin ? '管理员密码' : '访问密码') + '</label>' +
        '<div class="input' + (err ? ' err' : '') + '" id="inputWrap">' + LOCK +
          '<input id="pwd" name="password" type="password" placeholder="' + (isAdmin ? '请输入管理员密码' : '请输入访问密码') + '" autocomplete="current-password" autofocus required>' +
          '<button type="button" class="eye" id="eye" aria-label="显示密码">' + EYE + '</button>' +
        '</div>' +
        '<div class="msg' + (err ? ' on' : '') + '" id="msg" role="alert" aria-live="assertive">' + ALERT + '<span id="msgText">' + escapeHtml(err || '密码不正确，请重试') + '</span></div>' +
        '<button class="submit" id="submit" type="submit">登录</button>' +
      '</form>' +
      '<div class="foot">' + LOCK +
        '<span>密码通过 HMAC 签名 Cookie 校验</span>' +
        '<a class="sep" href="' + (isAdmin ? '/' : '/admin') + '">' + (isAdmin ? '返回首页' : '管理员登录') + '</a>' +
      '</div>' +
    '</div></div>' +
    footerHtml({ fixed: true }) +
    '<script>\n' +
    'var root=document.documentElement;\n' +
    'var btn=document.getElementById("themeBtn");\n' +
    'btn.addEventListener("click",function(){root.dataset.theme=root.dataset.theme==="dark"?"light":"dark";try{localStorage.setItem("dk-theme",root.dataset.theme);}catch(e){}});\n' +
    'var pwd=document.getElementById("pwd");\n' +
    'var eye=document.getElementById("eye");\n' +
    'eye.addEventListener("click",function(){var show=pwd.type==="password";pwd.type=show?"text":"password";eye.setAttribute("aria-label",show?"隐藏密码":"显示密码");pwd.focus();});\n' +
    'var wrap=document.getElementById("inputWrap");\n' +
    'var msg=document.getElementById("msg");\n' +
    'var msgText=document.getElementById("msgText");\n' +
    'pwd.addEventListener("input",function(){wrap.classList.remove("err");if(!msg.dataset.server)msg.classList.remove("on");});\n' +
    'var form=document.getElementById("form");\n' +
    'form.addEventListener("submit",function(e){if(!pwd.value.trim()){e.preventDefault();wrap.classList.add("err");msgText.textContent="请输入密码";msg.classList.add("on");document.getElementById("card").classList.add("shake");setTimeout(function(){document.getElementById("card").classList.remove("shake");},360);pwd.focus();return;}var s=document.getElementById("submit");s.disabled=true;s.innerHTML=\'<span class="spinner"></span> 正在验证…\';});\n' +
    'if(msg.classList.contains("on"))msg.dataset.server="1";\n' +
    '</script>\n</body>\n</html>';
}
