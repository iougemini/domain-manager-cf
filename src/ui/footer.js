// 全站页脚：登录页、访客页、管理页共用同一份内容与样式
//
// 单独成模块的原因：页脚要出现在三类页面上，而这三类页面的 CSS 是各自独立的
// （登录页一套、应用外壳一套）。内容或链接改一处却漏掉另一处，用户看到的就是
// 两个不同版本的品牌信息。这里同时导出 CSS 与 HTML，两套页面各自拼接即可。

import { CONFIG, PROJECT } from '../config.js';
import { icon } from './icons.js';
import { escapeHtml } from './data.js';

const esc = escapeHtml;

export const FOOTER_CSS = `
.site-foot{display:grid;gap:7px;justify-items:center;text-align:center;font-size:11.5px;color:var(--text-3);padding:18px 26px 22px;margin:0 auto;border-top:1px solid var(--border);max-width:1560px;width:100%}
.sf-line{display:flex;align-items:center;justify-content:center;gap:7px;flex-wrap:wrap;line-height:1.7}
.sf-brand{display:inline-flex;align-items:center;gap:6px;color:var(--text-2);font-weight:600;letter-spacing:.01em}
.sf-brand svg{color:var(--accent)}
.sf-brand em{font-style:normal;font-weight:500;font-size:10.5px;color:var(--text-3);padding:1px 6px;border:1px solid var(--border-2);border-radius:20px}
.sf-dot{color:var(--border-2);user-select:none}
.site-foot a{color:var(--text-2);text-decoration:none;transition:color 160ms ease}
.site-foot a:hover{color:var(--accent);text-decoration:underline;text-underline-offset:2px}
.sf-alt{font-size:10.5px;color:var(--text-3);opacity:.8;letter-spacing:.02em}
/* 登录页：卡片居中、body 溢出隐藏，页脚改为固定贴底 */
.site-foot.fixed{position:fixed;left:0;right:0;bottom:14px;margin:0;padding:0;border:0;z-index:1;max-width:none}
@media(max-width:520px){
  .site-foot{font-size:11px;padding:16px 14px 18px}
  .sf-dot{display:none}
  .sf-line{gap:4px 10px}
}
`;

/**
 * @param {{version?: string, fixed?: boolean, project?: object}} [options]
 *        fixed=true 用于登录页（卡片居中、页面不滚动，页脚固定贴底）
 *        project 不传时用 config 里的 PROJECT，保证与侧栏品牌一致
 */
export function footerHtml(options = {}) {
  const p = options.project || PROJECT;
  const version = options.version || CONFIG.VERSION;
  const year = new Date().getFullYear();
  const alt = p.FULL_NAME;

  return '<footer class="site-foot' + (options.fixed ? ' fixed' : '') + '">' +
    '<div class="sf-line">' +
      '<span class="sf-brand" title="' + esc(alt) + '" aria-label="' + esc(p.NAME + ' · ' + alt) + '">' +
        icon('shield', 13) + '<span>' + esc(p.NAME) + '</span><em>v' + esc(version) + '</em>' +
      '</span>' +
      '<span class="sf-dot" aria-hidden="true">·</span>' +
      '<a href="' + esc(p.COMMUNITY) + '" target="_blank" rel="noopener noreferrer">© ' + year +
        ' Copyright by NieGe Meta</a>' +
      '<span class="sf-dot" aria-hidden="true">·</span>' +
      '<a href="' + esc(p.GITHUB) + '" target="_blank" rel="noopener noreferrer" title="' + esc(alt) + '">' +
        'Powered by ' + esc(p.NAME) + '</a>' +
      '<span class="sf-dot" aria-hidden="true">·</span>' +
      '<span>' + esc(p.LICENSE) + ' License</span>' +
    '</div>' +
    '<div class="sf-alt">' + esc(alt) + '</div>' +
  '</footer>';
}
