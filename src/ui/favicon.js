// 站点图标：与登录页 .mark 同一枚盾牌（渐变圆角方块 + 白色对勾）。
//
// 之前用的是 emoji 文本（🛡️）当图标，问题有两个：
//   1. 渲染结果取决于系统字体，Windows / macOS / Android 出来的颜色和形状都不一样；
//   2. 16px 下 emoji 细节全糊，看起来像一坨彩色噪点。
// 改成内联 SVG 后，图标在登录页、主界面、书签栏里是同一个东西。
//
// 用 data URI 而不是 /favicon.ico 静态路由：Worker 每次请求都要走一遍
// initConfig + initManagers，为一个图标付这份开销不值得；而 data URI 直接
// 跟着 HTML 走，零请求、可被浏览器长期缓存。

const SHIELD_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">' +
    '<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0" stop-color="#5F9BFF"/>' +
      '<stop offset="1" stop-color="#2F6BE8"/>' +
    '</linearGradient></defs>' +
    '<rect width="64" height="64" rx="15" fill="url(#g)"/>' +
    '<g fill="none" stroke="#FFFFFF" stroke-width="4.4" stroke-linecap="round" stroke-linejoin="round">' +
      '<path d="M32 13.5l13.6 5.9v9.9c0 8.7-5.7 15.6-13.6 19.5-7.9-3.9-13.6-10.8-13.6-19.5v-9.9L32 13.5z"/>' +
      '<path d="M25.4 31.6l4.9 4.9 8.8-8.8"/>' +
    '</g>' +
  '</svg>';

/** data:image/svg+xml,... —— encodeURIComponent 会把 # < > " 一并转义，可安全放进属性 */
export const FAVICON_HREF = 'data:image/svg+xml,' + encodeURIComponent(SHIELD_SVG);

/** 直接可拼进 <head> 的 <link> 标签 */
export const FAVICON_LINK =
  '<link rel="icon" type="image/svg+xml" href="' + FAVICON_HREF + '">\n' +
  '<link rel="mask-icon" href="' + FAVICON_HREF + '" color="#2F6BE8">\n';

/** 移动端地址栏配色，跟随页面主题 */
export const THEME_COLOR_META =
  '<meta name="theme-color" content="#070A0F" media="(prefers-color-scheme: dark)">\n' +
  '<meta name="theme-color" content="#F5F7FA" media="(prefers-color-scheme: light)">\n';
