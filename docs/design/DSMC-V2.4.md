# DSMC v2.4.0 变更说明：加载性能、登录页与站点图标

> 起因：用户反馈「整体运行起来网页加载很慢」，同时要求把登录页的
> logo / DSMC / 标题居中，并把 favicon 换成登录页的 logo。
>
> 结论先放在前面：慢的根因不在前端体积，而在**每个请求都把整条链路重算一遍**。
> 光把 HTML 压小没有意义（Cloudflare 边缘本来就会 gzip），真正要动的是
> 「每次渲染都要问一次 Cloudflare、读几十次 KV、必要时还要等第三方接口」这条路径。

---

## 一、先量一遍：慢在哪里

用 73 个域名的预览页做基线（`design/preview/admin.html`，2.3.1 版本产出）：

| 构成 | 字符数 | 占比 |
|---|---:|---:|
| 总大小 | 364 843 | 100% |
| 表格行（138 行，域名库 + 续费清单） | 188 767 | 52% |
| 内联 SVG（382 个） | 91 289 | 25% |
| 内联客户端脚本 | 52 094 | 14% |
| 内联 CSS | 30 862 | 8% |
| 注入的数据块（JSON） | ~40 000 | 11% |

但这份体积是**压缩前**的。HTML/CSS/JS 都是高度可压缩内容，Cloudflare 边缘
默认就上 Brotli，线上实际传输大约 30–40 KB。所以「页面慢」不是传得慢。

真正的耗时在服务端，一个请求要顺序做完这些事：

1. `initConfig`：串行读 5 份 KV 配置（设置 / 账户 / DNSHE 凭证 / 通知配置 / 通知状态）
2. `initManagers`：再读 1 份（免费域名白名单）
3. `fetchCloudflareDomainsInfo`：对每个账户请求 `api.cloudflare.com/client/v4/zones`，
   分页之间还固定 sleep 200ms
4. `fetchDomainInfo`：对 73 个域名逐个查 WHOIS —— 缓存命中就是一次 KV 读，
   未命中就发网络请求；免费域名按服务商限流串行排队（DNSHE 2 秒一个）

第 4 步是最致命的：**冷缓存下 73 个域名要几十秒到一分多钟**，浏览器早就超时了。
即使缓存全热，第 1–3 步加上 73 次 KV 读也要 1 秒以上——而且 2.3.1 里
`CacheManager` 是每个请求 `new` 出来的，构造出来的内存层请求一结束就丢，
所以「缓存全热」这件事实际上从来没生效过。

---

## 二、四项优化

### 1. Zone 列表缓存（进程内 + KV）

`services/cloudflare.js`

- 缓存键 `cache:zones:v1`，TTL 2 分钟，两层：模块级 `zoneMemCache` + KV
- 缓存的是**脱敏副本**（只存 `ownerId`，不存 Token），读回来时按账户 id 现查
- 账户增删/启停会改变「签名」（`accountSignature`），缓存自动失效
- **一个账户都没查成功时不写缓存** —— 否则一次网络抖动会让「没有域名」在缓存里
  躺两分钟，页面看起来像域名全丢了，比慢更吓人
- `force: true` 绕过缓存（刷新按钮走这条路）

为什么是 2 分钟：用户在 Cloudflare 面板新加域名后，最多等 2 分钟就能看到。
再长就会被当成「漏域名」报 bug。

### 2. CacheManager 跨请求复用

`state.js`

```js
let sharedCacheManager = null;

if (!sharedCacheManager || sharedCacheManager.kv !== kv) {
  sharedCacheManager = new CacheManager(kv);
}
appState.cacheManager = sharedCacheManager;
```

按 KV 命名空间做单例。同一个 isolate 内 60 秒内的重复读直接命中内存，
不再走 KV。这一项对「缓存热了之后还是慢」的体感改善最直接。

### 3. 渲染时间预算 + 后台补全

这是本轮改动里唯一有**行为变化**的一项，需要说明取舍。

`fetchDomainInfo(domains, { budgetMs })` 新增预算参数：

- 每处理一个域名前检查 `Date.now() > deadline`
- 超时后 `service.query(domain, { cacheOnly: true })`：**只读缓存，不发网络请求**
- 免费域名的注册表元数据是本地常量（不花钱也不慢），照常返回
- 普通域名没缓存就返回 `{ pending: true }` 占位

页面路径用 `CONFIG.PAGE_LOOKUP_BUDGET`（4 秒），刷新按钮和定时任务用
`PAGE_BACKGROUND_BUDGET`（25 秒），或者不限时。

渲染完成后如果还有 `pending`，`ctx.waitUntil` 起一个后台任务把剩下的查完：

```js
function scheduleBackgroundFill(ctx, pending) {
  if (!pending || !ctx?.waitUntil) return;
  ctx.waitUntil(async () => {
    const zones = await fetchCloudflareDomainsInfo();
    await fetchDomainInfo(zones, { budgetMs: CONFIG.PAGE_BACKGROUND_BUDGET });
  });
}
```

UI 侧：

- `statusOf()` 新增 `pending` 状态（徽标「查询中」），与「未知 / 待设置」区分开——
  前者会自己好，后者要用户去补配置，混成一个状态会让人白等
- 页面顶部一条 callout：「N 个域名正在后台查询」，带「重新加载」按钮

**取舍**：首屏可能显示不完整的数据。但对比「白屏转圈 60 秒」，
「4 秒看到大部分 + 顶部明确说明还有几个在查」明显更好，而且后台补完之后
下一次刷新就是完整的。

顺带修掉两个「白等」的地方：

- `runBatched` 的批次间隔只在「真的发过请求」时才等待（整批 <50ms 说明全是缓存命中）
- Cloudflare 分页之间的固定 200ms sleep 直接删掉（限流 1200 次/5 分钟，串行翻页撞不到）

### 4. ETag / 304

`handlers.js`

```js
'Cache-Control': 'private, no-cache, must-revalidate',
'ETag': '"' + hashString(html) + '"',
'Vary': 'Cookie'
```

- 原来是 `no-store`，浏览器每次导航都要重新下载整页
- 现在是 `no-cache`（允许存副本，但每次使用前必须回来验证）+ ETag（FNV-1a）
- 内容没变 → 304，几十字节；变了 → 200 带新内容
- `Vary: Cookie`：页面内容确实跟登录态相关（未登录会 302），不能让别人共用

另外把 `initConfig` 里 5 份互不依赖的 KV 读改成 `Promise.all`。

---

## 三、登录页与站点图标

### 头部居中

```css
.hd{text-align:center}
.mark{...;margin:0 auto 16px}
```

只居中头部（logo / DSMC / 标题 / 说明），**表单区保持左对齐**——
标签和输入框居中之后眼睛要来回找，反而更难填。底部说明条跟着居中。

顺带修掉一个排版问题：副标题原来有 `max-width:296px`，23 个汉字的说明会被
挤成两行、末字「醒。」单独一行。去掉宽度限制 + `text-wrap:pretty` 后一行放下。

### favicon

原来是一个 emoji 文本 SVG：

```
<text y=".9em" font-size="90">🛡️</text>
```

两个问题：渲染结果取决于系统字体（Windows / macOS / Android 颜色形状都不一样），
16px 下细节全糊。

现在 `src/ui/favicon.js` 里放一枚内联 SVG（渐变圆角方块 + 白色对勾），
与登录页 `.mark` 同一个视觉，`login.js` 与 `shell.js` 共用：

```js
export const FAVICON_HREF = 'data:image/svg+xml,' + encodeURIComponent(SHIELD_SVG);
export const FAVICON_LINK = '<link rel="icon" type="image/svg+xml" href="...">';
```

为什么用 data URI 而不是 `/favicon.ico` 路由：Worker 每个请求都要走一遍
`initConfig` + `initManagers`，为一个图标付这份开销不值得；data URI 跟着 HTML 走，
零请求、可被浏览器长期缓存。

---

## 四、UI 审查清单

用 1440px / 390px 两个视口实测（Chrome headless + iframe 精确模拟 390px），
发现并修掉这些：

| 问题 | 现象 | 修法 |
|---|---|---|
| 13 周柱状图溢出 | 375px 下最后两根柱子被卡片裁掉（实测 `bar-col` 右边界 404 > 视口 375） | ≤760px 缩间距 6→3px、字号 10→9px、高度 150→126px |
| 底部导航标签折行 | 「域名库」变成「域名 / 库」，「续费清单」两行，参差不齐 | 字号 9px、`white-space:nowrap` + `text-overflow:ellipsis` |
| 窄屏顶栏拥挤 | 副标题挤占操作按钮空间 | ≤520px 隐藏 `#pageSub`，缩小 padding 与 gap |
| 抽屉不锁滚动 | 抽屉打开时背景还能滑，手机上滑一下再关掉位置全乱 | 抽屉/弹窗打开时给 `<html>` 加 `no-scroll`，按「是否还有遮罩」统一算 |
| 侧栏够不着 | 矮屏幕上「关于」和主题切换被切掉，`height:100vh` 无滚动 | `.rail{overflow-y:auto;overscroll-behavior:contain}` |
| 触摸目标偏小 | 行操作按钮 26px，手指点不准 | 28px 起，`pointer:coarse` 下 32px |
| 抽屉高度 | 移动端浏览器工具栏导致 `100vh` 溢出 | `height:100vh;height:100dvh` |
| 登录页可访问性 | 错误提示没有语义 | `role="alert" aria-live="assertive"`；装饰 logo `aria-hidden` |
| 移动端地址栏配色 | 缺 `theme-color` | 按 `prefers-color-scheme` 给两条 meta |

顺带确认没问题的：焦点可见性（全局 `:focus-visible`）、`prefers-reduced-motion`、
表格横向滚动容器、深/浅两套主题的对比度。

---

## 五、顺手修掉的安全隐患

`fetchAllDomains` 原来给每个域名对象塞了 `account: keyInfo.key`——**明文 API Token**。
当前视图层读的是 `normalizeDomains()` 归一化后的 `account`（账户名），所以线上没有
真的泄漏，但：

1. 这个对象会一路流到视图层，任何一处 `d.account` 渲染就是明文泄漏
2. 加 Zone 缓存之后，它会被写进 KV——等于在 KV 里多存一份密钥

改成 `ownerId: keyInfo.id`，并加测试断言「域名对象序列化后不含 Token」
「KV 缓存里不含 Token」。

另外修掉一个必然抛异常的分支：`initConfig` 里 `if (!accounts.length)` 原来写的是
`USERNAMES = USERNAMES_FALLBACK`（给 import 绑定赋值），一执行就 `TypeError`。

---

## 六、验证

```
npm run check
  单元测试   355/355 通过
  端到端冒烟  22/22 项通过
  esbuild 打包 通过
```

新增测试：

- `test/cloudflare-fetcher.test.js`（8）：缓存命中 / 签名失效 / 全挂不写缓存 /
  `force` / 脱敏
- `test/whois-budget.test.js`（4）：`cacheOnly` 不发请求、不写缓存、免费域名仍出元数据
- `test/html-response.test.js`（5）：200/304、内容变化后 ETag 变化、多值 ETag、`Vary`
- `test/ui-client.test.js`（11）：`clientScript()` 语法可解析、CSS 大括号配平、
  登录页居中规则、`statusOf` 区分 `pending`
- 冒烟（1）：`/admin` 二次访问走 304，并核对 `Cache-Control: no-cache` 与 `Vary: Cookie`。
  单测只测 `htmlResponse` 本身，路由把 `request` 传错、或页面里混进每请求都变的字段，
  只有走完整路由才看得见——这条补的就是这个缺口

其中「`clientScript()` 语法可解析」值得单独说：`client.js` 是 1200 多行的模板字符串，
Node 不会直接执行它，也不在单测覆盖范围内。写错一个引号，页面照样 200、HTML 也正常，
但所有交互全废。`new Function(code)` 一行就能把这类错误挡在提交前。

视觉验证（Chrome headless，1440×900 / 390×844）：

- `design/preview/shot-login.png`：登录页头部居中、副标题单行
- `design/preview/shot-admin.png`：管理页深色主题
- `design/preview/shot-light.png`：浅色主题
- `design/preview/shot-mobile.png`：390px 下顶栏 5 个按钮、9 个导航项单行、13 周柱状图完整

---

## 七、已知取舍与后续

1. **Zone 列表最长 2 分钟陈旧**。在 Cloudflare 面板新加的域名不会立刻出现。
   点「刷新全部」会 `force` 绕过缓存。
2. **后台补全可能被 isolate 回收打断**。Workers 的 `waitUntil` 只保证「尽力而为」。
   好在每个域名的结果都是单独写进 KV 缓存的，所以打断不会丢进度，下次访问继续补。
3. **首屏可能出现「查询中」徽标**。这是有意的设计，不是 bug——顶部有说明，
   点「重新加载」即可。
4. **HTML 体积没动**。382 个内联 SVG 和 138 行表格占了 70%+ 的字节，
   但 gzip 后收益有限，而拆成外部资源会破坏 `design/preview/*.html` 单文件预览的能力。
   如果后续域名数量再上一个量级，可以考虑：
   - 图标改成 `<symbol>` + `<use>` 精灵图（能省 ~75KB 未压缩体积）
   - 域名库只渲染首屏一页，其余由客户端按数据块渲染
