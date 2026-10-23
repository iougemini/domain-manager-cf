# DSMC v2.6.0 · 导航命名统一、DNSHE 并入设置、全站页脚

## 一、起因

三件事：

1. 侧栏三种构词法混着用 —— 「域名库」「续费清单」「免费域名」，长度 3/4/4 个字，
   纵向扫读时参差不齐，窄屏还要截断；
2. DNSHE 凭证管理单独占一个导航项，但它本质是"数据源配置"，用户找配置时
   第一反应是设置页；
3. 只有登录页底部有一行品牌信息，进站之后就没有页脚了。

## 二、导航

| 改前 | 改后 |
|---|---|
| 域名库 | 域名 |
| 续费清单 | 续费 |
| 免费域名 | 免费 |
| DNSHE（独立页） | 并入设置页 |

改完侧栏 8 项全是双字词：概览 / 域名 / 续费 / 账户 / 免费 / 通知 / 设置 / 关于。
窄屏底部导航每项约 48px，双字词刚好放得下，不需要 ellipsis。

页面标题（`META`）跟着一起改，否则点「域名」进去标题还写「域名库」。

### DNSHE 为什么能并进去

它的全部操作（新增 / 编辑 / 启停 / 测试 / 删除）都是独立按钮，不依赖页面级状态。
合并时唯一的坑是 **不能放进设置页的 `<form>` 里** —— 表单内的按钮默认
`type="submit"`，点「添加凭证」会顺带提交设置表单。所以 DNSHE 区块挂在
`</form>` 之后，作为设置视图的兄弟节点。

设置页原来的三张概览卡（DNSHE / WHOIS 代理 / 缓存）保留，DNSHE 那张去掉了
「管理 →」跳转（目标页已经不存在），改成静态说明。

## 三、页脚

抽成 `src/ui/footer.js`，同时导出 `FOOTER_CSS` 与 `footerHtml()`。理由：页脚要出现在
三类页面上，而这三类页面的 CSS 是各自独立的（登录页一套、应用外壳一套）。
只写在一个地方，改链接时就不会漏掉另一个。

内容：

```
[盾牌] DSMC v2.6.0 · © 2026 Copyright by NieGe Meta · Powered by DSMC · MIT License
Domain Status Manager for Cloudflare
```

- `Copyright by NieGe Meta` → `PROJECT.COMMUNITY`（niege.app）
- `Powered by DSMC` → `PROJECT.GITHUB`
- 全名同时出现在 `title`、`aria-label` 与页脚第二行（所谓 alt 文案）
- 外链统一 `target="_blank" rel="noopener noreferrer"`

### 布局差异

| 页面 | 位置 | 原因 |
|---|---|---|
| 管理页 / 访客页 | 内容流末尾，`border-top` 分隔 | 页面可滚动，页脚跟着内容走 |
| 登录页 | `position:fixed` 贴底 | 卡片垂直居中、`body{overflow:hidden}`，流式页脚会被裁掉 |

应用页靠 `.content{flex:1 1 auto}` 把页脚推到视口底部 —— 内容不足一屏时页脚也在底部，
不会浮在半空。

顺带把 `.content` 的 `padding-bottom` 从 96px 收到 8px：那 96px 原本是给移动端
固定底栏留的，现在由 `.main{padding-bottom:60px}` 负责，页脚自己还有 22px 内边距。

## 四、测试

原来冒烟里那条「/admin 渲染出账户/设置/DNSHE/通知入口」其实是**假通过**：
它只检查整页 HTML 里出没出现 `DNSHE` 这几个字，而 DNSHE 现在作为设置页的一个区块
仍然存在，所以把导航项删了它照样过。

改成先截出 `<aside class="rail">…</aside>`，再断言里面真的有 `>域名<`、`>续费<`、
`>免费<`，同时断言旧标签和 `data-view-link="dnshe"` 都不在了。

```
npm run check
  单元测试     374/374 通过
  端到端冒烟   28/28 项通过
  esbuild 打包  通过
```

新增 7 项 UI 测试：

- `FOOTER_CSS` 大括号配平（少一个 `}` 会让后面所有规则失效，肉眼极难发现）
- 版权行真的链到交流区、Powered by 真的链到仓库（**两处链错是这类页脚最常见的错误**，
  所以断言的是"版权文字前面 200 字符内出现了 COMMUNITY 链接"）
- 两个外链都带 `rel="noopener noreferrer"`
- 管理页与登录页都带页脚
- 登录页页脚是 `fixed`、应用页不是
- 侧栏标签统一（在 rail 片段内断言，避免误伤正文里的「免费域名」字样）
- DNSHE 不再是独立视图，且设置页里有 `data-action="dnshe-add"`

## 五、部署

无新增配置项、无 KV 变更、`CACHE_VERSION` 不变。直接部署。
