# DSMC v2.2.0 变更说明

> 本轮需求：DNSHE Key 作用域、账户页 CRUD、设置页、DNSHE 页、2999 永久域名标记、通知模块。
> 结论：六项全部落地。`npm test` **309 项通过**，端到端冒烟 16 项通过，
> esbuild 打包通过（374 KB），预览页 9 个视图渲染无异常，数据块可正常解析。

---

## 一、变更总览

| 需求 | 落地位置 | 对外可见变化 |
|---|---|---|
| ① DNSHE Key 作用域 | `services/free-domain-lookup.js`、`managers/dnshe-store.js` | 多凭证 + 401 自动切换；README 写清平台级/账户级差异 |
| ② 账户页可编辑 | `managers/accounts-store.js`（新）、`managers/api-key.js`（重写）、`ui/views.js#accountsView` | 账户增删改查、启停、单个/批量测试、环境变量导入 |
| ③ 设置页 | `managers/settings-store.js`（新）、`ui/views.js#settingsView` | 密码、会话时长、WHOIS 代理、查询节奏可视化修改 |
| ④ DNSHE 独立页 | `managers/dnshe-store.js`（新）、`ui/views.js#dnsheView` | 多组 Key/Secret 管理，单条验证连通性 |
| ⑤ 2999 = 永久域名 | `free-domain-lookup.js`、`services/whois.js`、`ui/data.js` | 紫色「永久」徽标，不参与到期告警 |
| ⑥ 通知页 + 通知模块 | `services/notify.js`（新）、`managers/notify-store.js`（新）、`ui/views.js#notifyView` | 9 个渠道、到期规则、测试发送、Cron 每日推送 |

新增 11 个模块，`src/` 下从 25 个文件增至 36 个。

---

## 二、需求①：DNSHE 的 Key 到底能查多少

### 实测到的

没有凭证时，两个接口都返回同样的 401：

```
GET https://api005.dnshe.com/?endpoint=whois&domain=xxx.us.ci
→ 401 {"error":"Missing API credentials (use X-API-Key and X-API-Secret headers)"}

GET https://api005.dnshe.com/?endpoint=subdomains&domain=xxx.us.ci
→ 401 {"error":"Missing API credentials (use X-API-Key and X-API-Secret headers)"}
```

这说明**两个接口都需要鉴权**，但证明不了「一个 Key 能不能查别人的域名」——这需要两组
不同账户的真实凭证做对照实验，而我没有。所以这一条结论来自官方文档的接口划分，不是实测。

### 结论（按接口分）

| 接口 | 作用域 | 依据 |
|---|---|---|
| `endpoint=whois` | **平台级** | 文档把它列为公开查询接口，按域名查注册信息，不涉及账户资源 |
| `endpoint=subdomains` / `dns_records` / `quota` / `keys` | **账户级** | 返回的都是「我的」资源，天然按 Key 归属过滤 |

也就是说：**查到期日这件事，一个 Key 就够用**；但账户类操作是隔离的。

### 于是怎么设计的

既然「一个 Key 够用」和「每个账户一个 Key」两种部署方式都可能存在，代码不押注任何一种：

```js
// free-domain-lookup.js#lookup
const attempts = spec.type === 'dnshe' && this.dnsheCredentials.length
  ? this.dnsheCredentials
  : [null];

for (const credential of attempts) {
  const result = await this.requestOnce(domain, spec, parser, credential);
  // 凭证被拒时换下一把；其余结果（成功/网络错误/未注册）直接返回
  if (result && result.authFailed) { lastAuthError = result; continue; }
  return result;
}
return lastAuthError || { error: 'DNSHE 凭证均不可用' };
```

好处是：某个账户的 Key 过期（401/403）时，只会切到下一组，**不会让全部 DNSHE 域名一起变成
「查询失败」**。坏处是多了一次循环，但只在失败路径上发生。

配套的 `managers/dnshe-store.js` 提供多凭证 CRUD，`config:dnshe` 存：

```json
[
  { "id": "dnshe_9f2a7c41", "label": "主账户", "key": "cfsd_...", "secret": "sk_...", "enabled": true }
]
```

Key 的格式校验是 `/^[A-Za-z0-9_-]{8,200}$/`——DNSHE 的 Key 以 `cfsd_` 开头，但我不想把
前缀写死，万一以后改了格式，写死就会误伤。

---

## 三、需求②：账户页从只读变 CRUD

### 为什么不能直接在原数组上改

旧代码把账户存在两个**平行数组**里：

```js
CF_API_KEYS = ["key1", "key2"]
USERNAMES   = ["user1", "user2"]
```

下标就是身份。删掉第一个，第二个自动顶上来变成「user1」的 Key——**配置会错位**，
而且没有任何地方能发现。所以这轮改成对象数组，用生成的 `id` 做身份：

```json
[{ "id": "acct_a1b2c3d4", "label": "主账户", "username": "gemini", "token": "...", "active": true }]
```

`config:accounts` 是唯一真相，`CF_API_KEYS` / `USERNAMES` 退化成「首次部署的种子」，
在页面上点「导入到 KV」后就不再被读取（`resolveAccounts` 的 source 会变成 `kv`）。

### 顺手修掉的一个真 bug

旧 `addApiKey` 里：

```js
const isValid = await this.testApiKey(token);   // 返回 { success, error }
if (!isValid) { ... }                            // 对象恒为真 → 永远不进分支
```

意思是**添加 Key 时从来没有校验过有效性**，填个 `abc` 也能加进去，直到第一次查域名才报错。
改成 `if (!result.success)` 之后，保存时会真的打一次 Cloudflare API，失败就直接拒绝。

### 编辑时 Token 留空 = 不修改

前端拿到的是掩码 `abcd12••••••••wxyz`，如果把它当值提交回去，KV 里就会存下这串掩码。
所以两层都做了处理：

- 前端：掩码字段渲染成 `placeholder="已设置，留空不修改"`，不给 `value`
- 后端：`token: patch.token || prev.token`

任何一层漏了，另一层还能兜住。

---

## 四、需求③④：设置页与 DNSHE 页

### 设置页解决的核心问题：优先级

把环境变量搬进 KV 之后，出现一个新问题：**默认值会覆盖环境变量**。

`freeDomainLiveLookup` 的默认值是 `true`。如果用户明确在环境变量里设了 `false`，
而 KV 里没有这个字段，读出来是 `undefined`，合并默认值后就变成 `true`——用户的 `false`
被静默吃掉了。

解法是记录「**用户真的设过哪些字段**」，而不是判断「值是不是空的」：

```js
// settings-store.js#loadSettingsWithMeta
const settings = { ...DEFAULT_SETTINGS };
const explicit = new Set();
for (const key of Object.keys(DEFAULT_SETTINGS)) {
  if (stored[key] !== undefined && stored[key] !== null) {
    settings[key] = stored[key];
    explicit.add(key);        // ← 关键：记住"用户真的设过"
  }
}
return { settings, explicit };

// settings-store.js#applySettings —— KV 显式设过 → 用 KV；否则看环境变量；都没有 → 默认值
appState.FREE_DOMAIN_LIVE_LOOKUP =
  known.has('freeDomainLiveLookup') ? settings.freeDomainLiveLookup
  : env.FREE_DOMAIN_LIVE_LOOKUP !== undefined ? parseBool(env.FREE_DOMAIN_LIVE_LOOKUP)
  : DEFAULT_SETTINGS.freeDomainLiveLookup;
```

`false` 和 `undefined` 终于是两件事了。

### 密码为什么用 PBKDF2 而不是手写哈希

第一版想用 JS 写个 SHA-256 迭代 1000 次——这在 Workers **免费版**上行不通：CPU 时间上限
是 10ms/请求，1000 次纯 JS 摘要会直接超时（错误码 1102）。改用原生 `crypto.subtle.deriveBits`：

```js
PBKDF2-HMAC-SHA256, 30000 轮, 16 字节随机盐 → 32 字节派生密钥
存储 { hash, salt, iterations }   // iterations 存进去，以后能升级轮数
```

30000 轮在 Workers 上是毫秒级，安全性远高于单次 SHA-256。

### 老部署怎么不炸

`verifyAccessPassword` 是两段式：

```js
1. 先按哈希校验（KV 里有记录时）
2. 失败则回退到环境变量明文比较（老部署）
```

所以升级不需要迁移脚本，也不用强制所有人改密码。等用户在设置页改过一次，就自动变成哈希了。

`publicSettings()` 投影时**永远不带 hash/salt**，只回 `accessPasswordSet: true` 这种布尔。

---

## 五、需求⑤：2999 是哨兵日期，不是错误

DNSHE 把子域名升级为永久后，`expires_at` 返回 `2999-12-31 00:00:00`。

原来的 `toYmd` 有年份上限：

```js
if (y < 1985 || y > 2100) return null;   // 2999 被当成非法值丢掉
```

于是 `expirationDate` 变成 `'Unknown'`，页面上显示「待设置」——**比显示一个错误日期更误导人**，
因为用户会以为域名没配好。

三处一起改：

| 位置 | 改动 |
|---|---|
| `free-domain-lookup.js#toYmd` | 上限 2100 → 9999 |
| `whois.js#parseDate` | 上限 2050 → 9999 |
| `ui/data.js#fmtDate` | 命中哨兵日期直接返回「永久」 |

判定阈值取 2900（`PERMANENT_YEAR`），而不是写死 2999：

```js
export const PERMANENT_YEAR = 2900;
export function isPermanentDate(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(value || ''));
  return m ? Number(m[1]) >= PERMANENT_YEAR : false;
}
```

留 99 年余量是因为不同注册局的哨兵值不一样（2999 / 9999 都有），而正常续期的域名
不可能超过 2900 年。用 `>=` 而不是 `===` 也避免以后换哨兵值再改一次。

前端 `ui/data.js` 里放了一份**零依赖的同名函数**——因为这个文件会进客户端 bundle，
不能 import 服务端模块（会把 `cloudflare:sockets` 拖进去）。

`isPermanent` 的两条来源是「或」的关系：

```js
isPermanent: Boolean(raw.isPermanent) || isPermanentDate(raw.expirationDate)
```

- `raw.isPermanent`：注册表规则判定（eu.org / is-a.dev / js.org 这类公益域名）
- `isPermanentDate(...)`：接口返回的哨兵日期（DNSHE 升级的永久域名）

通知摘要里显式排除永久域名，否则「还有 354000 天到期」会一直霸占告警列表。

---

## 六、需求⑥：通知模块

### 渠道抽象成纯函数

每个渠道只做一件事：**把消息变成一次 fetch 的参数**。

```js
{
  key: 'feishu',
  label: '飞书机器人',
  desc: '...',
  fields: [{ name: 'webhook', label: 'Webhook 地址', required: true }, ...],
  async build(config, message, nowMs) {
    return { url, init };   // 不自己发请求
  }
}
```

发送由 `NotificationService` 统一做，好处是：错误处理、超时、结果归一化只有一份；
加新渠道不用碰发送逻辑，前端表单也会按 `fields` 自动渲染。

### 飞书和钉钉的签名是反的

这是最容易踩的坑，两个平台都叫「加签」，算法却不一样：

```js
// 飞书：timestamp 和 secret 拼成 key，数据为空
const key = `${timestamp}\n${secret}`;
sign = HMAC_SHA256(key, '');          // data 是空字符串

// 钉钉：secret 是 key，timestamp 和 secret 拼成数据
sign = HMAC_SHA256(secret, `${timestamp}\n${secret}`);
```

抄错任何一边，都会一直返回 400 且错误信息含糊（「sign not match」）。代码里两边都写了注释。

### 为什么需要内容指纹

Cron 每天跑一次。如果只是「有临期域名就推」，那用户会连续 30 天收到一模一样的清单，
第 3 天就把机器人静音了。所以加了指纹去重：

```js
function fingerprintOf(digest) {
  return [
    digest.count,                                    // 数量
    [expired, week, month].join('/'),                // 紧急度分布
    digest.names.sort().join(',')                    // 域名集合（排序后）
  ].join('|');
}
```

三项全一样就跳过。域名新增/消失、或某个域名从「月内」掉进「周内」，指纹都会变，照常推送。
「立即发送」按钮传 `force: true` 绕过。

**只有至少一个渠道发送成功才更新指纹**——否则全渠道失败的那天会被记成「已推送」，
第二天内容不变就再也不推了，等于永久静默。

### Cron 的时间预算

`scheduled` 里要做两件事：清缓存 + 发通知。通知需要域名数据，而全量刷新 70+ 个域名
肯定超 `waitUntil` 的预算。所以 `collectDomainsForDigest` 是**缓存优先、有界实时查询**：

```js
const cached = await readAllCached();          // KV 里的，直接可用
const needLive = domains.filter(d => !cached[d.name]).slice(0, maxLive);  // 最多 12 个
```

语义上退了一步：提醒反映「最近一次已知状态」，不是每条都现查。这个取舍写在
`DEPLOYMENT.md` 里，避免用户以为是 bug。

### 掩码漏了一个字段

第一版 `SECRET_FIELDS` 只包含 `secret / token / apiKey / sendKey / key / accessToken`。
但飞书、钉钉、企业微信的机器人地址是把 token 写在**路径**里的：

```
https://open.feishu.cn/open-apis/bot/v2/hook/9f2a7c41b8e3   ← 这段就是凭证
```

漏掉 `webhook` / `url` 的结果是：读接口把完整地址回传前端，掩码形同虚设——打开 DevTools
或者截个图就拿到凭证了。已补上，并且给 `maskSecret` 加了 URL 分支：

```
https://open.feishu.cn/open-apis/bot/v2/hook/••••••••b8e3
```

保留 origin 与路径前缀（用户能认出是哪个平台的哪个机器人），只遮末段。如果沿用原来的
「首 6 位 + 尾 4 位」，URL 会变成 `https:••••••••b8e3`，前缀毫无信息量。

---

## 七、验证

```
$ npm run check
▶ 单元测试 … 309/309 通过
▶ 端到端冒烟 … 16/16 项通过
▶ esbuild 打包 … 通过
全部通过
```

### 端到端冒烟（`scripts/smoke.mjs`，本轮新增）

单测覆盖的是函数级行为，**「模块能不能装起来、路由有没有接错」它测不到**——比如
`index.js` 静态 import 了 `cloudflare:sockets`，在 Node 里根本加载不了；再比如新加的
`/api/notify` 路由忘了注册，单测照样全绿。

所以补了一层：用 esbuild 把 Worker 打成 Node 可 import 的包（`cloudflare:sockets`
alias 到桩），然后用假 KV 真跑一遍路由，16 项断言覆盖：

| 类别 | 断言 |
|---|---|
| 页面 | `/login`、`/admin-login` 返回 200；首页在「有/无访问密码」两种部署下分别公开/重定向 |
| 认证 | 密码错返回 401、密码对下发 `HttpOnly` cookie、管理员错密码不下发 cookie |
| 鉴权 | 未登录访问 `/api/accounts`、`/api/settings`、`/api/notify`、`/api/dnshe` 全部被拒 |
| 渲染 | 登录后 `/admin` 里四个新导航项都在，`dsmc-data` 能 `JSON.parse`，`notifyTypes` 恰好 9 个 |
| 安全 | `/admin` 页面（含注入的数据块）不含任何明文凭证 |
| Cron | `scheduled` 在通知未启用时安全跳过，不抛错 |

最后一条「不含明文凭证」正是第六节那个掩码漏洞的回归测试：`webhook` 没进
`SECRET_FIELDS` 时，这条断言会直接失败。

### 新增单测分布

本轮新增 177 项，总计 132 → 309：

| 文件 | 用例数 | 覆盖 |
|---|---|---|
| `test/kv-config.test.js` | 26 | 缓存 TTL、坏 JSON 不抛、读-改-写、`maskSecret` 的 URL 分支 |
| `test/accounts-store.test.js` | 24 | Token 校验、CRUD、source 优先级、环境变量导入、`getAllAccounts` 带 note |
| `test/settings-store.test.js` | 28 | PBKDF2、patch 校验、`applySettings` 优先级、投影不泄露哈希 |
| `test/dnshe-store.test.js` | 14 | Key 格式、CRUD、启用集合 |
| `test/notify.test.js` | 58 | 9 个渠道的 build 输出、签名、去重、失败不更新指纹、掩码回传 |
| `test/free-domain-lookup.test.js` | 44（+10） | 2999 哨兵日期、`isPermanentDate` 边界 |
| `test/ui-views.test.js` | 19 | **视图读的字段是否真在投影里**、Token/Webhook 不泄露、空态与权限 |

`ui-views.test.js` 是补出来的——本轮有两个 bug 是「页面 200、无 JS 报错、只是字段恒为
undefined」，单测和冒烟都发现不了：

| Bug | 症状 | 根因 |
|---|---|---|
| 设置页密码徽标 | 明明设了密码，一直显示「未设置」 | 视图读 `s.accessPassword`，`publicSettings()` 给的是 `accessPasswordSet` |
| 编辑账户清空备注 | 改个 Label 就把备注弄丢了 | `getAllAccounts()` 没返回 `note`，编辑表单回填成空串 |

两处都不是崩溃，是**静默错位**。所以专门加了一组测试，逐个断言「视图里读的字段」在
投影产出中存在，并且渲染结果里不出现 `undefined`。

### 预览页校验

`npm run preview` 渲染 73 个域名后，额外做了三项静态检查：

1. **9 个视图都有内容** —— `data-view` 标记齐全（overview / domains / expiring /
   accounts / freedomains / dnshe / notify / settings / about），逐块统计控件数量，
   排除「视图函数返回空串」这类问题
2. **数据块可解析** —— `dsmc-data` 能 `JSON.parse`，字段齐全（accounts 3 / dnshe 2 /
   domains 73 / notifyTypes 9）
3. **内联脚本语法合法** —— 抽出两个 `<script>` 块（主题预设 136 字符 + 客户端
   51625 字符）逐个 `node --check`，语法错误会让整页 JS 静默失效，必须单独验
4. **无明文凭证** —— 页面里搜不到 `9f2a7c41b8e3` / `demo-secret` / `barkkey123`

预览数据现在也走 `publicNotifyConfig` 投影——否则预览会把明文凭证画出来，
反而掩盖掉掩码失效这类问题。

---

## 八、已知限制

| 限制 | 原因 | 影响 |
|---|---|---|
| DNSHE 作用域结论非实测 | 需要两组真实账户凭证做对照 | 已用多凭证设计覆盖两种可能，无论结论如何都能工作 |
| Cron 只实时查 12 个域名 | `waitUntil` 时间预算 | 提醒反映最近已知状态，不是逐条现查 |
| KV 写入无事务 | Cloudflare KV 不提供 | 并发写仍可能丢条目；读-改-写只是降低概率 |
| 内存缓存 60 秒 | 减少 KV 读次数（免费版每天 10 万次） | 多 isolate 部署时，改配置后最长 60 秒才全局生效 |
| 邮件渠道依赖 Resend | 没做 SMTP（Workers 不支持裸 TCP SMTP） | 需要 Resend 账号 |
