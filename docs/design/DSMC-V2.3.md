# DSMC v2.3.0 变更说明

> 本轮需求：① `ip6.arpa` 加入免费域名并找到查询方式；② DNSHE 配了 API Key 仍返回 401；
> ③ 前台与管理页加入退出登录。
> 结论：三项全部落地。`npm run check` 三步全过 —— **327 单测 + 21 项端到端冒烟 + 打包通过**。

---

## 一、变更总览

| 需求 | 落地位置 | 对外可见变化 |
|---|---|---|
| ① `ip6.arpa` | `managers/free-domain.js` | 免费域名页多一行；`*.ip6.arpa` 标「永久」，不进告警 |
| ② DNSHE 401 | `services/free-domain-lookup.js`、`managers/cache.js`、`services/whois.js`、`handlers.js`、`state.js` | 失败缓存 5 分钟；改凭证立刻清缓存；401 提示分三种并带服务端原话 |
| ③ 退出登录 | `auth.js`、`handlers.js`、`index.js`、`ui/shell.js` | 顶栏退出图标；`/logout`、`/admin-logout` |

---

## 二、需求②：为什么配了 Key 还是 401

### 根因一（主因）：失败结果被当成正常结果缓存了 7 天

`WhoisService.query()` 里查询结果不分成功失败，一律 `cache.set(domain, result)`：

```js
const result = await this.resolveFreeDomain(domain, freeInfo);
await this.cache.set(domain, result);   // ← 401 兜底值也进了缓存
```

`CONFIG.CACHE_TTL` 是 **7 天**。于是第一次访问（还没配 Key）拿到的
`{ lookupError: 'DNSHE 认证失败（401）…', dataSource: 'registry' }` 被钉死在 KV 里，
之后补好 Key 刷新页面，读到的还是这条记录 —— 表现就是"改了配置完全没生效"。

而且 `cache.get()` 里那条"兜底值陈旧就重查"的保护条件恰好把它排除了：

```js
if (freeEntry && freeEntry.lookup &&
    domainData.expirationDate === 'Auto-Renewal' &&
    !domainData.liveLookup && !domainData.lookupError && !domainData.lookupSkipped) {
```

`lookupError` 非空 → 条件不成立 → 永远不重查，只能等 7 天。

### 根因二：401 的三种情况被压成一句话

`requestOnce()` 在 401/403 时直接返回固定文案，**把响应 body 丢了**。而 DNSHE 的
401 body 恰好区分了两种完全不同的故障（实测）：

```bash
# 不带任何头
$ curl "https://api005.dnshe.com/index.php?m=domain_hub&endpoint=whois&domain=test.cc.cd"
{"error":"Missing API credentials (use X-API-Key and X-API-Secret headers)",
 "error_code":"auth_invalid_credentials"}

# 只带 Key（缺 Secret）
$ curl -H "X-API-Key: cfsd_fakefakefake" "…&endpoint=whois&domain=test.cc.cd"
{"error":"Missing API credentials (use X-API-Key and X-API-Secret headers)"}

# Key + Secret 都带（值是假的）
$ curl -H "X-API-Key: cfsd_fakefakefake" -H "X-API-Secret: fakefakefakefake" "…"
{"error":"Invalid API key"}
```

也就是说：

- 只填 Key → 服务端说 `Missing`，看着像"根本没配"，实际是"配了一半"
- 填错 Key → 服务端说 `Invalid API key`，和"没配"是两回事

原来两种都显示「请检查 DNSHE API Key / Secret 是否正确」，用户没法判断该补 Secret 还是该换 Key。

### 改动

**1. 失败结果单独给短 TTL**

```js
// services/whois.js
function cacheTtlFor(result) {
  if (!result) return undefined;
  if (result.lookupError || result.whoisError) return CONFIG.CACHE_FAILURE_TTL;  // 5 分钟
  return undefined;                                                             // 默认 7 天
}
```

`CacheManager` 支持逐条 TTL（写进缓存体，读时按条目自己的 TTL 判断），内存层也一起遵守。

**2. 改凭证主动失效**

`handleDnsheApi` 的每次写操作（add / update / remove / toggle）之后：

```js
appState.dnsheCredentials = list.filter(item => item.enabled !== false);
appState.whoisService = null;
const purged = await invalidateDnsheCache();   // 按后缀 clearWhere
```

响应里带 `purged`，前端提示「已清掉 N 条旧缓存」。不必等 TTL，也不用点「清除全部缓存」。

**3. 401 提示分三种，并带服务端原话**

```js
authMessage(type, status, detail, hasCredential) {
  if (status === 403) return `${tag} 请求被拒绝（403）：…${tail}`;
  if (!hasCredential) return `${tag} 认证失败（401）：接口要求 API Key + Secret，当前没有可用凭证。…`;
  if (/missing/i.test(detail)) return `${tag} 认证失败（401）：Key 与 Secret 必须成对发送，当前凭证缺少其中一项${tail}`;
  return `${tag} 认证失败（401）：Key / Secret 被服务端拒绝，可能填错或已失效${tail}`;
}
```

**4. 不发半套请求头**

`lookup()` 先筛掉缺 Secret 的凭证，全部不完整时直接返回「凭证不完整」，一个请求都不发——
避免拿到那句会误导人的 `Missing API credentials`。

**5. 环境变量兜底恢复**

`DNSHE_API_KEY` / `DNSHE_API_SECRET` 重新生效（**KV 为空时**才用，页面配置优先）。
DNSHE 页会显示「当前在用环境变量里的凭证」，缺 Secret 时直接点出来。

**6. `CACHE_VERSION` 1.2.0 → 1.3.0**

已经中毒的旧缓存（7 天的 401）在部署后一次性作废，不用手工清 KV。

---

## 三、需求①：ip6.arpa

### 找到了什么

| 查询目标 | IANA RDAP | ARIN RDAP | 结果 |
|---|---|---|---|
| `ip6.arpa` | 200 | 200 | 有 registration 事件：2001-11-10 |
| `d.f.ip6.arpa`（RIR 级委派） | 200 | 404 | 只有 IANA 有 |
| `8.b.d.0.1.0.0.2.ip6.arpa` | 404 | 404 | 无记录 |
| 完整 /64 反向区（32 段 nibble） | 404 | 404 | 无记录 |

`whois.iana.org:43` 也能查到 `IP6.ARPA`，但同样只到 RIR 那一层。

结论：**没有逐区的 WHOIS**。IANA 只登记到 RIR 委派，RIR 侧只支持按 IP 前缀查
（`whois -h whois.arin.net "n + 2001:db8::/32"`），不认反向区名。

### 所以怎么做

不挂 `lookup`，标成 `renew: 'permanent'`：

```js
{
  suffix: 'ip6.arpa',
  category: 'public',
  registrar: 'IANA',
  renew: 'permanent',
  parentRegistered: '2001-11-10',
  provider: 'Hurricane Electric',
  note: 'IPv6 反向解析区（HE.net 免费委派）'
}
```

理由：反向解析区不注册、不续费、不过期，`permanent` 才是准确语义。挂一个对所有真实
反向区都 404 的查询，只会把界面刷成"未注册"或"待设置"——比不查更糟。
`LOOKUP_ENDPOINTS.iana` 保留端点，供排障时手工核对。

---

## 四、需求③：退出登录

| 路由 | 清掉的 cookie | 落地页 |
|---|---|---|
| `GET /logout` | `access_token` | `/login` |
| `GET /admin-logout` | `admin_token` **+** `access_token` | `/admin-login` |

管理页多清一个 `access_token` 是有意的：管理员会话能看到全部账户与凭证，
共用设备上只清 `admin_token` 会留下一个仍能读域名的前台会话。

用 GET 而不是 POST：退出是幂等的清状态操作，做成链接才能在无 JS 时可用。
cookie 是 `SameSite=Strict`，跨站请求带不上，不怕被一张图片登出。

入口放在顶栏（`.topbar-actions`），桌面与移动端都在。未设访问密码的公开站点
不显示前台退出 —— 没有"登录"可退。

---

## 五、验证

```
$ npm run check
▶ 单元测试 … 327/327 通过
▶ 端到端冒烟 … 21/21 项通过
▶ esbuild 打包 … 通过
全部通过
```

本轮新增测试：

| 文件 | 数量 | 覆盖 |
|---|---|---|
| `test/cache.test.js`（新） | 8 | 自定义 TTL 持久化与过期、版本失效、`clearWhere` 精确清理与内存同步 |
| `test/free-domain-lookup.test.js` | +8 | 401 三种提示、服务端原话透传、缺 Secret 不发请求、Key+Secret 成对发送、`ip6.arpa` 永久标记、回显域名校验、多级后缀归属 |
| `test/ui-views.test.js` | +2 | DNSHE 页的环境变量凭证提示（缺 Secret / 已有 KV 凭证时不提示） |
| `scripts/smoke.mjs` | +5 | 两个退出路由、退出后仍需登录、页面退出入口、改凭证清缓存 |

预览页额外确认：

- `admin.html` / `guest.html` 各出现 1 个退出入口（`href="/admin-logout"` / `href="/logout"`）
- 免费域名页渲染出 `ip6.arpa` 行（provider = Hurricane Electric，徽标「公益」）
- 页面正文无 `undefined` / `NaN` / `[object Object]`（残留的 5 处 `undefined` 都在内联脚本源码里）

---

## 六、部署注意

1. 直接 `wrangler deploy` 即可。`CACHE_VERSION` 升级会让旧 WHOIS 缓存整体作废，
   部署后第一次打开页面会重新查询（免费域名有节奏限制，全量刷新会比平时慢）。
2. 之前用 `DNSHE_API_KEY` / `DNSHE_API_SECRET` 环境变量的部署**不用改**：KV 里没有
   凭证时会自动回退到环境变量。
3. 如果 DNSHE 仍报 401，先看提示属于哪一种：
   - 「当前没有可用凭证」→ 去 DNSHE 页加一组，或检查环境变量是否只配了 Key
   - 「缺少其中一项」→ 补上 Secret
   - 「被服务端拒绝（服务端：Invalid API key）」→ Key 填错或已被删除
4. 退出登录是纯前端 cookie 操作，不涉及服务端会话表；改密码后旧 token 会因签名密钥
   变化（`TOKEN_SECRET` 从密码哈希派生）自然失效。

---

## 七、事故复盘：demo.cn.mt 显示成 demo.ccwu.cc

### 现象

用户报告：`demo.cn.mt` 在 DNSHE 后台是 **2026-04-03 → 2028-04-03**、NS 为
`ns1/ns2.dnshe.com`；DSMC 返回的却是 `parent: demo.ccwu.cc`、**2026-08-03 → 2036-08-03**、
NS 为 `tim/sneh.ns.cloudflare.com`。

### 排查

1. **后缀匹配没问题。** 直接跑 `getInfo()`：

   ```
   demo.cn.mt   → parent: cn.mt   | note: 免费 MT 子域名服务 - 子域名
   demo.ccwu.cc → parent: demo.ccwu.cc | note: 免费 CC 子域名服务 - 子域名
   ```

   `match()` 先按后缀长度降序、再逐个 `endsWith('.' + suffix)`，`cn.mt` 一定先命中。
   `match` 里没有 `includes`、没有不带点的 `endsWith`，不存在"被相邻后缀抢走"的路径。

2. **用户贴出的 JSON 与「查询 demo.ccwu.cc」的结果逐字段一致。** 用假 lookup 复现：

   ```
   $ query('demo.ccwu.cc')
   { registrar: 'DNSHE', registrationDate: '2026-08-03', expirationDate: '2036-08-03',
     parent: 'demo.ccwu.cc', description: '免费 CC 子域名服务 - 子域名',
     source: 'builtin', dataSource: 'dnshe', liveLookup: true,
     nameServers: ['tim.ns.cloudflare.com', 'sneh.ns.cloudflare.com'] }
   ```

   连字段顺序都一致。`parent` / `description` / `source` 这三个字段完全由**本地注册表**
   决定（`getInfo(domain)`），不来自 DNSHE；它们指向 `demo.ccwu.cc`，说明传给 `getInfo`
   的域名本身就是 `demo.ccwu.cc`。

3. **结论**：DSMC 收到的是 `/whois/demo.ccwu.cc`，不是 `/whois/demo.cn.mt`。
   最可能是抽屉开在另一行（两个域名都以 `demo` 开头，域名库列表里很容易点错），
   或者贴错了对照对象。

### 顺手修掉的真问题

排查过程里发现了三个会放大这类事故的缺陷，都已修：

| 问题 | 后果 | 修法 |
|---|---|---|
| DNSHE 响应里的 `domain` 字段没被校验 | 上游返回错行时，别人的到期日被静默挂到当前域名上 | `parseDnshe(data, expectedDomain)` 比对回显域名，不一致就丢弃并报错 |
| 抽屉里的 WHOIS 结果只显示一坨 JSON | 把接口外层 `{error, data}` 当域名对象读，字段全 `undefined`，看不出查的是谁 | 正确解包，并输出「查询域名 / dataSource / lookupError」 |
| `/whois/:domain` 无条件回写自定义域名 | 注册表兜底值（`Auto-Renewal`）会覆盖用户手填的到期日 | 只在 `dataSource !== 'registry'` 且无 `lookupError` 时回写 |

现在同一场景会得到明确结论：如果 DNSHE 对 `demo.cn.mt` 返回了 `demo.ccwu.cc` 的记录，
DSMC 会显示

```
实时查询失败：DNSHE 返回了另一个域名的数据（请求 demo.cn.mt，返回 demo.ccwu.cc），已丢弃
```

而不是把 2036-08-03 挂上去。

