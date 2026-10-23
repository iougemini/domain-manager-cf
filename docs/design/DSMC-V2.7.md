# DSMC v2.7.0 — 从「到期台账」到「域名巡检」

## 一、问题

v2.6.0 之前，整个系统只有一条时间线：**距离到期还有多少天**。

这条线管的是未来的事，而域名出事往往不在到期那天：

| 现象 | 真实原因 | 旧版显示 |
|---|---|---|
| 站点打不开 | 注册商暂停解析（`clientHold`，邮箱未验证/欠费） | 「正常 · 还有 240 天」 |
| 站点打不开 | 域名被注册局摘除（`NXDOMAIN`） | 「正常 · 还有 159 天」 |
| 域名突然消失 | `pendingDelete`，几天后释放 | 「临期」 |
| NS 被改走 | 解析指向别处 | 无感知 |

更具体的一个证据：`whois.js` 的普通 WHOIS 路径**从来没解析过 `status` 字段**，
而 RDAP 本来就会返回它。也就是说"域名被暂停"这个信号一直能拿到，只是被丢掉了。
免费域名路径解析了 `status`，但它随后又被 `data.js` 里一行
`d.status = statusOf(d)` 覆盖成了前端状态对象。

**数据已经在手里，只是没有走到眼前。**

## 二、两层巡检

### 注册层：EPP 状态分级

RDAP / WHOIS 的 `status` 是 EPP 状态码。关键判断是：**哪些该报警**。

```
danger  clientHold          注册商暂停解析 —— 站点已不可用
        serverHold          注册局暂停解析
        pendingDelete       已进入删除流程
        redemptionPeriod    已过期，处在赎回期

warn    pendingRestore      恢复处理中
        autoRenewPeriod     自动续费宽限期

info    pendingTransfer     转移中（纯信息）
        pendingRenew / Create / Update

ok      clientTransferProhibited    ← 陷阱在这里
        clientDeleteProhibited
        clientUpdateProhibited
        clientRenewProhibited
        active / ok / associated
```

**`clientTransferProhibited` 是最大的坑。** 几乎每个正常域名都带它（防盗保护），
有些还带 delete/update 变体。把它算成异常，整张表立刻全红，然后告警就没人看了。
`test/registry-status.test.js` 里专门有一组测试盯这条线。

归一化要认四种写法：`clientTransferProhibited` / `client transfer prohibited` /
`CLIENT TRANSFER PROHIBITED` / `client_transfer_prohibited`。

### 解析层：DNS 四态

用 DoH（`https://cloudflare-dns.com/dns-query`）并行查 A / AAAA / CNAME，
结果必须分成四类，不能只分"通/不通"：

| 结果 | 含义 | 是否报警 |
|---|---|---|
| `ok` | 查到至少一条地址记录 | 否 |
| `nxdomain` | DNS 返回 NXDOMAIN，**域名不存在** | **是** |
| `nodata` | NOERROR 但无地址记录，域名存在只是没配 | 否 |
| `error` | 探测本身失败（网络/超时/502） | 否 |

`nxdomain` 与 `nodata` 必须分开。前者是事故（过期被摘、NS 改走、注册局删除），
后者是常态（囤着没启用的域名）。混成一个状态，要么漏报事故，要么天天误报。

`error` 同理：探测器自己坏了，不代表域名坏了。

## 三、巡检为什么不放在渲染路径上

页面渲染有 4 秒预算（`CONFIG.PAGE_LOOKUP_BUDGET`）。几十个域名 × 3 个 DoH 请求，
塞不进去；而且"用户打开页面"这个时刻本来也不该决定"要不要探测"。

所以：

```
Cron（每天）                              页面渲染
  ├─ collectDomainsForDigest（有界）        ├─ readHealthBatch（只读 KV）
  ├─ runHealthCheck                        ├─ normalizeDomains（读 summary）
  │   ├─ 每域名 DNS 探测                   └─ 渲染
  │   ├─ 注册局状态取自 WHOIS 缓存（无额外请求）
  │   └─ 写 KV health:<domain>（TTL 2 天）
  └─ runDigest（到期摘要 + 健康告警）
```

调度参数：

- `maxDomains = 40`：单轮上限。Cron 有执行时长限制，宁可分几天轮完，也不要一次超时全丢
- `CONCURRENCY = 4`：DoH 并发。同时发几十个请求会被公共解析服务限速
- `minIntervalMs = 20h`：同一域名 20 小时内不重复探测
- TTL 2 天：每天巡检一次，留一天冗余，某次 Cron 失败不至于整片空白

**轮转不丢告警**：单轮只巡检 40 个，但告警基于 KV 里的**全部**记录汇总。
本轮没轮到的域名用的是上一轮结论，不会因为轮转顺序而漏报。

## 四、结论在服务端算好

`runHealthCheck` 写 KV 时会带上 `summary`：

```json
{
  "dns": { "status": "nxdomain", "records": {...}, "checkedAt": "..." },
  "registry": { "status": ["client hold"] },
  "summary": {
    "level": "danger", "dns": "nxdomain", "dnsLabel": "解析丢失",
    "registry": { "level": "danger", "suspended": true, "labels": ["注册商暂停解析"], "codes": ["clienthold"] },
    "problems": [{ "kind": "registry", "label": "注册商暂停解析", "level": "danger" }],
    "checkedAt": "..."
  }
}
```

**UI 只读结论，不再自己判一遍。**

理由：`src/ui/data.js` 会进客户端 bundle，按约定不能 import 服务端模块。
如果让它在客户端重新判一次，EPP 状态码字典就要在 `data.js` 里复制第二份，
两份迟早漂移，最后出现"通知说异常、页面说正常"这种最难查的错。

## 五、主状态优先级

`statusOf()` 的顺序（从高到低）：

```
1. whoisError        → 查询异常
2. registryAlert     → 已暂停 / 赎回期 / 即将删除     group: suspended
3. dnsLost           → 解析丢失                      group: suspended
4. isPermanent       → 永久
5. Auto-Renewal      → 自动续期
6. pending           → 查询中
7. setup / unknown   → 待补充 / 未知
8. 到期判定          → 已过期 / 临期 / 正常
```

注册局异常排在到期判定之前，是因为**已暂停的域名往往还剩几百天到期**。
落在后面的分支上，`statusCallout` 会输出「状态正常，距到期还有 240 天」——
这是整个界面里最误导人的一句话。

同理，`meter()` 对 `group === 'suspended'` 强制标红：红色徽标配绿色进度条，
扫一眼会以为这个域名没事。

## 六、通知：两条消息，不是一条

健康告警**独立推送**，与到期摘要各自去重（`lastFingerprint` / `lastHealthFingerprint`）。

原因：

- 到期提醒是「提前预告」—— 还有 30 天，安排个时间处理就行
- 健康告警是「现在出事了」—— 站点已经打不开

两者紧急程度差一个量级。混在一条里，用户扫一眼看到"30 个域名待处理"，
就不会注意到其中一个是 `clientHold`。

去重指纹取「域名 + 问题描述」：同一批异常不重复发，异常消失后再次出现要能重新发。

## 七、本轮踩到的坑

1. **`test/_fake-kv.js` 不支持 `get(key, { type: 'json' })`**
   读缓存永远返回字符串，`typeof raw === 'object'` 恒为 false，
   巡检记录等于从没读到过。这类假通过不报错，只会让功能静默失效
   （v2.6 的审计日志与限流器也栽在同一个坑上）。已修，并让 `put` 记录 `expirationTtl`。

2. **`shell.js` 的 `status` 投影漏了 `group`**
   抽屉靠 `d.status.group === 'suspended'` 判断是否暂停，缺了这个字段不会报错，
   只是判断恒为 false，于是已暂停的域名仍然主推「标记已续费」。
   新增 `test/ui-projection.test.js` 盯投影完整性。

3. **`summarizeRecord` 的 `checkedAt` 位置**
   记录顶层与 `summary` 里都有。只读 `summary` 的话，某些写入路径会让详情页
   显示「—」。`normalizeDomains` 改成两处都取。

4. **donut 分项合计 ≠ 总数**
   加「异常」状态时最初只在 chip 和表格里体现，环形图没加，
   于是总数 77 而分项合计 76。分项必须自洽。

5. **排序用了 `-1` 而不是 `-1e9`**
   已过期域名的 `days` 是负数（`-37` 比 `-1` 更小），
   结果「已过期 37 天」排在「已被暂停」前面，而后者才是站点已经挂了的那个。

## 八、验证

- `npm run check`：**448 单测 + 28 冒烟 + 打包**全过
- 新增测试：`registry-status`(15)、`dns-check`(12)、`health-store`(21)、
  `ui-health-status`(15)、`ui-projection`(5)
- 预览截图（`design/preview/`）：
  - `shot-overview-v27.png` 概览页显示「1 个域名注册局状态异常」
  - `shot-domains-v27.png` 异常域名置顶、chip 红色描边、进度条标红
  - `shot-drawer-held.png` 已暂停域名：主徽标「已暂停」、状态码 `clienthold`、
    底部无「标记已续费」
  - `shot-drawer-lost.png` 解析丢失域名：主徽标「解析丢失」、`NXDOMAIN` 说明

## 九、后续

- **证书层**：CF 托管域名可走 Zone API 拿 Universal SSL 状态；非 CF 域名需要
  第三方通道，稳定性要实测
- **可用性拨测**：定时请求首页判断 HTTP 状态与响应时间，需要频控与失败去重
- **NS 漂移**：与 WHOIS 里的 `nameServers` 对比，检测 NS 被改走
