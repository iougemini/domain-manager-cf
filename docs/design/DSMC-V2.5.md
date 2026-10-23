# DSMC v2.5.0 · 手动添加域名改为「先查 WHOIS，查不到再补」

## 一、起因

用户有一个 DNSHE 域名 `otime.cn.mt`，因为不能挂到 Cloudflare，只能手动加进 DSMC。
实际用下来有三个卡点：

1. 添加弹窗要求填注册商、注册日期、**到期日期（必填）**、DNS 服务商 —— 这些
   本该是查出来的，不是让人抄的；
2. 加完想改信息，唯一显眼的入口是「标记已续费」——用续费的名义改数据，语义错位；
3. 点下去还弹一句「将关闭该域名的 WHOIS 自动更新」，用户会以为改一次就再也不更新了。

第 3 点其实是事实：编辑接口无条件写 `autoUpdateWhois: false`，连只改备注也一样。

## 二、新流程

```
点「添加域名」
  └─ 只填：域名、备注（可选）
       └─ 提交 → 强制查一次 WHOIS（不吃旧缓存）
            ├─ 查到 → 注册商/注册日期/到期日/NS 写入 KV，lookupStatus = ok
            └─ 查不到 → 域名照样入库，lookupStatus = missing
                         └─ 前端立刻弹出补填表单，顶部带失败原因
                              └─ 保存 → autoUpdateWhois = false，lookupStatus = manual
```

几个刻意的选择：

- **查不到也要入库**。不然用户点了「取消」就什么都没有，下次还得从头来一遍。
  入库后列表里显示「待补充」，抽屉主操作是「补充信息」。
- **强制刷新**。缓存里可能躺着一条早前的失败记录（比如 DNSHE 凭证还没配好时
  查过一次），不跳过缓存的话用户刚加完就看到"查不到"，会以为功能坏了。
- **补填表单直接弹出来**，而不是提示「请到列表中编辑」。少一步就少一次困惑。

## 三、自定义域名现在会自己更新

`fetchDomainInfo` 原来对自定义域名是这么写的：

```js
if (domain.isCustomDomain) {
  processedDomain = { ...domain, registrar: domain.customInfo.registrar, ... };
}
```

直接读 KV 里那条记录，**等于只查了添加那一刻**。之后不管续费多少次，页面上的
到期日永远停在第一次的值 —— 这就是用户必须靠「标记已续费」硬改的根本原因。

现在只要 `autoUpdateWhois !== false`，就照常查一次（命中缓存时没有网络成本），
本地记录退化成兜底值。合并规则抽到 `src/services/domain-merge.js`：

| 情况 | 结果 |
|---|---|
| 实时值有意义 | 用实时值 |
| 实时值是 `N/A` / `Unknown` / `Error` | 回退本地值 |
| 两边都没有到期日 | `lookupStatus = missing`，把查询错误透传给 UI |
| 用户手工改过（`autoUpdateWhois === false`） | 以本地为准，来源标「手动维护」 |

「有没有拿到到期日」单独表达成 `lookupStatus`，UI 靠它决定显示正常状态还是
提示补填。**查到了还挂错误提示**是不允许的 —— 用户会以为这条数据不可信。

## 四、什么时候才冻结自动更新

编辑接口改成先比对三个日期类字段：

```js
const touched = ['registrar', 'registrationDate', 'expirationDate']
  .some(k => norm(info[k]) !== norm(existing[k]));
```

- 动了 → `autoUpdateWhois = false`、`lookupStatus = manual`
- 只改备注 → 保持原来的开关不动

弹窗文案也跟着改成「改了注册商或日期，就以你填的为准并停止 WHOIS 自动更新；
只改备注不受影响」。

## 五、顺手修掉的三个 bug

### 1. 「刷新」会偷偷续期

`handleRefreshAction` 对免费域名有这段逻辑：读到本地到期日 → **+1 年** → 写回 KV →
再返回。用户点「刷新 WHOIS」的本意是"去查最新的"，结果先被改了一年。而且它
`return` 得早，后面的真实查询根本没执行。

改成：刷新就只刷新，查到真数据再回写。续期只走「标记已续费」（显式传新日期）。

### 2. 注册日期是伪造的

`addDomain` 里 `registrationDate: info.registrationDate || new Date().toISOString().split('T')[0]`
—— 查不到真实注册日就写今天。页面会显示一个假值，而且后续自动更新看到
"已经有值了"就不再覆盖。改成 `'Unknown'`。

### 3. 注册日缺失导致状态判成「未知」

`statusOf` 原来要求到期日和注册日都有值，否则一律「未知」。但很多注册局
根本不返回 creation date（DNSHE 就是），于是一个到期日明确、明天就要续费的域名
会被标成「未知」，直接掉出「临期」筛选和到期提醒。

改成只看到期日。注册日期为空时页面显示 `—`，不影响任何判断。

## 六、测试

冒烟测试的假 KV 以前不支持 `get(key, { type: 'json' })`，直接返回字符串。后果：

- 审计日志写入时 `existingLogs.unshift is not a function`，异常被 catch 吞掉
  → **审计日志在冒烟里从没写成功过**
- 限流器 `kv.get(key, {type:'json'})` 同样拿到字符串，`data.count` 恒为 undefined
  → **限流从没生效过**，一个安全功能完全没被验证

补上解析后立刻暴露了第二个问题：连续登录会把测试 IP 锁 30 分钟，后面的检查全挂。
所以在每项检查前重置 `ratelimit:` 前缀，并把「连续失败登录返回 429」单独做一项
检查放在最后。

```
npm run check
  单元测试     367/367 通过
  端到端冒烟   27/27 项通过
  esbuild 打包  通过
```

新增测试：

- `test/domain-merge.test.js`（11）：实时优先、`N/A` 回退、两边都空标 missing、
  手工记录不覆盖、2999 识别永久、NS 回退、`pending` 透传
- `test/whois-budget.test.js`（+1）：`forceRefresh` 不读缓存
- 冒烟（+5）：新增域名落库并提示补填、重复添加 409、只改备注不冻结、
  改日期才冻结、连续登录失败 429

## 七、数据兼容

老记录不需要迁移：

- `lookupStatus` 缺失时，`mergeCustomDomainRecord` 会按"有没有到期日"现算
- 老记录里被伪造的注册日期（等于添加当天）无法自动识别，但会在下一次
  实时查询成功时被真实值覆盖
- `autoUpdateWhois: false` 的老记录保持冻结，行为不变

## 八、部署注意

无新增环境变量、无 KV 键变更、`CACHE_VERSION` 不变（缓存体结构没动）。
直接部署即可，旧缓存继续可用。
