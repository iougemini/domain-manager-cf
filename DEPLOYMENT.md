# DSMC - 部署指南

本项目为多模块 ESM 项目（入口 `src/index.js`，依赖 `itty-router`），推荐使用 Wrangler CLI 部署。

## 前置要求

- Node.js 20 或更高版本（推荐 22+：`npm test` 依赖 Node 自带的 glob 展开）
- Cloudflare 账户（免费版即可）
- Cloudflare API Token（需要 `Zone:Read` 权限）
- Wrangler CLI 工具（使用 `npx wrangler` 或全局安装）

## 方式一：使用 Wrangler CLI 部署（推荐）

### 步骤 1: 安装 Wrangler

```bash
# 使用 npm 安装
npm install -g wrangler

# 或使用 yarn
yarn global add wrangler

# 验证安装
wrangler --version
```

### 步骤 2: 登录 Cloudflare

```bash
wrangler login
```

浏览器会自动打开授权页面，点击允许授权。

### 步骤 3: 克隆项目并安装依赖

```bash
git clone https://github.com/iougemini/domain-manager-cf.git
cd domain-manager-cf
npm install
```

### 步骤 4: 创建 KV 命名空间

```bash
wrangler kv namespace create "DOMAIN_INFO"
```

命令执行后会返回：

```
🌀 Creating namespace with title "domain-manager-DOMAIN_INFO"
✨ Success!
Add the following to your configuration file in your kv_namespaces array:
{ binding = "DOMAIN_INFO", id = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }
```

**复制返回的 ID**。

### 步骤 5: 配置 wrangler.toml

仓库里只有模板 `wrangler.toml.example`。**先复制一份再改**：

```bash
cp wrangler.toml.example wrangler.toml
```

`wrangler.toml` 保存的是你自己的 KV ID 与凭证，已在 `.gitignore` 里 —— 它不该进仓库，
也不该出现在任何 PR 里。然后编辑项目根目录的 `wrangler.toml`：

```toml
name = "domain-manager"
main = "src/index.js"
compatibility_date = "2024-01-01"

# KV 命名空间配置
[[kv_namespaces]]
binding = "DOMAIN_INFO"
id = "粘贴您的KV命名空间ID"  # ← 替换为步骤4返回的ID

# Cron 定时任务配置
# 同时承担三件事：清理过期缓存 → 域名健康巡检 → 发送到期提醒与健康告警
# 注意：不配 cron 的话健康巡检永远不会执行，页面上的「健康巡检」会一直是空的
[triggers]
crons = ["0 2 * * *"]  # 每天 UTC 02:00（北京时间 10:00）

# 环境变量配置（仅作兜底）
[vars]
# ADMIN_PASSWORD = "your_admin_password"   # 首次登录用，登录后到设置页改
# WHOIS_PROXY = "https://your-whois-proxy.example.com"  # 可选
```

> **从 v2.2.0 起配置分成两层**：KV 优先、环境变量兜底。账户、密码、DNSHE 凭证、
> 查询节奏、通知渠道都能在页面上改，保存即生效，不需要重新部署。

### 步骤 6: 配置环境变量（首次部署的最小集）

v2.2.0 之后**只需要一个管理员密码**就能跑起来，其余全部在页面上配置。

```bash
# 只配这一个就够：用于首次登录管理后台
wrangler secret put ADMIN_PASSWORD
# 提示输入时，输入您的管理员密码（至少 6 位）
```

部署完成后登录 `/admin`，然后按下面顺序把配置搬进 KV：

| 顺序 | 页面 | 要做的事 | 对应的 KV 键 |
|------|------|---------|-------------|
| 1 | 设置 | 修改访问密码 / 管理员密码（改为哈希存储） | `config:settings` |
| 2 | 账户 | 添加 Cloudflare API Token（保存时会真实校验） | `config:accounts` |
| 3 | DNSHE | 添加 DNSHE Key/Secret（可选，支持多组） | `config:dnshe` |
| 4 | 通知 | 配置到期提醒渠道与规则（可选） | `config:notify` |
| 5 | 免费域名 | 调整免费后缀白名单（可选） | `config:free-domains` |

密码改为哈希存储后，就可以把 `ADMIN_PASSWORD` / `ACCESS_PASSWORD` 从环境变量里删掉了。

**老版本升级（v2.1.0 及更早）**

原有的 `CF_API_KEYS` / `USERNAMES` / `DNSHE_API_KEY` 仍然会被读取。登录后台后：

1. 进「账户」页，会出现「检测到环境变量中的 N 个账户」的提示，点「导入到 KV」
2. 进「设置」页把密码改一遍（旧明文密码仍可登录，改完就变成哈希）
3. 确认功能正常后，再删除旧的环境变量

```bash
# 老配置示例（升级后可以逐步移除）
wrangler secret put CF_API_KEYS
# 输入: ["key1","key2","key3"]

wrangler secret put USERNAMES
# 输入: ["user1","user2","user3"]

wrangler secret put DNSHE_API_KEY
wrangler secret put DNSHE_API_SECRET

wrangler secret put WHOIS_PROXY
# 输入: https://your-whois-proxy.example.com
```

**注意事项**：
- JSON 字符串格式必须严格：`["item1","item2"]`
- ✅ 正确：`["key1","key2","key3"]`
- ❌ 错误：`["key1", "key2", "key3"]`（有空格）
- ❌ 错误：`[key1,key2,key3]`（缺少引号）

**备选方式：在 wrangler.toml 中配置（不推荐）**

`wrangler.toml` 已被 `.gitignore` 忽略，但凭证一旦写进文件，就有被复制、被截图、
被误提交到别的仓库的风险。优先用 `wrangler secret put`。

```toml
[vars]
CF_API_KEYS = '["your_key1","your_key2"]'
USERNAMES = '["user1","user2"]'
ACCESS_PASSWORD = "your_access_password"
ADMIN_PASSWORD = "your_admin_password"
WHOIS_PROXY = "https://your-whois-proxy.example.com"
```

### 步骤 7: 本地测试（可选）

```bash
wrangler dev
```

访问 `http://localhost:8787` 测试功能。

### 步骤 8: 部署到生产环境

```bash
wrangler deploy
```

部署成功后会显示 Worker URL：

```
Published domain-manager (0.01 sec)
  https://domain-manager.your-subdomain.workers.dev
```

### 步骤 9: 验证部署

```bash
# 查看实时日志
wrangler tail

# 查看部署历史
wrangler deployments list
```

## 方式二：使用 Cloudflare 控制面板部署

### 步骤 1: 创建 KV 命名空间

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 导航到 **Workers & Pages** → **KV**
3. 点击 **Create a namespace**
4. 输入命名空间名称：`DOMAIN_INFO`
5. 点击 **Add** 创建
6. **记录生成的 Namespace ID**（后续步骤需要）

### 步骤 2: 创建 Worker

1. 在 Cloudflare Dashboard 中，导航到 **Workers & Pages**
2. 点击 **Create application** → **Create Worker**
3. 输入 Worker 名称，例如：`domain-manager`
4. 点击 **Deploy** 创建 Worker
5. 创建后，点击 **Edit code** 进入代码编辑器

### 步骤 3: 打包并上传代码

本项目为多模块 ESM 项目（入口为 `src/index.js`，并依赖 `itty-router`），无法直接在控制面板的 Quick Editor 中通过粘贴单个源文件部署。请先在本机打包：

```bash
npm install
npx wrangler deploy --dry-run --outdir dist
```

打包产物会生成在 `dist/` 目录。然后在控制面板中：

1. 打开 Worker 的 **Edit code**（Quick Editor）
2. 将 `dist/` 中打包生成的入口文件内容粘贴到编辑器中
3. 点击右上角 **Save and Deploy** 保存并部署

> 💡 **提示**：多模块项目推荐使用方式一（Wrangler CLI），它会自动完成打包与依赖处理，避免手动上传的繁琐。

### 步骤 4: 绑定 KV 命名空间

1. 返回 Worker 详情页面
2. 点击 **Settings** → **Variables**
3. 在 **KV Namespace Bindings** 区域点击 **Add binding**
4. 填写配置：
   - **Variable name**: `DOMAIN_INFO`
   - **KV namespace**: 选择刚才创建的 `DOMAIN_INFO` 命名空间
5. 点击 **Save** 保存

### 步骤 5: 配置环境变量

在 **Settings** → **Variables** 页面。

v2.2.0 起**只需要 `ADMIN_PASSWORD` 一个变量**就能跑起来，其余都在管理后台页面上配置。

##### 必需（首次部署）

| 变量名 | 值示例 | 说明 | 必需 |
|--------|--------|------|------|
| `ADMIN_PASSWORD` | `admin_password` | 管理后台密码，登录后到「设置」页改成哈希存储 | ✅ 是 |

##### 可选（兜底 / 老配置）

| 变量名 | 值示例 | 说明 | 必需 |
|--------|--------|------|------|
| `ACCESS_PASSWORD` | `your_password` | 前端访问密码，留空表示站点公开 | ❌ 否 |
| `CF_API_KEYS` | `["key1","key2"]` | 老版本账户配置，可在「账户」页一键导入 KV | ❌ 否 |
| `USERNAMES` | `["user1","user2"]` | 与 `CF_API_KEYS` 一一对应 | ❌ 否 |
| `DNSHE_API_KEY` | `cfsd_xxxx` | 可在「DNSHE」页管理，支持多组 | ❌ 否 |
| `DNSHE_API_SECRET` | `sk_xxxx` | 同上 | ❌ 否 |
| `WHOIS_PROXY` | `https://your-whois-proxy.example.com` | 不配则 WHOIS 查询返回 N/A | ❌ 否 |
| `TOKEN_SECRET` | 随机字符串 | 会话签名密钥，不配则从密码哈希派生 | ❌ 否 |

**重要提示**：
- `CF_API_KEYS` 和 `USERNAMES` 必须是有效的 JSON 字符串
- 数组长度必须一致（一一对应）
- 使用 **Encrypt** 选项保护敏感信息（推荐）

##### Secrets（推荐）

为了更好的安全性，建议将敏感信息设置为 Secret：

1. 在 **Variables** 区域点击 **Add variable**
2. 勾选 **Encrypt** 选项
3. 添加以下 Secret：
   - `ADMIN_PASSWORD`
   - `ACCESS_PASSWORD`
   - `CF_API_KEYS`
   - `USERNAMES`

### 步骤 6: 配置 Cron Trigger

Cron 同时承担两件事，**建议无论如何都配上**：

1. 清理过期的 KV 缓存
2. 发送到期提醒（通知未启用时这一步直接跳过，不影响清理）

1. 在 Worker 详情页面，点击 **Triggers** → **Cron Triggers**
2. 点击 **Add Cron Trigger**
3. 输入 Cron 表达式：`0 2 * * *`（每天 UTC 02:00 = 北京时间 10:00）
4. 点击 **Add Trigger** 保存

> 想一天检查两次可以填 `0 2 * * *` 和 `0 14 * * *`。注意 Cron 用的是 **UTC**，
> 通知内容里的日期按「设置 → 时区偏移」换算（默认 +8）。
>
> 每次运行最多对 12 个域名做实时查询，其余走缓存——这是为了不超出 `waitUntil`
> 的时间预算。所以提醒反映的是「最近一次已知状态」，不是逐条现查。

### 步骤 7: 完成部署

1. 返回 Worker 详情页面
2. 找到 **Preview** 区域的 Worker URL
3. 访问该 URL，输入 `ACCESS_PASSWORD` 登录
4. 开始使用！

## 部署后验证

### 1. 访问前端

访问您的 Worker URL，应该能看到登录页面。

### 2. 测试登录

使用配置的 `ACCESS_PASSWORD` 登录前端。

### 3. 测试管理后台

访问 `/admin` 路径，使用 `ADMIN_PASSWORD` 登录。

### 4. 检查日志

如果遇到问题，可以实时查看日志：

```bash
wrangler tail
```

## 常见问题

### Q1: 出现 "DOMAIN_INFO is not defined" 错误

**A**: 请确认:
1. 已经创建了 KV 命名空间
2. wrangler.toml 中正确配置了 KV 命名空间的 ID
3. binding 名称必须是 `DOMAIN_INFO` (大小写敏感)

### Q2: 环境变量未生效

**A**:
- 使用 `wrangler secret` 设置的变量需要重新部署才能生效
- 检查 wrangler.toml 中的 `[vars]` 配置是否正确
- 查看部署日志中的环境变量加载提示

### Q3: 如何更新环境变量

**A**:
```bash
# 更新 secret
wrangler secret put ADMIN_PASSWORD

# 然后重新部署
wrangler deploy
```

### Q4: Cron 定时任务未执行

**A**:
确认 wrangler.toml 中配置了:
```toml
[triggers]
crons = ["0 2 * * *"]
```

查看 Cron 执行日志:
```bash
wrangler tail --format pretty
```

### Q5: WHOIS 查询返回 N/A 或失败

**A**: 未配置 `WHOIS_PROXY` 时查询会返回 `N/A`。请自建或使用公共 WHOIS 代理后，通过 `wrangler secret put WHOIS_PROXY` 配置。详见 [README 的自建 WHOIS 代理章节](./README.md#自建-whois-代理可选)。

### Q6: 到期提醒没有推送

按顺序排查：

1. **通知开关**：「通知」页顶部的「启用定时提醒」是否勾上
2. **渠道开关**：渠道列表里每条渠道右侧的开关是否为开启状态，状态列是否显示「已配置」
3. **Cron 是否配置**：`wrangler.toml` 的 `[triggers]` 里是否有 `crons`
4. **内容去重**：域名集合与紧急度分布和上次一样时会被跳过，这是有意的。
   点「立即发送」可以强制推一次
5. **真的没有临期域名**：提醒只包含「提前天数」范围内的域名，且永久域名（2999 年到期）被排除

### Q6: 「健康巡检」一直显示「还没有巡检记录」

**A**: 巡检只在 Cron 里执行，不会在页面渲染时触发（几十个域名的 DNS 探测塞不进渲染预算）。

1. **Cron 是否配置**：`wrangler.toml` 的 `[triggers]` 里要有 `crons`。没配的话巡检永远不会跑
2. **等一轮**：单次最多巡检 40 个域名，且同一域名 20 小时内不重复探测。域名多的话要分几天轮完
3. **看日志**：`wrangler tail` 里搜「巡检结果」，正常会输出 `{"checked":N,"skipped":N,"failed":N,"alerts":N}`
4. **`failed` 偏高**：说明 DoH 探测失败。检查 Worker 能否访问 `cloudflare-dns.com`，
   或该域名所在网络环境的出口是否被限制

巡检结果在 KV 里保留 2 天。如果某天 Cron 失败，页面会沿用前一天的数据，不会突然清空。
6. **看日志**：`wrangler tail` 里搜 `notify`，能看到每个渠道的 HTTP 状态与返回体

### Q7: 通知渠道一直提示「HTTP 400」或签名错误

**A**: 飞书和钉钉的加签算法**不一样**，填错 secret 位置就会一直 400：

- 飞书：`HMAC-SHA256(key = timestamp + "\n" + secret, data = "")`
- 钉钉：`HMAC-SHA256(key = secret, data = timestamp + "\n" + secret)`

另外确认 secret 填的是「加签」密钥，不是 Webhook 地址里的 token。Telegram 报
`chat not found` 通常是没先给 Bot 发过 `/start`。

### Q8: DNSHE 的 Key 只能查自己账户的域名吗

**A**: 分接口看：

- `endpoint=whois`（本项目用来查到期日的那个）是**平台级**，一个有效 Key 能查任意 DNSHE 域名
- `endpoint=subdomains` / `dns_records` / `quota` / `keys` 是**账户级**，只能看到 Key 所属账户下的资源

所以理论上一个 Key 就够用。但为了让某个账户的 Key 过期时不影响全部域名，本项目支持
在「DNSHE」页配多组凭证，遇 401/403 自动切换下一组。

### Q9: 域名到期日显示成 2999 年 / 标记为「永久」

**A**: 这是**正确行为**。DNSHE 把子域名升级为永久后，接口返回的到期日是
`2999-12-31` 这类哨兵日期，本项目识别为「永久域名」并显示紫色徽标，同时把它排除在
到期提醒之外。如果你看到某个域名被误判，检查它的到期日是否真的落在 2900 年之后。

## 更多资源

- [Cloudflare Workers 文档](https://developers.cloudflare.com/workers/)
- [Wrangler CLI 文档](https://developers.cloudflare.com/workers/wrangler/)
- [KV 命名空间文档](https://developers.cloudflare.com/workers/runtime-apis/kv/)
- [Cron Triggers 文档](https://developers.cloudflare.com/workers/configuration/cron-triggers/)
- [WHOIS代理自部署仓库](https://github.com/zmh-program/next-whois) - 可选的自建WHOIS服务

## 支持

如果遇到其他问题,请检查:
1. README.md - 查看使用说明
2. CHANGELOG.md - 查看更新记录
3. src/ - 查看代码实现
4. wrangler.toml - 确认配置正确
