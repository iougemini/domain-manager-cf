# DSMC — Domain Status Manager for Cloudflare

<div align="center">

<img src="./logo.svg" width="120" height="120" alt="DSMC — Domain Status Manager for Cloudflare">

--- 
![Version](https://img.shields.io/badge/version-2.7.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange.svg)

**DSMC — Domain Status Manager for Cloudflare**

基于 Cloudflare Workers 的域名状态管理系统，支持多账户域名统一管理、WHOIS/RDAP 查询、到期提醒、免费二级域名自动识别等功能。

[功能特性](#功能特性) • [快速开始](#快速开始) • [部署指南](#部署指南) • [配置说明](#配置说明) • [使用文档](#使用文档)

</div>

---

## 📋 目录

- [关于项目名称](#关于项目名称)
- [功能特性](#功能特性)
- [技术架构](#技术架构)
- [快速开始](#快速开始)
- [部署指南](#部署指南)
- [配置说明](#配置说明)
- [使用文档](#使用文档)
- [故障排查](#故障排查)
- [更新日志](#更新日志)
- [贡献指南](#贡献指南)
- [许可证](#许可证)

---

## 关于项目名称

**从 v2.0 版本开始，本项目正式更名为 DSMC（Domain Status Manager for Cloudflare）。**

| 阶段 | 名称 | 形态 |
|---|---|---|
| v1 及更早 | `domain-manager` | 单文件 `workers.js`，5841 行 |
| v2.0 起 | **DSMC** | 模块化架构，`src/` 下按职责分层 |

更名的由来：这个项目最初只做「把域名列出来、告诉你什么时候到期」，叫 `domain-manager`
还算贴切。但随着巡检、通知、免费域名识别这些能力加进来，它真正管的是**状态**——
域名还能不能用、解析有没有丢、注册局有没有把解析停掉、证书和续费还有多久。
「状态」比「管理」更接近它现在做的事，于是 v2.0 定了 DSMC 这个名字。

更名不影响已部署的实例：`wrangler.toml` 里的 Worker 名称保持 `domain-manager` 没有改，
KV 命名空间与自定义域名都照旧。**改 Worker 名称等于新建一个 Worker**，绑定与域名全部要重来，
所以仓库名变了、部署名不变是有意为之。

---

## ✨ 功能特性

### 核心功能
- 🔐 **多账户管理** - 多个 Cloudflare 账户的域名统一管理，页面内增删改查
- 📊 **域名总览** - 实时查看所有域名状态、注册商、到期时间
- 🔍 **WHOIS 查询** - 集成 WHOIS 代理服务，快速查询域名信息
- 🩺 **域名巡检** - 注册局状态（`clientHold` / `pendingDelete` / 赎回期）与 DNS 解析双通道探测。
  定时任务执行，异常域名置顶显示并单独推送告警；解析正常但未配地址的域名不误报
- 🏷️ **免费域名识别** - 内置免费/公益后缀表，自动匹配注册商，支持 RDAP / DNSHE / WHOIS-TCP 实时查询
- ♾️ **永久域名标记** - 到期日为 2999 年（DNSHE 升级永久）的域名自动标记为「永久」，不参与到期告警
- ⚙️ **KV 动态配置** - 白名单、账户、密码、查询节奏都在页面内改，60 秒内生效，无需重新部署
- 🔔 **到期通知** - 9 个内置渠道（飞书/钉钉/企业微信/Telegram/Server酱/PushPlus/Bark/邮件/Webhook），由 Cron 每天推送
- 🏷️ **自定义标签** - 为域名添加自定义标签，便于分类管理

### 高级特性
- 🔄 **智能缓存** - KV 存储缓存 WHOIS 数据，降低查询延迟
- 🔒 **安全认证** - 基于 HMAC-SHA256 的 Token 认证机制
- 🔐 **密码哈希存储** - PBKDF2-HMAC-SHA256（30000 轮）+ 随机盐，KV 里不存明文密码
- 🚪 **退出登录** - 前台与管理页各有退出入口，清 cookie 后回登录页
- 📱 **响应式设计** - 支持桌面端和移动端访问
- 🌙 **深色模式** - 提供舒适的深色主题
- ⚡ **无服务器架构** - 基于 Cloudflare Workers，零服务器维护成本
- 🔧 **灵活配置** - 环境变量与 KV 双层配置，环境变量只作兜底

### 管理功能
- 🛠️ **账户管理** - 可视化管理 Cloudflare API Token，支持单个/批量连通性测试
- 🔑 **DNSHE 凭证管理** - 多组 Key/Secret，遇 401/403 自动切换到下一组
- ⚙️ **系统设置** - 访问密码、管理员密码、会话时长、WHOIS 代理、查询节奏集中配置
- ➕ **添加即查询** - 手动添加域名只需填域名，自动查一次 WHOIS 并落库；查不到才让你补填
- 📈 **使用统计** - 查看 API 密钥使用情况和错误统计
- 🗑️ **自动清理** - 定时清理过期缓存数据（Cron Job）
- 🔐 **双重密码** - 前端访问密码 + 管理后台密码，安全可靠

---

## 🏗️ 技术架构

> **项目演进**：本项目最初是一个 5841 行的单体 `workers.js`，所有逻辑集中在单个脚本中。随着功能增长，单体文件在可维护性、可测试性和协作上逐渐受限，因此从 **v2 版本** 开始，项目重构为模块化架构。**v1 及之前为单文件历史版本**，v2 起在 `src/` 下以多模块方式开发。

### 为什么将单文件拆分为多模块？

- **可维护性**：42 个职责单一模块（根 11 / managers 11 / services 9 / ui 11）取代 5841 行单体，
  定位与改动成本更低
- **可测试性**：模块边界清晰，可独立编写单元测试（当前 448 例全部通过）
- **可读性**：按职责分层（入口/编排/业务/基础工具），依赖方向单一
- **安全性**：配置、认证、限流集中为独立模块，便于统一加固与审计
- **协作性**：模块边界清晰，多人并行开发互不干扰

### 前端技术
- **原生 JavaScript** - 无框架依赖，轻量高效
- **现代 CSS** - Flexbox/Grid 布局，响应式设计
- **深色主题** - CSS 变量实现主题切换

### 后端技术
- **Cloudflare Workers** - Edge Computing 平台
- **KV 存储** - 分布式键值存储，用于缓存和配置
- **Cron Triggers** - 定时任务支持

### 安全机制
- **HMAC-SHA256** - Token 签名验证
- **环境变量** - 敏感信息隔离
- **输入验证** - XSS/SQL注入防护

### 页面加载为什么快

页面慢的根源不是前端体积，而是「每个请求都把整条链路重算一遍」。现在做了四件事：

| 手段 | 省掉什么 | 量级 |
|---|---|---|
| Zone 列表缓存 2 分钟（进程内 + KV） | 一次到 `api.cloudflare.com` 的往返 | 200–600ms |
| `CacheManager` 跨请求复用 | 每个域名一次 KV 读（几十次） | 300ms+ |
| 渲染时间预算 + 后台补全 | 冷缓存时等第三方接口 | 数十秒 → 4s 封顶 |
| ETag / 304 | 数据没变时的整页重传 | 全量 → 几十字节 |

第三条要展开说：DNSHE 公共接口按 2 秒一个排队，几十个域名全量查一遍要一分多钟。
现在页面渲染只给 4 秒预算，超出后切「只读缓存」——已缓存的照常显示，没缓存的
标成「查询中」，由 `ctx.waitUntil` 在后台补完，页面顶部会提示还有几个在查。
用户看到的是「马上有内容 + 慢慢变全」，而不是白屏转圈。

---

## 🚀 快速开始

### 前置要求

- Node.js 20 或更高版本（推荐 22+：`npm test` 依赖 Node 自带的 glob 展开）
- Cloudflare 账户（免费版即可）
- Cloudflare API Token（需要 `Zone:Read` 权限）
- Wrangler CLI 工具（使用 `npx wrangler` 或全局安装）

### 最简部署

1. **克隆本仓库**
   ```bash
   git clone https://github.com/iougemini/DSMC.git
   cd DSMC
   ```
2. **安装依赖**
   ```bash
   npm install
   ```
3. **创建 KV 命名空间**（记录返回的 ID）
   ```bash
   npx wrangler kv:namespace create "DOMAIN_INFO"
   ```
4. **从模板生成本地配置**
   ```bash
   cp wrangler.toml.example wrangler.toml
   ```
   `wrangler.toml` 已被 `.gitignore` 忽略 —— 它保存的是你自己的 KV ID 与凭证，不该进仓库。
5. **填写 KV ID**：把上一步返回的 ID 填进 `[[kv_namespaces]]`，按需配置环境变量（见[配置说明](#配置说明)）
6. **部署**
   ```bash
   npx wrangler deploy
   ```

详细步骤请查看[部署指南](#部署指南)。

---

## 📦 部署指南

本项目为多模块 ESM 项目，支持两种部署方式，推荐使用 Wrangler CLI（自动打包与依赖处理）。

### 快速部署（Wrangler CLI）

```bash
git clone https://github.com/iougemini/DSMC.git
cd DSMC
npm install
cp wrangler.toml.example wrangler.toml
wrangler kv:namespace create "DOMAIN_INFO"   # 记录返回的 ID
# 编辑 wrangler.toml 填入 KV ID，并按需配置环境变量
wrangler deploy
```

### 使用 Cloudflare 控制面板

项目为多模块 ESM 项目，需先在本地打包（`npx wrangler deploy --dry-run --outdir dist`）再上传到控制面板。

---

📄 **完整部署步骤**（两种方式的详细步骤、环境变量、KV 绑定、Cron、故障排查）请查看 → [部署文档](./DEPLOYMENT.md)

---

## ⚙️ 配置说明

### 配置的两层结构

从 `v2.2.0` 起配置分成两层，**KV 优先、环境变量兜底**：

1. **KV（推荐）** - 登录管理后台后在页面上直接改，保存即生效
2. **环境变量** - 只在 KV 里没有对应项时生效，用于首次部署引导或 CI 注入

| KV 键 | 页面入口 | 内容 |
|-------|---------|------|
| `config:accounts` | 账户 | Cloudflare 账户列表（Token、用户名、备注、启停状态） |
| `config:settings` | 设置 | 访问/管理员密码哈希、会话时长、WHOIS 代理、查询节奏 |
| `config:dnshe` | DNSHE | DNSHE API Key 列表（支持多组，401/403 自动切换） |
| `config:notify` | 通知 | 通知渠道与到期提醒规则 |
| `notify:state` | 通知 | 上次推送时间、内容指纹、各渠道结果（自动维护） |
| `config:free-domains` | 免费域名 | 免费/公益域名后缀白名单 |

### 环境变量列表（兜底）

| 变量名 | 类型 | 说明 | 默认值 | 必需 |
|--------|------|------|--------|------|
| `ADMIN_PASSWORD` | 字符串 | 管理后台密码（首次登录用，之后可在设置页改成哈希） | （空） | ❌ 否 |
| `ACCESS_PASSWORD` | 字符串 | 前端访问密码（留空表示站点公开） | （空） | ❌ 否 |
| `CF_API_KEYS` | JSON数组 | Cloudflare API 密钥列表（可在账户页一键导入 KV） | `[]` | ❌ 否 |
| `USERNAMES` | JSON数组 | 对应的用户名列表（与 API 密钥一一对应） | `[]` | ❌ 否 |
| `DNSHE_API_KEY` | 字符串 | DNSHE API Key（可在设置页管理） | （空） | ❌ 否 |
| `DNSHE_API_SECRET` | 字符串 | DNSHE API Secret | （空） | ❌ 否 |
| `WHOIS_PROXY` | 字符串 | WHOIS 代理服务地址 | （空，未配置时返回 N/A） | ❌ 否 |
| `TOKEN_SECRET` | 字符串 | 会话 token 签名密钥 | 从密码哈希派生 | ❌ 否 |

> 首次部署只需要 `ADMIN_PASSWORD`（或直接用默认密码登录后立刻修改）。所有配置都能在页面上补齐。

### 关于 DNSHE API Key 的作用域

DNSHE 的接口分两类，**权限范围不一样**：

| 接口 | 作用域 | 说明 |
|------|--------|------|
| `endpoint=whois` | **平台级** | 一个有效 Key 可以查询**任意** DNSHE 域名的注册信息 |
| `endpoint=subdomains` / `dns_records` / `quota` / `keys` | **账户级** | 只能看到 Key 所属账户下的资源 |

因此本项目把 DNSHE 凭证做成了**多组可并存**：即使某个账户的 Key 过期，只要还有一组可用，域名查询就不会整体失效（遇 401/403 自动切下一组）。

**401 排查**：`whois` 端点要求 `X-API-Key` 与 `X-API-Secret` **成对**发送。只填 Key 会拿到
`Missing API credentials (use X-API-Key and X-API-Secret headers)`——看起来像"根本没配"，实际是"只配了一半"。
两种情况的提示已经分开，凭证被拒时还会带上服务端原话（如 `Invalid API key`）。

认证失败的结果只缓存 **5 分钟**，改完凭证刷新即可生效；服务端也会在保存凭证时主动清掉这些后缀的旧缓存。

**数据核对**：`whois` 响应里带 `domain`，DSMC 会拿它和请求的域名比对，不一致就整条丢弃并提示
「DNSHE 返回了另一个域名的数据」。抽屉里的 WHOIS 结果第一行是「查询域名: xxx」，
可以据此确认这条数据到底属于哪个域名。

### 获取 Cloudflare API Token

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 点击右上角头像 → **My Profile**
3. 选择 **API Tokens** 标签
4. 点击 **Create Token**
5. 选择 **Custom Token** 或使用模板
6. 配置权限：
   - **Zone** - **Zone** - **Read**
   - **Zone** - **DNS** - **Read**（可选，用于 DNS 记录查询）
7. 设置 **Zone Resources**（选择要管理的域名）
8. 点击 **Continue to summary** → **Create Token**
9. **复制生成的 Token**（只显示一次）

### 自建 WHOIS 代理（可选）

本项目通过 `WHOIS_PROXY` 环境变量接入 WHOIS 查询服务。**未配置时 WHOIS 查询会返回 `N/A`，不影响其他功能正常运行**，因此你可以选择使用公共代理、自建代理、或完全禁用 WHOIS 查询。

#### 为什么建议自建？

公共 WHOIS 代理通常存在以下限制：
- **速率限制**：短时间内大量查询容易被限流甚至封禁
- **稳定性**：公共服务的可用性和响应延迟不受控制
- **隐私性**：你查询的域名列表会经过第三方服务器

自建代理部署成本极低（免费即可），可以完全掌控查询频率、数据流向与服务可用性。

#### 代理服务需要实现的 API 契约

本工具会采用以下 HTTP 请求查询 WHOIS 信息，任何实现该契约的服务都可以直接接入：

**请求**

```
GET {WHOIS_PROXY}/api/lookup?query={要查询的域名}
```

请求头：
- `Accept: application/json`
- `User-Agent: DSMC/2.7.0`
- `Cache-Control: no-cache`

请求默认超时 30 秒，失败后自动重试（最多 3 次）。

**响应**（HTTP 200，JSON）

```json
{
  "status": "ok",
  "result": {
    "registrar": "GoDaddy.com, LLC",
    "creationDate": "2020-01-15",
    "expirationDate": "2025-01-15"
  }
}
```

工具会从响应中解析三个字段：**注册商**（`registrar`）、**注册日期**（`registrationDate`）、**到期日期**（`expirationDate`）。字段名兼容多种写法：

| 用途 | 可识别的字段名 |
|------|---------------|
| 注册商 | `registrar`、`registrarName`、`sponsoringRegistrar` |
| 注册日期 | `creationDate`、`created`、`registrationDate` |
| 到期日期 | `expirationDate`、`expires`、`expiry` |

若响应中没有上述标准字段，也可返回 `rawWhoisContent`（WHOIS 原始文本），工具会自动用正则从中提取。当全部关键字段都无法识别时，字段值会标记为 `Unknown`。

**错误响应**：设置错误标记即可，例如：

```json
{ "error": true, "message": "domain not found" }
```

或

```json
{ "status": "error", "message": "query rate limited" }
```

#### 推荐部署方案

1. **next-whois**（开箱即用）
   - 仓库地址：https://github.com/zmh-program/next-whois
   - 部署平台：Vercel / Cloudflare Pages / 自托管（Docker / Node.js）
   - 部署后得到形如 `https://<your-deploy>.vercel.app` 的地址，即可接入（具体接口路径请以该项目文档为准）

2. **自定义实现**（更灵活）
   - 在 Cloudflare Worker 或任意 Serverless 平台上，按照上述 API 契约实现一个简单的转发服务
   - 内部对接任意 WHOIS 数据源（如系统 `whois` 命令、第三方 API 等）

#### 接入配置

部署完成后，将代理地址设置到 `WHOIS_PROXY` 环境变量：

```bash
wrangler secret put WHOIS_PROXY
# 输入: https://your-whois-proxy.example.com
```

或在 Cloudflare 控制面板的 **Variables** 中添加 `WHOIS_PROXY` 变量。

---

## 📖 使用文档

### 前端功能

#### 登录
1. 访问 Worker URL
2. 输入 `ACCESS_PASSWORD`
3. 点击登录

#### 退出登录
顶栏右上角的退出图标（→ `/logout`）会清掉 `access_token` 并回到登录页。
管理页的退出（→ `/admin-logout`）会把 `admin_token` 与 `access_token` 一起清掉——
管理员会话能看到全部账户与凭证，共用设备上只清一半等于没退。

#### 查看域名列表
- **域名总览**：显示所有账户的域名
- **筛选功能**：按注册商、到期时间筛选
- **搜索功能**：快速搜索域名
- **状态标识**：
  - 🔴 红色「已暂停 / 解析丢失」：注册局暂停了解析，或域名已经查不到 —— **站点当前打不开**
  - 🔴 红色：7 天内到期
  - 🟡 黄色：30 天内到期
  - 🟢 绿色：正常

#### 域名巡检

到期日管的是「未来某天会失效」，巡检管的是「现在还能不能用」。域名被注册商暂停时
（常见原因是注册邮箱未验证或欠费），列表里往往还安静地显示「还有 240 天」——所以
巡检结论的优先级排在到期判定之前。

- **注册层**：解析 RDAP/WHOIS 的 EPP 状态码。`clientHold`（注册商暂停解析）、
  `serverHold`、`pendingDelete`、赎回期判为异常；`clientTransferProhibited` 这类
  防盗锁**不算异常**（几乎每个正常域名都带着它）
- **解析层**：通过 DoH 查 A / AAAA / CNAME，分四种结果 —— 正常 / `NXDOMAIN`
  （域名不存在，事故）/ `nodata`（存在但没配地址，囤域名的常态，不报警）/ 探测失败
- **什么时候跑**：只跑在 Cron，不占页面渲染时间。结果写进 KV（`health:<domain>`，2 天过期），
  打开页面只读结论。单轮最多 40 个域名、并发 4、20 小时内不重复探测
- **异常域名置顶**：归入「异常」分组，不受排序方式影响；抽屉里能看到具体状态码与探测时间
- **告警独立推送**：与到期摘要分成两条消息、各自去重 —— 混在一条里，扫一眼只会看到
  「30 个域名」，不会注意到其中一个是 `clientHold`

> 巡检依赖 `wrangler.toml` 里的 `[triggers] crons`。不配 cron，巡检永远不会执行，
> 页面上的「健康巡检」会一直是空的。

#### WHOIS 查询
1. 点击域名行的 **WHOIS** 按钮
2. 查看域名注册信息
3. 正常结果缓存 7 天；**查询失败只缓存 5 分钟**，改完配置刷新就能重试

#### 编辑域名信息
1. 点击域名行的 **编辑** 按钮
2. 修改到期时间或添加备注
3. 点击 **保存** 提交

### 管理后台

#### 访问管理后台
1. 访问 `https://your-worker.workers.dev/admin`
2. 输入 `ADMIN_PASSWORD` 登录（未配置时用默认密码，登录后请立刻到「设置」页修改）

#### 账户管理（账户页）
- **添加账户**：填 Label、Cloudflare 用户名、API Token，保存时会真实请求一次 Cloudflare API 验证
- **编辑账户**：改 Label / 用户名 / 备注；Token 留空表示不修改
- **删除账户**：连同该账户的域名缓存一起移除
- **启用/停用**：停用后不再用它查询域名，但配置保留
- **测试连通性**：单个测试或「全部测试」批量验证
- **从环境变量导入**：检测到 `CF_API_KEYS` / `USERNAMES` 时一键写入 KV

> Token 只以掩码形式回传前端（形如 `abcd12••••••••wxyz`），明文永不离开 Worker。

#### 自定义域名（不在 Cloudflare 里的域名）

有些域名（比如 DNSHE 的 `xxx.cn.mt`）没法挂到 Cloudflare，需要手动加进来：

1. 点右上角「添加域名」，**只填域名**，其余交给程序
2. 添加时立刻查一次 WHOIS（强制刷新，不吃旧缓存）：
   - **查到了** → 注册商、注册日期、到期日、名称服务器直接写入 KV，列表里正常显示
   - **查不到** → 域名照样加进去，状态显示「待补充」，并立刻弹出补填表单（带失败原因）
3. 补填后该域名标记为「人工维护」，不再被自动更新覆盖

后续刷新页面时，只要没人工改过日期，自定义域名会和 Cloudflare 域名一样自动更新；
抽屉里的「刷新 WHOIS」会强制查一次并回写。**「刷新」不再顺手续期**——续期请用
「标记已续费」，两个动作以前混在一起，点一次刷新到期日就悄悄多了一年。

#### DNSHE 凭证管理（设置页）
- 多组 Key/Secret 并存，可单独启用/停用
- 遇 401/403 自动切换到下一组可用凭证
- 每条凭证支持「验证」按钮，实时探测是否可用

#### 系统设置（设置页）
- **访问密码 / 管理员密码**：改为 PBKDF2-HMAC-SHA256（30000 轮）+ 随机盐存储
- **会话时长**：登录 Cookie 有效期（1–720 小时）
- **WHOIS 代理**：不填则 WHOIS 查询返回 N/A
- **免费域名实时查询**：开关、超时（2000–30000ms）、User-Agent
- **查询节奏**：DNSHE / WHOIS / RDAP 三个服务商的请求间隔，避免触发限流

#### 到期通知（通知页）
- **提醒规则**：提前多少天（1–365）、是否包含已过期、时区偏移
- **通知渠道**：9 种内置类型，按类型动态渲染表单字段
- **测试发送**：单渠道发一条测试消息，结果直接显示在页面上
- **立即发送**：跳过内容去重，立刻推一次完整到期摘要

支持的渠道：

| 渠道 | 必填字段 | 说明 |
|------|---------|------|
| 通用 Webhook | `url` | POST 一段 JSON，适合自建服务 |
| 飞书 | `webhook` | 可选「加签」`secret` |
| 钉钉 | `accessToken` | 可选「加签」`secret` |
| 企业微信 | `key` | 群机器人 Webhook key |
| Telegram | `token`、`chatId` | 需要先和 Bot 对话一次 |
| Server 酱 | `sendKey` | SCT 开头的 SendKey |
| PushPlus | `token` | |
| Bark | `key` | 可选自建 `server` |
| 邮件 | `apiKey`、`from`、`to` | 通过 Resend 发送 |

> 到期提醒由 Cron 触发（默认每天 UTC 02:00）。内容指纹相同的推送会被跳过，避免天天收到一样的清单。

#### 免费域名（侧栏「免费」）
- 增删改查免费/公益域名后缀白名单
- 内置项可停用，也可一键恢复默认
- 保存后 60 秒内生效，无需重新部署
- 内置 20 个后缀，含 `ip6.arpa`（HE.net 免费委派的 IPv6 反向解析区，按永久域名处理）

> **为什么 `ip6.arpa` 不做实时查询**：反向解析区没有逐区的 WHOIS/RDAP 记录。IANA RDAP 只登记到
> `ip6.arpa` 本身与 RIR 级委派（如 `d.f.ip6.arpa`），用户自己的 `/48`、`/64` 反向区一律 404；
> RIR 侧只支持按 IP 前缀查，不认反向区名。这类区不注册、不过期，所以标成「永久」比挂一个必然失败的查询更准确。

---

## 🔧 故障排查

### 常见问题

#### 1. 部署后出现 "DOMAIN_INFO is not defined" 错误

**原因**：未正确配置 KV 命名空间绑定。

**解决方案**：
- 确认已创建 KV 命名空间
- 确认 `wrangler.toml` 中配置了正确的 KV ID
- 确认绑定名称为 `DOMAIN_INFO`（大小写敏感）

#### 2. 用户名显示为 "cloudflare username1" 等默认值

**原因**：环境变量未正确配置或格式错误。

**解决方案**：
```bash
# 检查日志
wrangler tail

# 重新设置环境变量
wrangler secret put USERNAMES
# 输入: ["user1","user2","user3"]

# 重新部署
wrangler deploy
```

#### 3. 域名列表无法加载

**原因**：API 密钥无效或权限不足。

**解决方案**：
1. 访问 `/admin` 管理后台
2. 检查 API 密钥状态
3. 查看错误信息
4. 确认 API Token 权限包含 `Zone:Read`

#### 4. WHOIS 查询失败

**原因**：WHOIS 代理服务不可用或未正确配置。

**解决方案**：
```bash
# 检查代理是否可访问（注意使用 /api/lookup 路径）
curl "https://your-whois-proxy.example.com/api/lookup?query=example.com"

# 或重新配置自建代理
wrangler secret put WHOIS_PROXY
# 输入: https://your-whois-proxy.example.com
```

#### 5. 环境变量未生效

**解决方案**：
```bash
# 确认 Secret 已设置
wrangler secret list

# 重新部署
wrangler deploy

# 查看日志确认加载成功
wrangler tail
```

### 查看日志

**实时日志**：
```bash
wrangler tail
```

**格式化日志**：
```bash
wrangler tail --format pretty
```

**过滤日志**：
```bash
wrangler tail | grep "错误"
wrangler tail | grep "失败"
```

### 更多帮助

- 📄 [完整部署指南](./DEPLOYMENT.md)

---

## 📝 更新日志

本项目的完整版本历史请查看 [CHANGELOG.md](./CHANGELOG.md)。

各版本为什么这么做、放弃了哪些方案，记录在 [`docs/design/`](./docs/design/) 里 ——
例如 v2.7 的巡检为什么只跑 Cron 而不放在渲染路径上、为什么 `nodata` 不能报警。

---

## 🤝 贡献指南

欢迎贡献代码、报告问题或提出建议！

### 贡献流程

1. **Fork** 本仓库
2. **创建** 功能分支 (`git checkout -b feature/AmazingFeature`)
3. **提交** 更改 (`git commit -m '添加某个很棒的功能'`)
4. **推送** 到分支 (`git push origin feature/AmazingFeature`)
5. **创建** Pull Request

### 开发规范

- 使用有意义的提交信息
- 遵循现有代码风格
- 添加必要的注释
- 测试新功能
- 更新相关文档

### 本地自检

提交前跑一遍完整检查链：

```bash
npm run check     # 单测 + 端到端冒烟 + 打包，三步全过才算通过
```

也可以单独跑：

```bash
npm test          # 448 项单元测试（node --test）
npm run smoke     # 端到端冒烟：打包后在 Node 里真跑路由，28 项断言
npm run bundle    # esbuild 打包，产物 dist/worker.js
npm run preview   # 渲染静态预览页，产物在上级目录 design/preview/
```

`npm run smoke` 会把 Worker 打成可在 Node 里 import 的包，用假 KV 跑一遍
`/login`、`/admin-login`、`/admin`、`/api/*` 和 `scheduled`，并检查页面里
不含明文凭证。单测覆盖函数级行为，冒烟覆盖「模块能装起来、路由没接错」。

### 报告问题

在创建 Issue 时，请提供：
- 问题描述
- 复现步骤
- 预期行为
- 实际行为
- 错误日志（如有）
- 环境信息（Wrangler版本、浏览器等）

---

## 📄 许可证

本项目采用 [MIT License](./LICENSE) 许可证。

---

## 🙏 致谢

本项目基于 [ypq123456789/domainkeeper](https://github.com/ypq123456789/domainkeeper) 项目进行改进和扩展。

特别感谢:
- [ypq123456789/domainkeeper](https://github.com/ypq123456789/domainkeeper) - 原始域名可视化展示面板项目
- [Cloudflare Workers](https://workers.cloudflare.com/) - 强大的 Edge Computing 平台
- [next-whois](https://github.com/zmh-program/next-whois) - WHOIS 查询代理服务
- 所有贡献者和用户的支持

---

## 📮 联系方式

- **问题反馈**: [GitHub Issues](https://github.com/iougemini/DSMC/issues)
- **功能建议**: [GitHub Discussions](https://github.com/iougemini/DSMC/discussions)

---

<div align="center">

**如果这个项目对你有帮助，请给一个 ⭐️ Star 支持一下！**

Made with ❤️ by [iougemini](https://github.com/iougemini)

</div>
