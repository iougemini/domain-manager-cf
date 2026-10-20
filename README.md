# Domain Manager

<div align="center">

<svg width="150" height="150" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="shieldGradient" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#4A90E2;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#357ABD;stop-opacity:1" />
    </linearGradient>
  </defs>
  <path d="M50 10 L80 20 L80 45 Q80 70 50 90 Q20 70 20 45 L20 20 Z"
        fill="url(#shieldGradient)"
        stroke="#2C5F8D"
        stroke-width="2"/>
  <path d="M50 25 L65 32 L65 48 Q65 62 50 75 Q35 62 35 48 L35 32 Z"
        fill="#ffffff"
        opacity="0.3"/>
  <text x="50" y="58"
        font-size="28"
        font-weight="bold"
        text-anchor="middle"
        fill="#ffffff">✓</text>
</svg>

--- 
![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange.svg)

基于 Cloudflare Workers 的域名管理系统，支持多账户域名统一管理、WHOIS查询、到期提醒等功能。

[功能特性](#功能特性) • [快速开始](#快速开始) • [部署指南](#部署指南) • [配置说明](#配置说明) • [使用文档](#使用文档)

</div>

---

## 📋 目录

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

## ✨ 功能特性

### 核心功能
- 🔐 **多账户管理** - 支持多个 Cloudflare 账户的域名统一管理
- 📊 **域名总览** - 实时查看所有域名状态、注册商、到期时间
- 🔍 **WHOIS 查询** - 集成 WHOIS 代理服务，快速查询域名信息
- ⏰ **到期提醒** - 自动标记即将到期的域名（7天、30天提醒）
- 🏷️ **自定义标签** - 为域名添加自定义标签，便于分类管理

### 高级特性
- 🔄 **智能缓存** - KV 存储缓存 WHOIS 数据，降低查询延迟
- 🔒 **安全认证** - 基于 HMAC-SHA256 的 Token 认证机制
- 📱 **响应式设计** - 支持桌面端和移动端访问
- 🌙 **深色模式** - 提供舒适的深色主题
- ⚡ **无服务器架构** - 基于 Cloudflare Workers，零服务器维护成本
- 🔧 **灵活配置** - 支持环境变量配置，便于多环境部署

### 管理功能
- 🛠️ **API 密钥管理** - 可视化管理 Cloudflare API 密钥
- 📈 **使用统计** - 查看 API 密钥使用情况和错误统计
- 🗑️ **自动清理** - 定时清理过期缓存数据（Cron Job）
- 🔐 **双重密码** - 前端访问密码 + 管理后台密码，安全可靠

---

## 🏗️ 技术架构

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

---

## 🚀 快速开始

### 前置要求

- Node.js 18 或更高版本
- Cloudflare 账户（免费版即可）
- Cloudflare API Token（需要 `Zone:Read` 权限）
- Wrangler CLI 工具（使用 `npx wrangler` 或全局安装）

### 最简部署

1. **克隆本仓库**
   ```bash
   git clone https://github.com/iougemini/domain-manager-cf.git
   cd domain-manager-cf
   ```
2. **安装依赖**
   ```bash
   npm install
   ```
3. **创建 KV 命名空间**（记录返回的 ID）
   ```bash
   npx wrangler kv:namespace create "DOMAIN_INFO"
   ```
4. **配置 `wrangler.toml`**：将 KV ID 填入 `[[kv_namespaces]]`，并按需配置环境变量（见[配置说明](#配置说明)）
5. **部署**
   ```bash
   npx wrangler deploy
   ```

详细步骤请查看[部署指南](#部署指南)。

---

## 📦 部署指南

本项目为多模块 ESM 项目，支持两种部署方式，推荐使用 Wrangler CLI（自动打包与依赖处理）。

### 快速部署（Wrangler CLI）

```bash
git clone https://github.com/iougemini/domain-manager-cf.git
cd domain-manager-cf
npm install
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

### 环境变量列表

| 变量名 | 类型 | 说明 | 默认值 | 必需 |
|--------|------|------|--------|------|
| `CF_API_KEYS` | JSON数组 | Cloudflare API 密钥列表 | `[]` | ✅ 是 |
| `USERNAMES` | JSON数组 | 对应的用户名列表（与API密钥一一对应） | `[]` | ✅ 是 |
| `ACCESS_PASSWORD` | 字符串 | 前端访问密码 | `XXXXXX` | ✅ 是 |
| `ADMIN_PASSWORD` | 字符串 | 管理后台密码 | `XXXXXX` | ✅ 是 |
| `WHOIS_PROXY` | 字符串 | WHOIS 代理服务地址 | （空，未配置时返回 N/A） | ❌ 否 |

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
- `User-Agent: DomainKeeper/1.2.0`
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

#### 查看域名列表
- **域名总览**：显示所有账户的域名
- **筛选功能**：按注册商、到期时间筛选
- **搜索功能**：快速搜索域名
- **状态标识**：
  - 🔴 红色：7天内到期
  - 🟡 黄色：30天内到期
  - 🟢 绿色：正常

#### WHOIS 查询
1. 点击域名行的 **WHOIS** 按钮
2. 查看域名注册信息
3. 数据会自动缓存 7 天

#### 编辑域名信息
1. 点击域名行的 **编辑** 按钮
2. 修改到期时间或添加备注
3. 点击 **保存** 提交

### 管理后台

#### 访问管理后台
1. 访问 `https://your-worker.workers.dev/admin`
2. 输入 `ADMIN_PASSWORD` 登录

#### API 密钥管理
- **查看状态**：查看所有 API 密钥的使用情况
- **启用/禁用**：手动启用或禁用 API 密钥
- **错误统计**：查看 API 调用错误次数
- **添加密钥**：动态添加新的 API 密钥
- **删除密钥**：移除不再使用的 API 密钥

#### 系统设置
- **缓存管理**：查看和清理缓存数据
- **日志查看**：查看系统运行日志
- **配置导出**：导出当前配置（不含敏感信息）

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

### v1.0.0 (2024-10-16)

#### 新功能
- ✨ 完整的域名管理系统
- ✨ 多账户支持
- ✨ WHOIS 查询集成
- ✨ 到期提醒功能
- ✨ 深色主题

#### 改进
- 🔧 WHOIS_PROXY 支持环境变量配置
- 🔧 优化初始化流程，采用延迟加载模式
- 🔧 智能检测 KV 旧数据，防止覆盖环境变量
- 🔧 改进输入验证，修复正则表达式错误

#### 修复
- 🐛 修复 DOMAIN_INFO 未定义错误
- 🐛 修复用户名显示 fallback 值问题
- 🐛 修复服务初始化时机问题
- 🐛 修复域名编辑保存错误

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

- **问题反馈**: [GitHub Issues](https://github.com/iougemini/domain-manager-cf/issues)
- **功能建议**: [GitHub Discussions](https://github.com/iougemini/domain-manager-cf/discussions)

---

<div align="center">

**如果这个项目对你有帮助，请给一个 ⭐️ Star 支持一下！**

Made with ❤️ by [iougemini](https://github.com/iougemini)

</div>
