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
  - [方法一：使用 Cloudflare 控制面板部署](#方法一使用-cloudflare-控制面板部署)
  - [方法二：使用 Wrangler CLI 部署](#方法二使用-wrangler-cli-部署)
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

- Cloudflare 账户（免费版即可）
- Cloudflare API Token（需要 `Zone:Read` 权限）
- （可选）Wrangler CLI 工具

### 最简部署

1. **Fork 本仓库**
2. **在 Cloudflare 控制面板创建 Worker**
3. **复制 `workers.js` 内容到 Worker**
4. **配置环境变量**（见[配置说明](#配置说明)）
5. **访问 Worker URL 开始使用**

详细步骤请查看[部署指南](#部署指南)。

---

## 📦 部署指南

### 方法一：使用 Cloudflare 控制面板部署

#### 步骤 1: 创建 KV 命名空间

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 导航到 **Workers & Pages** → **KV**
3. 点击 **Create a namespace**
4. 输入命名空间名称：`DOMAIN_INFO`
5. 点击 **Add** 创建
6. **记录生成的 Namespace ID**（后续步骤需要）

#### 步骤 2: 创建 Worker

1. 在 Cloudflare Dashboard 中，导航到 **Workers & Pages**
2. 点击 **Create application** → **Create Worker**
3. 输入 Worker 名称，例如：`domain-manager`
4. 点击 **Deploy** 创建 Worker
5. 创建后，点击 **Edit code** 进入代码编辑器

#### 步骤 3: 部署代码

1. 复制本仓库的 `workers.js` 文件内容
2. 粘贴到 Cloudflare Worker 编辑器中
3. 点击右上角 **Save and Deploy** 保存并部署

#### 步骤 4: 绑定 KV 命名空间

1. 返回 Worker 详情页面
2. 点击 **Settings** → **Variables**
3. 在 **KV Namespace Bindings** 区域点击 **Add binding**
4. 填写配置：
   - **Variable name**: `DOMAIN_INFO`
   - **KV namespace**: 选择刚才创建的 `DOMAIN_INFO` 命名空间
5. 点击 **Save** 保存

#### 步骤 5: 配置环境变量

在 **Settings** → **Variables** 页面：

##### 环境变量 (Variables)
添加以下变量（点击 **Add variable**）：

| 变量名 | 值示例 | 说明 | 必需 |
|--------|--------|------|------|
| `CF_API_KEYS` | `["key1","key2"]` | Cloudflare API 密钥数组（JSON字符串） | ✅ 是 |
| `USERNAMES` | `["user1","user2"]` | 对应的用户名数组（JSON字符串） | ✅ 是 |
| `ACCESS_PASSWORD` | `your_password` | 前端访问密码 | ✅ 是 |
| `ADMIN_PASSWORD` | `admin_password` | 管理后台密码 | ✅ 是 |
| `WHOIS_PROXY` | `https://your-whois.com` | WHOIS代理地址（可选） | ❌ 否 |

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

#### 步骤 6: 配置 Cron Trigger（可选）

1. 在 Worker 详情页面，点击 **Triggers** → **Cron Triggers**
2. 点击 **Add Cron Trigger**
3. 输入 Cron 表达式：`0 2 * * *`（每天凌晨2点执行清理任务）
4. 点击 **Add Trigger** 保存

#### 步骤 7: 完成部署

1. 返回 Worker 详情页面
2. 找到 **Preview** 区域的 Worker URL
3. 访问该 URL，输入 `ACCESS_PASSWORD` 登录
4. 开始使用！

---

### 方法二：使用 Wrangler CLI 部署

#### 步骤 1: 安装 Wrangler

```bash
# 使用 npm 安装
npm install -g wrangler

# 或使用 yarn
yarn global add wrangler

# 验证安装
wrangler --version
```

#### 步骤 2: 登录 Cloudflare

```bash
wrangler login
```

浏览器会自动打开授权页面，点击允许授权。

#### 步骤 3: 克隆项目

```bash
git clone https://github.com/your-username/domain-manager-cf.git
cd domain-manager-cf
```

#### 步骤 4: 创建 KV 命名空间

```bash
wrangler kv:namespace create "DOMAIN_INFO"
```

命令执行后会返回：
```
🌀 Creating namespace with title "domain-manager-DOMAIN_INFO"
✨ Success!
Add the following to your configuration file in your kv_namespaces array:
{ binding = "DOMAIN_INFO", id = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }
```

**复制返回的 ID**。

#### 步骤 5: 配置 wrangler.toml

编辑项目根目录的 `wrangler.toml` 文件：

```toml
name = "domain-manager"
main = "workers.js"
compatibility_date = "2024-01-01"

# KV 命名空间配置
[[kv_namespaces]]
binding = "DOMAIN_INFO"
id = "粘贴您的KV命名空间ID"  # ← 替换为步骤4返回的ID

# Cron 定时任务配置（可选）
[triggers]
crons = ["0 2 * * *"]  # 每天凌晨2点执行清理任务

# 环境变量配置（不推荐敏感信息）
[vars]
# WHOIS_PROXY = "https://your-whois-proxy.com"  # 可选
```

#### 步骤 6: 配置环境变量

**推荐方式：使用 wrangler secret（加密存储）**

```bash
# 配置管理员密码
wrangler secret put ADMIN_PASSWORD
# 提示输入时，输入您的管理员密码

# 配置访问密码
wrangler secret put ACCESS_PASSWORD
# 输入前端访问密码

# 配置 Cloudflare API 密钥
wrangler secret put CF_API_KEYS
# 输入: ["key1","key2","key3"]
# 注意：必须是有效的 JSON 字符串，不能有空格

# 配置用户名
wrangler secret put USERNAMES
# 输入: ["user1","user2","user3"]

# (可选) 配置 WHOIS 代理
wrangler secret put WHOIS_PROXY
# 输入: https://your-whois-proxy.com
```

**注意事项**：
- JSON 字符串格式必须严格：`["item1","item2"]`
- ✅ 正确：`["key1","key2","key3"]`
- ❌ 错误：`["key1", "key2", "key3"]`（有空格）
- ❌ 错误：`[key1,key2,key3]`（缺少引号）

**备选方式：在 wrangler.toml 中配置（不推荐）**

```toml
[vars]
CF_API_KEYS = '["your_key1","your_key2"]'
USERNAMES = '["user1","user2"]'
ACCESS_PASSWORD = "your_access_password"
ADMIN_PASSWORD = "your_admin_password"
WHOIS_PROXY = "https://your-whois-proxy.com"
```

#### 步骤 7: 本地测试（可选）

```bash
wrangler dev
```

访问 `http://localhost:8787` 测试功能。

#### 步骤 8: 部署到生产环境

```bash
wrangler deploy
```

部署成功后会显示 Worker URL：
```
Published domain-manager (0.01 sec)
  https://domain-manager.your-subdomain.workers.dev
```

#### 步骤 9: 验证部署

```bash
# 查看实时日志
wrangler tail

# 查看部署历史
wrangler deployments list
```

访问 Worker URL，应该看到：
- ✅ 登录页面正常显示
- ✅ 输入 `ACCESS_PASSWORD` 可以登录
- ✅ 域名列表能够正常加载
- ✅ WHOIS 查询功能正常

---

## ⚙️ 配置说明

### 环境变量列表

| 变量名 | 类型 | 说明 | 默认值 | 必需 |
|--------|------|------|--------|------|
| `CF_API_KEYS` | JSON数组 | Cloudflare API 密钥列表 | `[]` | ✅ 是 |
| `USERNAMES` | JSON数组 | 对应的用户名列表（与API密钥一一对应） | `[]` | ✅ 是 |
| `ACCESS_PASSWORD` | 字符串 | 前端访问密码 | `XXXXXX` | ✅ 是 |
| `ADMIN_PASSWORD` | 字符串 | 管理后台密码 | `XXXXXX` | ✅ 是 |
| `WHOIS_PROXY` | 字符串 | WHOIS 代理服务地址 | `https://who.nie.ge` | ❌ 否 |

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

默认使用公共 WHOIS 代理服务 `https://who.nie.ge`。

如需自建代理服务，请参考：
- **仓库地址**: https://github.com/zmh-program/next-whois
- **部署平台**: Vercel / Cloudflare Pages / 自托管

部署完成后，将代理地址设置到 `WHOIS_PROXY` 环境变量。

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

**原因**：WHOIS 代理服务不可用。

**解决方案**：
```bash
# 检查默认代理是否可访问
curl https://who.nie.ge/api/whois?domain=example.com

# 或使用自建代理
wrangler secret put WHOIS_PROXY
# 输入: https://your-whois-proxy.com
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

- **问题反馈**: [GitHub Issues](https://github.com/your-username/domain-manager-cf/issues)
- **功能建议**: [GitHub Discussions](https://github.com/your-username/domain-manager-cf/discussions)

---

<div align="center">

**如果这个项目对你有帮助，请给一个 ⭐️ Star 支持一下！**

Made with ❤️ by [Your Name]

</div>
