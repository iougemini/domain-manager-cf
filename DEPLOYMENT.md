# Domain Manager - 部署指南

本项目为多模块 ESM 项目（入口 `src/index.js`，依赖 `itty-router`），推荐使用 Wrangler CLI 部署。

## 前置要求

- Node.js 18 或更高版本
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

### 步骤 5: 配置 wrangler.toml

编辑项目根目录的 `wrangler.toml` 文件：

```toml
name = "domain-manager"
main = "src/index.js"
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
# WHOIS_PROXY = "https://your-whois-proxy.example.com"  # 可选
```

### 步骤 6: 配置环境变量

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
# 输入: https://your-whois-proxy.example.com
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

在 **Settings** → **Variables** 页面：

##### 环境变量 (Variables)

添加以下变量（点击 **Add variable**）：

| 变量名 | 值示例 | 说明 | 必需 |
|--------|--------|------|------|
| `CF_API_KEYS` | `["key1","key2"]` | Cloudflare API 密钥数组（JSON字符串） | ✅ 是 |
| `USERNAMES` | `["user1","user2"]` | 对应的用户名数组（JSON字符串） | ✅ 是 |
| `ACCESS_PASSWORD` | `your_password` | 前端访问密码 | ✅ 是 |
| `ADMIN_PASSWORD` | `admin_password` | 管理后台密码 | ✅ 是 |
| `WHOIS_PROXY` | `https://your-whois-proxy.example.com` | WHOIS代理地址（可选） | ❌ 否 |

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

### 步骤 6: 配置 Cron Trigger（可选）

1. 在 Worker 详情页面，点击 **Triggers** → **Cron Triggers**
2. 点击 **Add Cron Trigger**
3. 输入 Cron 表达式：`0 2 * * *`（每天凌晨2点执行清理任务）
4. 点击 **Add Trigger** 保存

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
