// 全局状态对象 - 集中管理共享可变状态
//
// 说明:
// Cloudflare Workers 的 isolate 模型下, 模块级状态在同 isolate 内跨请求共享。
// 为避免请求间状态污染, 每次请求进入时由 state.js 的 initConfig()/initManagers()
// 重置配置与重新分配管理器实例。
//
// 该模块零依赖, 是所有业务模块的共享状态底座, 避免循环依赖。

export const appState = {
  // 运行时环境 (request.env)
  env: null,

  // 请求追踪 ID (P3: 结构化日志贯穿)
  requestId: '',

  // 配置 (由 initConfig 从环境变量 + KV 加载)
  CF_API_KEYS: [],
  USERNAMES: [],
  ACCESS_PASSWORD: '',
  ADMIN_PASSWORD: '',
  // KV 里存的是密码哈希；有值时优先于上面的明文环境变量
  ACCESS_PASSWORD_HASH: null,
  ADMIN_PASSWORD_HASH: null,
  TOKEN_SECRET: '',
  SESSION_HOURS: 24,

  // 从 KV 载入的账户与 DNSHE 凭证（initConfig 填充）
  accounts: [],
  accountSource: 'none',
  dnsheCredentials: [],
  dnsheAll: [],
  // 环境变量里是否配了 DNSHE_API_KEY / DNSHE_API_SECRET（只做展示与兜底提示）
  dnsheEnv: { hasKey: false, hasSecret: false },
  settings: null,
  notifyConfig: null,
  notifyState: null,

  // 管理器与服务单例 (由 initManagers / getXxx 延迟创建)
  apiKeyManager: null,
  cacheManager: null,
  freeDomainManager: null,
  customDomainManager: null,
  rateLimiter: null,
  auditLogger: null,
  whoisService: null,
  cloudflareFetcher: null,

  // TCP WHOIS 通道。由入口 index.js 注入（Workers 用 cloudflare:sockets），
  // 不在这里直接 import，是为了让 state.js 及其依赖在 Node 环境下也能被测试。
  whoisTransport: null,
};