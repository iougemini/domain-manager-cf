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

  // 配置 (由 initConfig 从环境变量加载)
  CF_API_KEYS: [],
  USERNAMES: [],
  ACCESS_PASSWORD: '',
  ADMIN_PASSWORD: '',
  TOKEN_SECRET: '',

  // 管理器与服务单例 (由 initManagers / getXxx 延迟创建)
  apiKeyManager: null,
  cacheManager: null,
  freeDomainManager: null,
  customDomainManager: null,
  rateLimiter: null,
  auditLogger: null,
  whoisService: null,
  cloudflareFetcher: null,
};