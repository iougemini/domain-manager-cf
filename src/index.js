// 入口文件 - 路由注册与 Worker 导出

import { Router } from 'itty-router';
import { appState } from './app-state.js';
import { initConfig, initManagers, cleanupKV } from './state.js';
import {
  handleManualQuery,
  handleCfKeysApi,
  handleCustomDomainsApi,
  handleApiUpdate,
  handleAuditLogs,
  handleLogin,
  handleAdminLogin,
  handleWhoisRequest,
  handleAdmin,
  handleFrontend
} from './handlers.js';

const router = Router();

// API 路由
router.post('/api/manual-query', handleManualQuery);
router.all('/api/cf-keys', handleCfKeysApi);
router.all('/api/custom-domains', handleCustomDomainsApi);
router.post('/api/update', handleApiUpdate);
router.get('/api/audit-logs', (request, env) => handleAuditLogs(request, env));

// 认证路由
router.post('/login', (request, env) => handleLogin(request, env));
router.post('/admin-login', (request, env) => handleAdminLogin(request, env));

// WHOIS 查询路由
router.get('/whois/:domain', ({ params }) => handleWhoisRequest(params.domain));

// 页面路由
router.get('/admin', handleAdmin);
router.get('/', handleFrontend);

// 404 处理
router.all('*', () => new Response('Not Found', { status: 404 }));

function makeRequestId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return Date.now().toString(36) + Math.random().toString(36).slice(2);
}

// Module Worker 格式的导出(推荐,支持环境变量)
export default {
  async fetch(request, env, ctx) {
    // P3: 为每个请求生成追踪 ID, 贯穿结构化日志
    appState.requestId = makeRequestId();

    // P2: 每次请求重新初始化配置与管理器, 消除跨请求状态污染
    initConfig(env);
    initManagers();

    try {
      return await router.handle(request, env, ctx);
    } catch (error) {
      console.error('请求处理异常:', error);
      return new Response(`Internal Server Error: ${error.message}`, { status: 500 });
    }
  },

  // Cron触发器(用于定期清理KV)
  async scheduled(event, env, ctx) {
    appState.requestId = makeRequestId();
    console.log('🕐 执行定期KV清理任务...');
    initConfig(env);
    initManagers();
    ctx.waitUntil(cleanupKV());
  }
};

// Service Worker 格式的兼容性支持(向后兼容,但无法使用环境变量)
if (typeof addEventListener !== 'undefined') {
  addEventListener('fetch', event => {
    console.warn('⚠️ 使用Service Worker格式,无法访问环境变量!请升级到Module Worker格式。');
    appState.requestId = makeRequestId();
    initConfig({});
    initManagers();
    event.respondWith(router.handle(event.request, {}, {}));
  });
}