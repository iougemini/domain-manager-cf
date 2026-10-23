// 入口文件 - 路由注册与 Worker 导出

import { Router } from 'itty-router';
import { appState } from './app-state.js';
import { initConfig, initManagers, cleanupKV } from './state.js';
// TCP WHOIS 通道是 Workers 专有能力（cloudflare:sockets），只在这里注入，
// 避免 state.js 及其依赖在 Node 环境下无法加载
import { tcpWhois } from './services/tcp-whois.js';
import {
  handleManualQuery,
  handleCfKeysApi,
  handleAccountsApi,
  handleSettingsApi,
  handleDnsheApi,
  handleNotifyApi,
  handleCustomDomainsApi,
  handleFreeDomainsApi,
  handleApiUpdate,
  handleAuditLogs,
  handleLogin,
  handleAdminLogin,
  handleLogout,
  handleAdminLogout,
  handleWhoisRequest,
  handleAdmin,
  handleFrontend
} from './handlers.js';
import { collectDomainsForDigest } from './state.js';
import { runDigest } from './managers/notify-store.js';
import { CONFIG } from './config.js';
import { DnsChecker } from './services/dns-check.js';
import { runHealthCheck, collectHealthAlerts, readHealthBatch } from './managers/health-store.js';

const router = Router();

// 注入运行时能力：免费域名的 WHOIS/TCP 查询（pp.ua 等）
appState.whoisTransport = tcpWhois;

// API 路由
router.post('/api/manual-query', handleManualQuery);
// 旧路径保留，实现已并入账户管理
router.all('/api/cf-keys', handleCfKeysApi);
router.all('/api/accounts', handleAccountsApi);
router.all('/api/settings', handleSettingsApi);
router.all('/api/dnshe', handleDnsheApi);
router.all('/api/notify', handleNotifyApi);
router.all('/api/custom-domains', handleCustomDomainsApi);
router.all('/api/free-domains', handleFreeDomainsApi);
router.post('/api/update', handleApiUpdate);
router.get('/api/audit-logs', (request, env) => handleAuditLogs(request, env));

// 认证路由 (GET渲染登录表单, POST处理提交)
router.all('/login', (request, env) => handleLogin(request, env));
router.all('/admin-login', (request, env) => handleAdminLogin(request, env));

// 退出登录：清 cookie 后回登录页
router.get('/logout', handleLogout);
router.get('/admin-logout', handleAdminLogout);

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
    // 两者都是 async 的（要读 KV 里的设置/账户/白名单），必须 await
    await initConfig(env);
    await initManagers();

    try {
      return await router.handle(request, env, ctx);
    } catch (error) {
      console.error('请求处理异常:', error);
      return new Response(`Internal Server Error: ${error.message}`, { status: 500 });
    }
  },

  /**
   * Cron 触发器：KV 清理 + 到期提醒。
   *
   * 提醒跑在这里而不是请求里，是因为它要发外部通知；放在页面渲染路径上会
   * 让页面变慢，而且用户不打开页面就收不到提醒。
   */
  async scheduled(event, env, ctx) {
    appState.requestId = makeRequestId();
    console.log('🕐 执行定时任务...');
    await initConfig(env);
    await initManagers();

    ctx.waitUntil((async () => {
      try {
        await cleanupKV();
      } catch (error) {
        console.error('KV 清理失败:', error);
      }

      try {
        // 先收集域名（有界：缓存优先 + 最多补查 12 个），再决定要不要推送
        const domains = await collectDomainsForDigest({ maxLive: 12 });

        // ── 巡检 ──────────────────────────────────────────
        // 只在一部分域名上跑（maxDomains），但**告警按 KV 里的全部记录汇总**：
        // 本轮没轮到的域名，用的是上一轮的结论，不会因为轮转顺序而漏报
        let healthAlerts = [];
        const kv = env ? env.DOMAIN_INFO : null;
        try {
          const statusByName = new Map(domains.map(d => [d.name, d.status || null]));
          const health = await runHealthCheck({
            kv,
            domains,
            dnsChecker: new DnsChecker({ timeoutMs: CONFIG.HEALTH_DNS_TIMEOUT }),
            registryLookup: name => statusByName.get(name) || null
          });

          const records = await readHealthBatch(kv, domains.map(d => d.name));
          healthAlerts = collectHealthAlerts(records);

          console.log('巡检结果:', JSON.stringify({
            checked: health.checked,
            skipped: health.skipped,
            failed: health.failed,
            alerts: healthAlerts.length
          }));
        } catch (error) {
          console.error('巡检失败:', error);
        }

        const result = await runDigest({ kv, domains, healthAlerts });
        console.log('到期提醒结果:', JSON.stringify(result).slice(0, 500));
      } catch (error) {
        console.error('到期提醒失败:', error);
      }
    })());
  }
};

// Service Worker 格式的兼容性支持(向后兼容,但无法使用环境变量)
if (typeof addEventListener !== 'undefined') {
  addEventListener('fetch', event => {
    console.warn('⚠️ 使用Service Worker格式,无法访问环境变量!请升级到Module Worker格式。');
    appState.requestId = makeRequestId();
    event.respondWith(
      initConfig({}).then(() => initManagers()).then(() => router.handle(event.request, {}, {}))
    );
  });
}