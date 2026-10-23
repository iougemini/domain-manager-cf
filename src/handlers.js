import { appState } from './app-state.js';
import { CONFIG, getLocale, t } from './config.js';
import { getCookie, verifyAuthToken, createAuthToken, createCookieHeader, createClearCookieHeader } from './auth.js';
import { validateDomain, validateAction } from './validators.js';
import { ApiError, ERROR_CODES, ValidationError, createErrorResponse, createSuccessResponse } from './errors.js';
import { AUDIT_EVENTS, getAuditLogger, logger } from './logger.js';
import { getRateLimiter, RATE_LIMIT_CONFIG } from './rate-limiter.js';
import {
  getWhoisService,
  fetchCloudflareDomainsInfo,
  fetchDomainInfo,
  collectDomainsForDigest
} from './state.js';
import { testCloudflareApi } from './services/cloudflare.js';
import { FreeDomainManager, LOOKUP_ENDPOINTS, DEFAULT_SUFFIXES } from './managers/free-domain.js';
import { FreeDomainLookup } from './services/free-domain-lookup.js';
import { knownValue, mergeCustomDomainRecord, hasUsableExpiry } from './services/domain-merge.js';
import {
  loadFreeDomainEntries,
  updateFreeDomainEntries,
  upsertEntry,
  dropEntry
} from './managers/free-domain-store.js';
import { makeId } from './managers/kv-config.js';
import {
  publicSettings,
  normalizeSettingsPatch,
  saveSettings,
  loadSettingsWithMeta,
  applySettings,
  makePasswordRecord,
  verifyAccessPassword,
  verifyAdminPassword
} from './managers/settings-store.js';
import {
  loadDnsheCredentials,
  upsertDnsheCredential,
  removeDnsheCredential,
  toggleDnsheCredential,
  publicCredential
} from './managers/dnshe-store.js';
import {
  loadNotifyConfig,
  publicNotifyConfig,
  saveNotifyRules,
  upsertChannel,
  removeChannel,
  toggleChannel,
  testChannel,
  runDigest,
  loadNotifyState
} from './managers/notify-store.js';
import { channelMetas } from './services/notify.js';
import { generateHTML, generateLoginHTML } from './ui/index.js';
export async function handleManualQuery(request) {
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "只支持POST请求" }), {
      status: 405,
      headers: { "Content-Type": "application/json" }
    });
  }

  // 速率限制检查
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  const limiter = getRateLimiter(appState.env);
  if (limiter) {
    const { allowed, remaining, retryAfter } = await limiter.checkApiLimit(ip);
    if (!allowed) {
      logger.warn('API速率限制触发', { ip, retryAfter });
      return new Response(JSON.stringify({
        success: false,
        error: { code: 'RATE_LIMITED', message: '请求过于频繁,请稍后重试' }
      }), {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'X-RateLimit-Remaining': '0',
          'Retry-After': String(retryAfter || 60)
        }
      });
    }
  }

  try {

    const data = await request.json();

    // 验证域名输入
    let domain;
    try {
      domain = validateDomain(data.domain);
    } catch (error) {
      if (error instanceof ValidationError) {
        console.warn(`❌ 域名验证失败: ${error.message}`);
        return new Response(JSON.stringify({
          error: error.userMessage,
          field: error.field
        }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
      throw error;
    }

    console.log('✅ 手动查询域名: ' + domain);
    const service = getWhoisService();
    const whoisInfo = await service.query(domain);

    return new Response(JSON.stringify(whoisInfo), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('手动查询异常:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Cloudflare API密钥管理API（旧路径，保留兼容；实现已并入账户管理）
export async function handleCfKeysApi(request, env) {
  return handleAccountsApi(request, env);
}

/* ---------------- 账户管理（KV config:accounts） ---------------- */

/**
 * 账户 = 一个 Cloudflare API Token + 一个显示名。
 * 这一组接口取代了原来「环境变量 CF_API_KEYS / USERNAMES 两个数组」的做法，
 * 页面上可以直接增删改，不需要重新部署。
 */
export async function handleAccountsApi(request) {
  const token = getCookie(request, 'admin_token');
  const payload = await verifyAuthToken(token, 'admin');

  if (!payload) {
    return new Response(JSON.stringify({ error: '需要管理员权限' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const kv = appState.env ? appState.env.DOMAIN_INFO : null;

  try {
    if (request.method === 'GET') {
      return new Response(JSON.stringify({
        accounts: appState.apiKeyManager.getAllAccounts(),
        source: appState.accountSource,
        total: appState.apiKeyManager.keys.length,
        // 前端据此决定要不要显示"导入环境变量"按钮
        envAccounts: countEnvAccounts(appState.env)
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    if (!kv) {
      return new Response(JSON.stringify({ error: 'KV 未绑定（DOMAIN_INFO），无法保存账户' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const data = await request.json();
    let action;
    try {
      action = validateAction(data.action, [
        'add', 'update', 'remove', 'toggle', 'test', 'test-all', 'import'
      ]);
    } catch (error) {
      return jsonError(error, 400);
    }

    switch (action) {
      case 'add': {
        const created = await appState.apiKeyManager.addAccount({
          label: data.label,
          username: data.username,
          token: data.token,
          note: data.note
        });
        return jsonOk(`已添加账户 ${created.username}`, {
          accounts: appState.apiKeyManager.getAllAccounts()
        });
      }

      case 'update': {
        const updated = await appState.apiKeyManager.updateAccount(data.id, {
          label: data.label,
          username: data.username,
          token: data.token,
          note: data.note,
          enabled: data.enabled
        });
        return jsonOk(`已更新账户 ${updated.username}`, {
          accounts: appState.apiKeyManager.getAllAccounts()
        });
      }

      case 'remove': {
        await appState.apiKeyManager.removeAccount(data.id);
        return jsonOk('账户已删除', { accounts: appState.apiKeyManager.getAllAccounts() });
      }

      case 'toggle': {
        const active = await appState.apiKeyManager.toggleAccount(data.id);
        return jsonOk('账户已' + (active ? '启用' : '停用'), {
          active,
          accounts: appState.apiKeyManager.getAllAccounts()
        });
      }

      case 'test': {
        const result = await appState.apiKeyManager.testAccount(data.id);
        return jsonOk(result.ok ? '连接正常' : '连接失败', { result });
      }

      case 'test-all': {
        const results = await appState.apiKeyManager.testAll();
        const ok = results.filter(r => r.ok).length;
        return jsonOk(`测试完成：${ok}/${results.length} 个正常`, { results });
      }

      case 'import': {
        const result = await appState.apiKeyManager.importFromEnv();
        appState.accountSource = 'kv';
        return jsonOk(`已从环境变量导入 ${result.added} 个账户`, {
          ...result,
          accounts: appState.apiKeyManager.getAllAccounts()
        });
      }

      default:
        return jsonError(new Error('无效的操作'), 400);
    }
  } catch (error) {
    console.error('账户管理错误:', error);
    return jsonError(error, error.status || 400);
  }
}

function countEnvAccounts(env) {
  if (!env || !env.CF_API_KEYS) return 0;
  try {
    const list = JSON.parse(env.CF_API_KEYS);
    return Array.isArray(list) ? list.length : 0;
  } catch (e) {
    return 0;
  }
}

function jsonOk(message, extra) {
  return new Response(JSON.stringify({ success: true, message, ...(extra || {}) }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

/** 会话有效期（秒），由「设置」页控制，默认 24 小时 */
function sessionSeconds() {
  const hours = Number(appState.SESSION_HOURS);
  const safe = Number.isFinite(hours) && hours > 0 ? hours : 24;
  return Math.round(safe * 3600);
}

function jsonError(error, status = 400) {
  const message = (error && (error.userMessage || error.message)) || '操作失败';
  return new Response(JSON.stringify({ error: message, field: error && error.field }), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

/* ---------------- 运行设置（KV config:settings） ---------------- */

export async function handleSettingsApi(request) {
  const token = getCookie(request, 'admin_token');
  const payload = await verifyAuthToken(token, 'admin');

  if (!payload) {
    return new Response(JSON.stringify({ error: '需要管理员权限' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const kv = appState.env ? appState.env.DOMAIN_INFO : null;

  try {
    if (request.method === 'GET') {
      return new Response(JSON.stringify({
        settings: publicSettings(appState.settings, appState.env)
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    if (!kv) {
      return new Response(JSON.stringify({ error: 'KV 未绑定（DOMAIN_INFO），无法保存设置' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const data = await request.json();
    const action = String(data.action || 'save');

    if (action === 'clear-cache') {
      const count = await appState.cacheManager.clearAll();
      return jsonOk(`已清除 ${count} 条缓存`);
    }

    if (action !== 'save') return jsonError(new Error('无效的操作'), 400);

    let patch;
    try {
      patch = normalizeSettingsPatch(data.settings || data);
    } catch (error) {
      return jsonError(error, 400);
    }

    // 密码单独处理：留空表示不修改，非空则哈希后入库
    const raw = data.settings || data;
    const messages = [];

    if (raw.accessPassword) {
      try {
        patch.accessPassword = await makePasswordRecord(raw.accessPassword);
        messages.push('访问密码');
      } catch (error) {
        return jsonError(new Error('访问密码：' + error.message), 400);
      }
    }

    if (raw.adminPassword) {
      try {
        patch.adminPassword = await makePasswordRecord(raw.adminPassword);
        messages.push('管理员密码');
      } catch (error) {
        return jsonError(new Error('管理员密码：' + error.message), 400);
      }
    }

    // 密码改了要保证 token 签名密钥存在，否则已签发的 cookie 会全部失效且无法重建
    if ((patch.accessPassword || patch.adminPassword) && !appState.settings.tokenSecret) {
      patch.tokenSecret = makeId('ts');
    }

    const saved = await saveSettings(kv, patch);
    appState.settings = saved;

    // 立刻把新设置灌进当前 isolate，避免"保存成功但页面还是旧值"
    const { explicit } = await loadSettingsWithMeta(kv);
    applySettings(saved, appState.env, explicit);
    appState.whoisService = null;

    if (messages.length) {
      messages.push('已更新，相关会话会在下次登录时生效');
    }

    return jsonOk(
      messages.length ? messages.join('、') + ' 已更新' : '设置已保存',
      { settings: publicSettings(saved, appState.env) }
    );
  } catch (error) {
    console.error('设置保存错误:', error);
    return jsonError(error, error.status || 500);
  }
}

/* ---------------- DNSHE 凭证（KV config:dnshe） ---------------- */

export async function handleDnsheApi(request) {
  const token = getCookie(request, 'admin_token');
  const payload = await verifyAuthToken(token, 'admin');

  if (!payload) {
    return new Response(JSON.stringify({ error: '需要管理员权限' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const kv = appState.env ? appState.env.DOMAIN_INFO : null;

  try {
    if (request.method === 'GET') {
      const list = await loadDnsheCredentials(kv);
      return new Response(JSON.stringify({
        credentials: list.map(publicCredential),
        enabled: list.filter(item => item.enabled !== false).length,
        total: list.length
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    if (!kv) {
      return new Response(JSON.stringify({ error: 'KV 未绑定（DOMAIN_INFO），无法保存凭证' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const data = await request.json();
    let action;
    try {
      action = validateAction(data.action, ['add', 'update', 'remove', 'toggle', 'test']);
    } catch (error) {
      return jsonError(error, 400);
    }

    const afterChange = async (message, extra) => {
      const list = await loadDnsheCredentials(kv);
      // 凭证变了，查询器要重建，否则还在用旧 Key
      appState.dnsheCredentials = list.filter(item => item.enabled !== false);
      appState.whoisService = null;
      // 旧缓存里多半是上一次 401 的兜底值，一并作废
      const purged = await invalidateDnsheCache();
      return jsonOk(message, {
        ...extra,
        purged,
        credentials: list.map(publicCredential),
        enabled: appState.dnsheCredentials.length,
        total: list.length
      });
    };

    switch (action) {
      case 'add': {
        const created = await upsertDnsheCredential(kv, data);
        return afterChange(`已添加凭证 ${created.label}`);
      }
      case 'update': {
        const updated = await upsertDnsheCredential(kv, data, data.id);
        return afterChange(`已更新凭证 ${updated.label}`);
      }
      case 'remove': {
        await removeDnsheCredential(kv, data.id);
        return afterChange('凭证已删除');
      }
      case 'toggle': {
        const enabled = await toggleDnsheCredential(kv, data.id);
        return afterChange('凭证已' + (enabled ? '启用' : '停用'), { enabledState: enabled });
      }
      case 'test': {
        const result = await probeDnsheCredential(kv, data.id);
        return jsonOk(result.ok ? '凭证可用' : '凭证不可用', { result });
      }
      default:
        return jsonError(new Error('无效的操作'), 400);
    }
  } catch (error) {
    console.error('DNSHE 凭证错误:', error);
    return jsonError(error, error.status || 400);
  }
}

/**
 * 探测 DNSHE 凭证是否可用。
 *
 * 用 whois 端点查一个大概率不存在的域名：返回 registered:false 说明认证通过，
 * 401/403 才是凭证问题。这样既能验证凭证，又不需要真的拥有某个域名。
 */
/**
 * 清掉所有 DNSHE 域名的 WHOIS 缓存。
 *
 * 凭证一改就得清：之前的缓存里躺着的正是"401 认证失败 → 回退注册表"那条结果，
 * 不清的话用户改完 Key 刷新页面还是同一句报错，会以为改动没生效。
 * 返回清掉的条数，方便在响应里如实告诉用户。
 */
async function invalidateDnsheCache() {
  const cache = appState.cacheManager;
  if (!cache || typeof cache.clearWhere !== 'function') return 0;

  const manager = appState.freeDomainManager;
  const entries = manager ? manager.listAll() : DEFAULT_SUFFIXES;
  const suffixes = entries
    .filter(entry => entry && entry.lookup && entry.lookup.type === 'dnshe')
    .map(entry => entry.suffix);

  if (!suffixes.length) return 0;

  return cache.clearWhere(domain => suffixes.some(s => domain === s || domain.endsWith('.' + s)));
}

async function probeDnsheCredential(kv, id) {
  const list = await loadDnsheCredentials(kv);
  const credential = list.find(item => item.id === id);
  if (!credential) throw new Error('凭证不存在，可能已被删除');

  const probe = new FreeDomainLookup({
    dnsheCredentials: [{ key: credential.key, secret: credential.secret }],
    timeout: 8000
  });

  const result = await probe.lookup('dsmc-probe.us.ci', {
    type: 'dnshe',
    endpoint: LOOKUP_ENDPOINTS.dnshe
  });

  if (result && result.authFailed) {
    return { ok: false, error: result.error };
  }
  if (result && result.error && !result.registered) {
    // 网络类错误不算凭证无效，但也要如实告诉用户
    return { ok: false, error: result.error };
  }
  return { ok: true, error: null };
}

/* ---------------- 通知（KV config:notify） ---------------- */

export async function handleNotifyApi(request) {
  const token = getCookie(request, 'admin_token');
  const payload = await verifyAuthToken(token, 'admin');

  if (!payload) {
    return new Response(JSON.stringify({ error: '需要管理员权限' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const kv = appState.env ? appState.env.DOMAIN_INFO : null;

  try {
    if (request.method === 'GET') {
      const config = await loadNotifyConfig(kv);
      const state = await loadNotifyState(kv);
      return new Response(JSON.stringify({
        config: publicNotifyConfig(config),
        state,
        // 渠道类型与字段定义下发到前端，新增渠道不用改 UI 代码
        types: channelMetas()
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    if (!kv) {
      return new Response(JSON.stringify({ error: 'KV 未绑定（DOMAIN_INFO），无法保存通知配置' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const data = await request.json();
    let action;
    try {
      action = validateAction(data.action, [
        'save-rules', 'channel-add', 'channel-update', 'channel-remove',
        'channel-toggle', 'test', 'send-now'
      ]);
    } catch (error) {
      return jsonError(error, 400);
    }

    const payloadOfConfig = async (message) => {
      const config = await loadNotifyConfig(kv);
      appState.notifyConfig = config;
      return jsonOk(message, {
        config: publicNotifyConfig(config),
        state: await loadNotifyState(kv)
      });
    };

    switch (action) {
      case 'save-rules': {
        await saveNotifyRules(kv, {
          enabled: data.enabled,
          daysBefore: data.daysBefore,
          includeExpired: data.includeExpired,
          timezoneOffset: data.timezoneOffset
        });
        return payloadOfConfig('通知设置已保存');
      }

      case 'channel-add': {
        const created = await upsertChannel(kv, data, null);
        return payloadOfConfig(`已添加渠道 ${created.label}`);
      }

      case 'channel-update': {
        const updated = await upsertChannel(kv, data, data.id);
        return payloadOfConfig(`已更新渠道 ${updated.label}`);
      }

      case 'channel-remove': {
        await removeChannel(kv, data.id);
        return payloadOfConfig('渠道已删除');
      }

      case 'channel-toggle': {
        const enabled = await toggleChannel(kv, data.id);
        return payloadOfConfig('渠道已' + (enabled ? '启用' : '停用'));
      }

      case 'test': {
        const result = await testChannel(kv, data.id);
        appState.notifyConfig = await loadNotifyConfig(kv);
        return jsonOk(result.ok ? '测试消息已发送' : '发送失败', {
          result,
          state: await loadNotifyState(kv)
        });
      }

      case 'send-now': {
        const domains = await collectDomainsForDigest({ maxLive: 12 });
        const result = await runDigest({ kv, domains, force: true });
        return jsonOk(
          result.skipped ? ('未发送：' + result.reason) : `已发送 ${result.sent} 个渠道，${result.count} 个域名`,
          { result, state: await loadNotifyState(kv) }
        );
      }

      default:
        return jsonError(new Error('无效的操作'), 400);
    }
  } catch (error) {
    console.error('通知配置错误:', error);
    return jsonError(error, error.status || 400);
  }
}


// 自定义域名管理API

const JSON_HEADERS = { 'Content-Type': 'application/json' };

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

/**
 * 新增自定义域名时立刻查一次 WHOIS。
 *
 * forceRefresh 是必须的：缓存里可能躺着一条早前的失败记录（比如 DNSHE 凭证
 * 还没配好时查过一次），不跳过缓存的话用户刚加完就看到"查不到"，
 * 会以为功能坏了。失败结果只缓存 5 分钟，但 5 分钟也够让人困惑。
 */
async function lookupNewCustomDomain(domain) {
  try {
    const info = await getWhoisService().query(domain, { forceRefresh: true });
    return info || {};
  } catch (error) {
    logger.warn('新增域名查询失败', { domain, error: error.message });
    return { whoisError: error.message };
  }
}

export async function handleCustomDomainsApi(request) {
  // 验证管理员权限 - 使用安全token验证
  const token = getCookie(request, 'admin_token');
  const payload = await verifyAuthToken(token, 'admin');

  if (!payload) {
    return new Response(JSON.stringify({ error: '需要管理员权限' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    await appState.customDomainManager.loadFromKV();

    if (request.method === 'GET') {
      // 获取所有自定义域名
      const domains = appState.customDomainManager.getAllDomains();
      return new Response(JSON.stringify({ domains }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (request.method === 'POST') {
      const data = await request.json();

      // 验证action参数
      let action, domain;
      try {
        action = validateAction(data.action, ['add', 'update', 'remove']);
        domain = validateDomain(data.domain);
      } catch (error) {
        if (error instanceof ValidationError) {
          return new Response(JSON.stringify({
            error: error.userMessage,
            field: error.field
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        throw error;
      }

      const { info } = data;

      switch (action) {
        case 'add': {
          // 已存在就别再走一遍查询：查询有成本（DNSHE 按 IP 限速），
          // 而且 addDomain 抛的是通用 Error，会变成 500
          if (appState.customDomainManager.getDomain(domain)) {
            return jsonResponse({ error: '域名已在列表中，可直接编辑它', field: 'domain' }, 409);
          }

          // 新流程：用户只填域名，剩下交给 WHOIS。查到就写库，查不到再让他补
          const live = await lookupNewCustomDomain(domain);
          const merged = mergeCustomDomainRecord({}, live);
          const ok = merged.lookupStatus === 'ok';

          const record = await appState.customDomainManager.addDomain(domain, {
            notes: info && info.notes,
            registrar: merged.registrar,
            registrationDate: merged.registrationDate,
            expirationDate: merged.expirationDate,
            nameServers: merged.nameServers,
            dataSource: merged.dataSource,
            isPermanent: merged.isPermanent,
            lookupStatus: ok ? 'ok' : 'missing',
            lookupError: merged.lookupError
          });

          return jsonResponse({
            success: true,
            domain,
            // 前端据此决定：直接提示成功，还是紧接着弹出补填表单
            needsManual: !ok,
            record: {
              notes: record.notes,
              registrar: record.registrar,
              registrationDate: record.registrationDate,
              expirationDate: record.expirationDate,
              isPermanent: record.isPermanent,
              dataSource: record.dataSource,
              lookupStatus: record.lookupStatus,
              lookupError: record.lookupError
            },
            message: ok
              ? `已添加 ${domain}，到期日期 ${merged.expirationDate}`
              : `已添加 ${domain}，但没查到到期信息`
          });
        }

        case 'update': {
          // 检查域名是否存在于自定义域名管理器中
          const existingDomain = appState.customDomainManager.getDomain(domain);

          // 只有真的改了「注册商 / 注册日期 / 到期日期」才关闭 WHOIS 自动更新。
          // 以前只要走一次编辑就冻结，改个备注也会让到期日从此不再自动跟进，
          // 而弹窗还在提示"将关闭自动更新"——用户只能靠「标记已续费」绕开
          const dateFields = ['registrar', 'registrationDate', 'expirationDate'];
          const touched = dateFields.some(key => {
            if (!info || info[key] === undefined) return false;
            const next = knownValue(info[key]) || 'Unknown';
            const prev = knownValue(existingDomain && existingDomain[key]) || 'Unknown';
            return next !== prev;
          });

          const patch = { ...info };
          if (touched) {
            patch.autoUpdateWhois = false; // 手动编辑后禁用自动WHOIS更新
            patch.lastManualEdit = new Date().toISOString();
            patch.lookupStatus = hasUsableExpiry(patch) ? 'manual' : 'missing';
          } else if (existingDomain) {
            // 没动日期就保持原来的自动更新开关，别悄悄改掉
            patch.autoUpdateWhois = existingDomain.autoUpdateWhois;
          }

          if (existingDomain) {
            await appState.customDomainManager.updateDomain(domain, patch);
          } else {
            // 域名不存在，创建新的自定义域名记录
            await appState.customDomainManager.addDomain(domain, {
              ...patch,
              status: (info && info.status) || 'Active',
              notes: (info && info.notes) || '手动添加的域名信息修正',
              autoUpdateWhois: false, // 手动编辑的域名不自动更新
              lastManualEdit: new Date().toISOString(),
              lookupStatus: hasUsableExpiry(patch) ? 'manual' : 'missing'
            });
          }

          return jsonResponse({
            success: true,
            autoUpdateWhois: patch.autoUpdateWhois !== false,
            message: touched ? '域名更新成功，已关闭自动更新' : '域名更新成功'
          });
        }

        case 'remove':
          await appState.customDomainManager.removeDomain(domain);
          return jsonResponse({ success: true, message: '域名删除成功' });

        default:
          return jsonResponse({ error: '无效的操作' }, 400);
      }
    }

    return new Response('Method Not Allowed', { status: 405 });
  } catch (error) {
    console.error('自定义域名管理错误:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

/* ---------------- 免费域名白名单（KV 动态配置） ---------------- */

const SUFFIX_PATTERN = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;
const RENEW_VALUES = ['permanent', 'auto', 'manual'];
const LOOKUP_TYPES = ['rdap', 'dnshe', 'whois'];

/**
 * 校验并规范化前端提交的后缀配置。
 * 白名单直接决定"哪些域名不再查 WHOIS"，格式错误会让匹配表被垃圾数据污染，
 * 所以这里对后缀、续期模式、查询类型都做严格校验。
 * 导出是为了让单测能直接覆盖校验规则，不必伪造整个请求上下文。
 */
export function normalizeSuffixPayload(data) {
  const suffix = String(data.suffix || data.domain || '')
    .trim().toLowerCase().replace(/^\.+|\.+$/g, '');

  if (!suffix || suffix.length < 2 || suffix.length > 253 || !SUFFIX_PATTERN.test(suffix)) {
    throw new ValidationError('后缀格式不正确，示例：is-a.dev', 'suffix');
  }

  const renew = data.renew === undefined || data.renew === ''
    ? 'auto'
    : String(data.renew).toLowerCase();
  if (!RENEW_VALUES.includes(renew)) {
    throw new ValidationError('续期模式只能是 permanent / auto / manual', 'renew');
  }

  const entry = {
    suffix,
    renew,
    registrar: String(data.registrar || '').trim() || 'Unknown',
    provider: String(data.provider || '').trim() || String(data.registrar || '').trim() || suffix,
    note: String(data.note || '').trim(),
    category: data.category === 'public' ? 'public' : 'free'
  };

  // 查询配置三选一：不填 = 只使用元数据兜底
  const lookupType = String(data.lookupType || '').trim().toLowerCase();
  const endpoint = String(data.endpoint || '').trim();
  if (lookupType) {
    if (!LOOKUP_TYPES.includes(lookupType)) {
      throw new ValidationError('查询方式只能是 rdap / dnshe / whois', 'lookupType');
    }
    if (!endpoint) {
      throw new ValidationError('选择查询方式后必须填写端点', 'endpoint');
    }
    if (lookupType === 'whois' && !/^[a-z0-9.-]+(:\d{1,5})?$/i.test(endpoint)) {
      throw new ValidationError('WHOIS/TCP 端点格式应为 host 或 host:port', 'endpoint');
    }
    entry.lookup = { type: lookupType, endpoint };
  }

  return entry;
}

function freeDomainListPayload() {
  const manager = appState.freeDomainManager;
  return {
    entries: manager ? manager.listAll() : [],
    total: manager ? manager.size : 0
  };
}

export async function handleFreeDomainsApi(request) {
  const token = getCookie(request, 'admin_token');
  const payload = await verifyAuthToken(token, 'admin');

  if (!payload) {
    return new Response(JSON.stringify({ error: '需要管理员权限' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const kv = appState.env ? appState.env.DOMAIN_INFO : null;

  try {
    if (request.method === 'GET') {
      return new Response(JSON.stringify(freeDomainListPayload()), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const data = await request.json();
    let action;
    try {
      action = validateAction(data.action, ['add', 'update', 'remove', 'restore']);
    } catch (error) {
      if (error instanceof ValidationError) {
        return new Response(JSON.stringify({ error: error.userMessage, field: error.field }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      throw error;
    }

    if (!kv) {
      return new Response(JSON.stringify({
        error: 'KV 未绑定（DOMAIN_INFO），无法保存白名单配置'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    let entry;
    if (action !== 'restore') {
      try {
        entry = normalizeSuffixPayload(data);
      } catch (error) {
        if (error instanceof ValidationError) {
          return new Response(JSON.stringify({ error: error.userMessage, field: error.field }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        throw error;
      }
    }

    const suffix = action === 'restore'
      ? String(data.suffix || '').trim().toLowerCase()
      : entry.suffix;

    if (!suffix) {
      return new Response(JSON.stringify({ error: '缺少 suffix 参数' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    await updateFreeDomainEntries(kv, entries => {
      if (action === 'restore') return dropEntry(entries, suffix);
      if (action === 'remove') {
        // 内置/环境变量条目不能真的删掉，只能写一条 disabled 覆盖标记；
        // KV 层优先级最高，于是它就"消失"了，但仍能在管理页面恢复
        return upsertEntry(entries, { suffix, disabled: true });
      }
      return upsertEntry(entries, { ...entry, disabled: false });
    });

    // saveFreeDomainEntries 已经把新配置写进内存缓存，这里直接重建管理器即可。
    // 同时清掉 whoisService 单例，避免它继续持有旧的白名单引用。
    const kvEntries = await loadFreeDomainEntries(kv);
    appState.freeDomainManager = new FreeDomainManager({
      overrides: appState.env ? appState.env.FREE_DOMAIN_SUFFIXES : undefined,
      kvEntries
    });
    appState.whoisService = null;

    const messages = {
      add: `已添加 ${suffix}`,
      update: `已更新 ${suffix}`,
      remove: `已停用 ${suffix}`,
      restore: `已恢复 ${suffix} 的默认配置`
    };

    return new Response(JSON.stringify({
      success: true,
      message: messages[action],
      ...freeDomainListPayload()
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('免费域名配置错误:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

/* ------------------------------------------------------------------ *
 * 页面渲染的公共部分：条件请求 + 后台补全
 * ------------------------------------------------------------------ */

/** FNV-1a，够快也够散，只用来给 HTML 生成 ETag */
function hashString(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16) + '-' + str.length.toString(16);
}

/**
 * 页面响应：ETag + 304。
 *
 * 之前用 Cache-Control: no-store，浏览器每次导航都得把整页（几十万字符）重新
 * 下载一遍。页面内容完全由数据决定，数据没变时 HTML 也没变，用 ETag 做条件
 * 请求就能让"数据没变"的访问只回几十字节。
 *
 * 用 no-cache 而不是 no-store：允许浏览器留副本，但每次使用前必须回来验证。
 */
export function htmlResponse(request, html) {
  const etag = '"' + hashString(html) + '"';
  const headers = {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'private, no-cache, must-revalidate',
    'ETag': etag,
    Vary: 'Cookie'
  };

  const inm = request && request.headers ? request.headers.get('if-none-match') : null;
  if (inm && inm.split(',').some(tag => tag.trim() === etag)) {
    return new Response(null, { status: 304, headers });
  }
  return new Response(html, { status: 200, headers });
}

/**
 * 本次渲染有域名没查完时，把剩下的交给 ctx.waitUntil 继续。
 *
 * 为什么不直接在请求里查完：DNSHE 公共接口按 2 秒一个排队，几十个域名就是
 * 一分多钟，浏览器早就超时了。先渲染已知的，剩下的后台慢慢补，用户下次刷新
 * 就能看到完整数据。
 */
function scheduleBackgroundFill(ctx, pending) {
  if (!pending || !ctx || typeof ctx.waitUntil !== 'function') return;

  ctx.waitUntil((async () => {
    try {
      const zones = await fetchCloudflareDomainsInfo();
      const result = await fetchDomainInfo(zones, { budgetMs: CONFIG.PAGE_BACKGROUND_BUDGET });
      logger.info('后台补全域名信息完成', { total: zones.length, pending: result.pending });
    } catch (error) {
      logger.warn('后台补全域名信息失败', { error: error.message });
    }
  })());
}

export async function handleFrontend(request, env, ctx) {
  try {
    // 如果设置了访问密码,验证token
    // 注意要同时判断明文（环境变量）和哈希（KV 设置），只判断前者会让
    // 「在设置页设了密码」的部署变成完全公开
    if (appState.ACCESS_PASSWORD || appState.ACCESS_PASSWORD_HASH) {
      const token = getCookie(request, 'access_token');
      const payload = await verifyAuthToken(token, 'access');

      if (!payload) {
        return Response.redirect(`${new URL(request.url).origin}/login`, 302);
      }
    }

    const startedAt = Date.now();
    const domains = await fetchCloudflareDomainsInfo();
    const { domains: domainsWithInfo, pending } = await fetchDomainInfo(domains, {
      budgetMs: CONFIG.PAGE_LOOKUP_BUDGET
    });

    scheduleBackgroundFill(ctx, pending);

    logger.info('前台页面渲染完成', {
      domains: domainsWithInfo.length,
      pending,
      ms: Date.now() - startedAt
    });

    return htmlResponse(request, generateHTML(domainsWithInfo, false, { pending }));
  } catch (error) {
    console.error('前台页面异常:', error);
    return new Response(`页面加载失败: ${error.message}`, { status: 500 });
  }
}

export async function handleAdmin(request, env, ctx) {
  try {
    // 验证管理员token
    const token = getCookie(request, 'admin_token');
    const payload = await verifyAuthToken(token, 'admin');

    if (!payload) {
      return Response.redirect(`${new URL(request.url).origin}/admin-login`, 302);
    }

    const startedAt = Date.now();
    const domains = await fetchCloudflareDomainsInfo();
    const { domains: domainsWithInfo, pending } = await fetchDomainInfo(domains, {
      budgetMs: CONFIG.PAGE_LOOKUP_BUDGET
    });

    scheduleBackgroundFill(ctx, pending);

    logger.info('管理页渲染完成', {
      domains: domainsWithInfo.length,
      pending,
      ms: Date.now() - startedAt
    });

    return htmlResponse(request, generateHTML(domainsWithInfo, true, { pending }));
  } catch (error) {
    console.error('管理页面异常:', error);
    return new Response(`管理页面加载失败: ${error.message}`, { status: 500 });
  }
}

export async function handleLogin(request, env) {
  const locale = getLocale(request);
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  const limiter = getRateLimiter(env);
  const logger = getAuditLogger(env);

  try {
    if (limiter) {
      const isLocked = await limiter.isLockedOut(ip);
      if (isLocked) {
        return new Response(generateLoginHTML(t(locale, 'login.title'), "/login", t(locale, 'login.locked')), {
          headers: { "Content-Type": "text/html; charset=utf-8" },
          status: 429
        });
      }

      const rateCheck = await limiter.checkLoginLimit(ip);
      if (!rateCheck.allowed) {
        return new Response(generateLoginHTML(t(locale, 'login.title'), "/login", t(locale, 'login.rateLimited', { seconds: rateCheck.retryAfter })), {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Retry-After": String(rateCheck.retryAfter)
          },
          status: 429
        });
      }
    }

    if (request.method === "POST") {
      const formData = await request.formData();
      const password = formData.get("password");

      console.log("前台登录尝试");

      if (await verifyAccessPassword(password)) {
        console.log("前台登录成功");

        if (limiter) await limiter.clearFailedLogins(ip);
        if (logger) await logger.log(AUDIT_EVENTS.LOGIN_SUCCESS, {}, request);

        const maxAge = sessionSeconds();
        const token = await createAuthToken('access', maxAge);
        const isHttps = request.url.startsWith('https://');

        return new Response("Login successful", {
          status: 302,
          headers: {
            "Location": "/",
            "Set-Cookie": createCookieHeader('access_token', token, maxAge, isHttps)
          }
        });
      } else {
        console.log("前台登录失败：密码错误");

        if (limiter) await limiter.recordFailedLogin(ip);
        if (logger) await logger.log(AUDIT_EVENTS.LOGIN_FAILED, { reason: 'invalid_password' }, request);

        return new Response(generateLoginHTML(t(locale, 'login.title'), "/login", t(locale, 'login.error')), {
          headers: { "Content-Type": "text/html; charset=utf-8" },
          status: 401
        });
      }
    }

    return new Response(generateLoginHTML(t(locale, 'login.title'), "/login"), {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  } catch (error) {
    console.error('登录处理异常:', error);
    return createErrorResponse(new ApiError(ERROR_CODES.INTERNAL_ERROR, error.message, 500));
  }
}

export async function handleAdminLogin(request, env) {
  const locale = getLocale(request);
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  const limiter = getRateLimiter(env);
  const logger = getAuditLogger(env);

  try {
    console.log("处理管理员登录请求");

    if (limiter) {
      const isLocked = await limiter.isLockedOut(`admin:${ip}`);
      if (isLocked) {
        return new Response(generateLoginHTML(t(locale, 'admin.title'), "/admin-login", t(locale, 'login.locked')), {
          headers: { "Content-Type": "text/html; charset=utf-8" },
          status: 429
        });
      }

      const rateCheck = await limiter.checkLimit(`admin:${ip}`, 3, RATE_LIMIT_CONFIG.LOGIN_WINDOW_MS);
      if (!rateCheck.allowed) {
        return new Response(generateLoginHTML(t(locale, 'admin.title'), "/admin-login", t(locale, 'login.rateLimited', { seconds: rateCheck.retryAfter })), {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Retry-After": String(rateCheck.retryAfter)
          },
          status: 429
        });
      }
    }

    if (request.method === "POST") {
      console.log("处理POST登录表单");
      const formData = await request.formData();
      const password = formData.get("password");

      console.log("验证管理员密码");

      if (await verifyAdminPassword(password)) {
        console.log("管理员登录成功");

        if (limiter) await limiter.clearFailedLogins(`admin:${ip}`);
        if (logger) await logger.log(AUDIT_EVENTS.ADMIN_LOGIN_SUCCESS, {}, request);

        const maxAge = sessionSeconds();
        const token = await createAuthToken('admin', maxAge);
        const isHttps = request.url.startsWith('https://');

        return new Response("Admin login successful", {
          status: 302,
          headers: {
            "Location": "/admin",
            "Set-Cookie": createCookieHeader('admin_token', token, maxAge, isHttps)
          }
        });
      } else {
        console.log("管理员登录失败：密码错误");

        if (limiter) await limiter.recordFailedLogin(`admin:${ip}`);
        if (logger) await logger.log(AUDIT_EVENTS.ADMIN_LOGIN_FAILED, { reason: 'invalid_password' }, request);

        return new Response(generateLoginHTML(t(locale, 'admin.title'), "/admin-login", t(locale, 'admin.error')), {
          headers: { "Content-Type": "text/html; charset=utf-8" },
          status: 401
        });
      }
    }

    return new Response(generateLoginHTML(t(locale, 'admin.title'), "/admin-login"), {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  } catch (error) {
    console.error('管理员登录异常:', error);
    return createErrorResponse(new ApiError(ERROR_CODES.INTERNAL_ERROR, error.message, 500));
  }
}

/**
 * 退出前台登录。
 *
 * 用 GET 而不是 POST：退出是个幂等的"清状态"操作，做成链接才能在
 * 没有 JS 的情况下也能用。Cookie 是 SameSite=Strict，跨站请求根本带不上，
 * 所以不怕被人用一张图片把你登出。
 */
export async function handleLogout(request) {
  const isHttps = request.url.startsWith('https://');
  const logger = getAuditLogger(appState.env);

  try {
    if (logger) await logger.log(AUDIT_EVENTS.LOGOUT, {}, request);
  } catch (error) {
    console.error('退出登录审计写入失败:', error);
  }

  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/login',
      'Set-Cookie': createClearCookieHeader('access_token', isHttps),
      'Cache-Control': 'no-store'
    }
  });
}

/**
 * 退出管理员登录。
 *
 * 连 access_token 一起清：管理员会话能看到全部账户与凭证，在共用设备上
 * 只清 admin_token 会留下一个还能读域名的前台会话，等于没退干净。
 */
export async function handleAdminLogout(request) {
  const isHttps = request.url.startsWith('https://');
  const logger = getAuditLogger(appState.env);

  try {
    if (logger) await logger.log(AUDIT_EVENTS.ADMIN_LOGOUT, {}, request);
  } catch (error) {
    console.error('退出登录审计写入失败:', error);
  }

  const headers = new Headers({
    'Location': '/admin-login',
    'Cache-Control': 'no-store'
  });
  headers.append('Set-Cookie', createClearCookieHeader('admin_token', isHttps));
  headers.append('Set-Cookie', createClearCookieHeader('access_token', isHttps));

  return new Response(null, { status: 302, headers });
}

export async function handleAuditLogs(request, env) {
  try {
    const adminToken = getCookie(request, 'admin_token');
    const isAdmin = await verifyAuthToken(adminToken, 'admin');

    if (!isAdmin) {
      return createErrorResponse(new ApiError(ERROR_CODES.AUTH_FAILED, 'Admin authentication required', 401));
    }

    const logger = getAuditLogger(env);
    if (!logger) {
      return createErrorResponse(new ApiError(ERROR_CODES.CONFIG_ERROR, 'Audit logging not configured', 500));
    }

    const url = new URL(request.url);
    const limit = parseInt(url.searchParams.get('limit') || '100', 10);
    const offset = parseInt(url.searchParams.get('offset') || '0', 10);

    const logs = await logger.getLogs(Math.min(limit, 500), offset);

    return createSuccessResponse({
      logs: logs,
      pagination: {
        limit: limit,
        offset: offset,
        hasMore: logs.length === limit
      }
    });
  } catch (error) {
    console.error('获取审计日志异常:', error);
    return createErrorResponse(new ApiError(ERROR_CODES.INTERNAL_ERROR, error.message, 500));
  }
}

export async function handleWhoisRequest(domain) {
  try {
    console.log('处理WHOIS请求: ' + domain);

    if (!domain) {
      return new Response(JSON.stringify({
        error: true,
        message: '域名参数不能为空'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const service = getWhoisService();
    // 这是抽屉里的「刷新 WHOIS」，用户点了就是想要新数据，
    // 读缓存返回同一条旧记录等于没刷新
    const whoisInfo = await service.query(domain, { forceRefresh: true });

    // 查到真数据才回写，规则见 syncCustomDomainFromLookup：
    // 注册表兜底值、查询报错、用户手工改过的记录都不覆盖
    await syncCustomDomainFromLookup(domain, whoisInfo);

    // 检查是否有原始数据
    let rawData = null;
    if (!appState.freeDomainManager.isFree(domain) && CONFIG.WHOIS_PROXY) {
      try {
        const response = await fetch(`${CONFIG.WHOIS_PROXY}/api/lookup?query=${domain}`, {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            'User-Agent': `DSMC/${CONFIG.VERSION}`,
          },
          signal: AbortSignal.timeout(CONFIG.TIMEOUT)
        });

        if (response.ok) {
          const data = await response.json();
          rawData = data.result?.rawWhoisContent || data.rawData || data.raw_data;
        }
      } catch (error) {
        console.warn('获取原始WHOIS数据失败: ' + domain, error.message);
      }
    }

    return new Response(JSON.stringify({
      error: false,
      // 回显实际查询的域名：用户核对数据时最容易搞混的就是"这条是谁的"
      queriedDomain: domain,
      data: whoisInfo,
      rawData: rawData
    }), {
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('WHOIS请求处理异常: ' + domain, error);
    return new Response(JSON.stringify({
      error: true,
      message: `获取WHOIS数据失败: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
export async function handleApiUpdate(request) {
  try {
    console.log("处理API更新请求");

    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "只支持POST请求" }), {
        status: 405,
        headers: { "Content-Type": "application/json" }
      });
    }

    // 验证管理员权限 - 使用安全token验证
    const token = getCookie(request, 'admin_token');
    const payload = await verifyAuthToken(token, 'admin');

    if (!payload) {
      return new Response(JSON.stringify({ error: "未授权访问" }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }

    const data = await request.json();
    const { action, domain, force } = data;

    if (!action) {
      return new Response(JSON.stringify({ error: "缺少action参数" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    let result = {};

    switch (action) {
      case "refresh":
        result = await handleRefreshAction(domain, force);
        break;
      case "clear-cache":
        result = await handleClearCacheAction(domain);
        break;
      case "test-apis":
        result = await handleTestApisAction();
        break;
      case "get-stats":
        result = await handleGetStatsAction();
        break;
      default:
        return new Response(JSON.stringify({ error: "不支持的action" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
    }

    return new Response(JSON.stringify(result), {
      headers: { "Content-Type": "application/json" }
    });

  } catch (error) {
    console.error("API更新处理异常:", error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}

/** 只有这些来源算"真的查到了"，注册表兜底值不写回数据库 */
const LIVE_SOURCES = new Set(['rdap', 'dnshe', 'whois', 'whois-proxy']);

/**
 * 把一次实时查询的结果回写到自定义域名记录里。
 *
 * 只在"确实查到了"时写：注册表兜底值（Auto-Renewal / 永久）拿来回写，
 * 会把用户手上真实的到期日覆盖成一句占位文本——v2.3.1 踩过这个坑。
 */
async function syncCustomDomainFromLookup(domain, info) {
  if (!info || !LIVE_SOURCES.has(info.dataSource)) return false;

  await appState.customDomainManager.loadFromKV();
  const existing = appState.customDomainManager.getDomain(domain);
  if (!existing) return false;
  if (existing.autoUpdateWhois === false) return false; // 手工改过的不动

  const merged = mergeCustomDomainRecord(existing, info);
  if (merged.lookupStatus === 'missing') return false;

  await appState.customDomainManager.updateDomain(domain, {
    registrar: merged.registrar,
    registrationDate: merged.registrationDate,
    expirationDate: merged.expirationDate,
    nameServers: merged.nameServers,
    dataSource: merged.dataSource,
    isPermanent: merged.isPermanent,
    lookupStatus: 'ok',
    lookupError: null,
    lastWhoisUpdate: new Date().toISOString()
  });
  return true;
}

export async function handleRefreshAction(domain, force) {
  if (domain) {
    console.log('刷新单个域名: ' + domain + ' (强制: ' + force + ')');

    // 刷新就是刷新，不顺手续期。
    // 以前免费域名在这里先把到期日 +1 年再返回，点一次「刷新 WHOIS」就等于
    // 悄悄改了数据，也让「标记已续费」变成唯一能改日期的入口——两件事被搅在一起。
    // 续期请走 /api/custom-domains 的 update（前端「标记已续费」）。
    const service = getWhoisService();
    const info = await service.query(domain, { forceRefresh: Boolean(force) });

    // 查到真数据就落库，抽屉里刷出来的结果下次打开还在
    await syncCustomDomainFromLookup(domain, info);

    return {
      success: true,
      message: `域名 ${domain} 信息已更新`,
      data: info
    };
  } else {
    console.log("刷新所有域名");
    // 强制刷新时绕过 Zone 列表缓存，否则刚在 Cloudflare 加的域名要等两分钟
    const domains = await fetchCloudflareDomainsInfo({ force: Boolean(force) });

    if (force) {
      await appState.cacheManager.clearAll();
      console.log("已清除所有缓存");
    }

    const updated = await fetchDomainInfo(domains, { budgetMs: CONFIG.PAGE_BACKGROUND_BUDGET });
    return {
      success: true,
      message: updated.pending
        ? `已更新 ${updated.domains.length - updated.pending} 个域名，${updated.pending} 个未查完（稍后刷新继续补）`
        : `已更新 ${updated.domains.length} 个域名信息`,
      count: updated.domains.length,
      pending: updated.pending,
      force: force
    };
  }
}

export async function handleClearCacheAction(domain) {
  if (domain) {
    await appState.cacheManager.delete(domain);
    return {
      success: true,
      message: `域名 ${domain} 缓存已清除`
    };
  } else {
    const count = await appState.cacheManager.clearAll();
    return {
      success: true,
      message: `所有缓存已清除，共 ${count} 个项目`
    };
  }
}

export async function handleTestApisAction() {
  console.log("🧪 测试API密钥状态");
  const results = await appState.apiKeyManager.testAll();

  return {
    success: true,
    message: "API密钥测试完成",
    results: results.map(item => ({
      username: item.username,
      status: item.ok ? '正常' : '异常',
      error: item.error,
      active: item.active,
      errorCount: item.errorCount
    }))
  };
}

export async function handleGetStatsAction() {
  console.log("获取系统统计信息");

  const domains = await fetchCloudflareDomainsInfo();
  const activeKeys = appState.apiKeyManager.getActiveKeys();

  // 获取缓存统计
  let cacheList = { keys: [] };
  if (appState.env && appState.env.DOMAIN_INFO) {
    cacheList = await appState.env.DOMAIN_INFO.list({ prefix: 'whois_' });
  } else {
    console.error('❌ DOMAIN_INFO KV命名空间未初始化');
  }

  return {
    success: true,
    stats: {
      totalDomains: domains.length,
      activeApiKeys: activeKeys.length,
      totalApiKeys: appState.apiKeyManager.keys.length,
      cachedDomains: cacheList.keys.length,
      version: CONFIG.VERSION,
      lastUpdate: new Date().toISOString()
    }
  };
}
