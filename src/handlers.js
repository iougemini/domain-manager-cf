import { appState } from './app-state.js';
import { CONFIG, getLocale, t } from './config.js';
import { getCookie, verifyAuthToken, createAuthToken, secureCompare, createCookieHeader } from './auth.js';
import { validateDomain, validateApiKey, validateAction } from './validators.js';
import { ApiError, ERROR_CODES, ValidationError, createErrorResponse, createSuccessResponse } from './errors.js';
import { AUDIT_EVENTS, getAuditLogger, logger } from './logger.js';
import { getRateLimiter, RATE_LIMIT_CONFIG } from './rate-limiter.js';
import { getWhoisService, fetchCloudflareDomainsInfo, fetchDomainInfo } from './state.js';
import { testCloudflareApi } from './services/cloudflare.js';
import { generateHTML, generateLoginHTML } from './ui.js';
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

// Cloudflare API密钥管理API
export async function handleCfKeysApi(request) {
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
    await appState.apiKeyManager.init();

    if (request.method === 'GET') {
      // 获取所有API密钥
      const keys = appState.apiKeyManager.getAllKeys();
      return new Response(JSON.stringify({ keys }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (request.method === 'POST') {
      const data = await request.json();

      // 验证action参数
      let action;
      try {
        action = validateAction(data.action, ['add', 'remove', 'toggle', 'clearOldData']);
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

      switch (action) {
        case 'clearOldData':
          // 清除KV中的旧数据
          const cleared = await appState.apiKeyManager.clearOldKVData();
          if (cleared) {
            // 重新从环境变量初始化
            appState.apiKeyManager.initFromEnv();
            return new Response(JSON.stringify({
              success: true,
              message: '已清除KV旧数据并重新从环境变量加载'
            }), {
              headers: { 'Content-Type': 'application/json' }
            });
          } else {
            return new Response(JSON.stringify({
              success: true,
              message: 'KV中没有需要清除的旧数据'
            }), {
              headers: { 'Content-Type': 'application/json' }
            });
          }


        case 'add':
          // 验证API密钥和用户名
          try {
            const validatedKey = validateApiKey(data.key);
            const validatedUsername = data.username ? data.username.trim() : '';

            if (!validatedUsername) {
              throw new ValidationError('用户名不能为空', 'username');
            }

            await appState.apiKeyManager.addApiKey(validatedKey, validatedUsername);
            return new Response(JSON.stringify({ success: true, message: 'API密钥添加成功' }), {
              headers: { 'Content-Type': 'application/json' }
            });
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

        case 'remove':
        case 'toggle':
          // 验证API密钥
          try {
            const validatedKey = validateApiKey(data.key);

            if (action === 'remove') {
              await appState.apiKeyManager.removeApiKey(validatedKey);
              return new Response(JSON.stringify({ success: true, message: 'API密钥删除成功' }), {
                headers: { 'Content-Type': 'application/json' }
              });
            } else {
              const isActive = await appState.apiKeyManager.toggleApiKey(validatedKey);
              return new Response(JSON.stringify({
                success: true,
                message: `API密钥${isActive ? '启用' : '禁用'}成功`,
                active: isActive
              }), {
                headers: { 'Content-Type': 'application/json' }
              });
            }
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

        default:
          return new Response(JSON.stringify({ error: '无效的操作' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
      }
    }

    return new Response('Method Not Allowed', { status: 405 });
  } catch (error) {
    console.error('API密钥管理错误:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// 自定义域名管理API
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
        case 'add':
          await appState.customDomainManager.addDomain(domain, info);
          return new Response(JSON.stringify({ success: true, message: '域名添加成功' }), {
            headers: { 'Content-Type': 'application/json' }
          });

        case 'update':
          // 检查域名是否存在于自定义域名管理器中
          const existingDomain = appState.customDomainManager.getDomain(domain);

          if (existingDomain) {
            // 域名已存在，直接更新，并标记为手动编辑
            await appState.customDomainManager.updateDomain(domain, {
              ...info,
              autoUpdateWhois: false, // 手动编辑后禁用自动WHOIS更新
              lastManualEdit: new Date().toISOString()
            });
          } else {
            // 域名不存在，创建新的自定义域名记录
            await appState.customDomainManager.addDomain(domain, {
              ...info,
              status: info.status || 'Active',
              notes: info.notes || '手动添加的域名信息修正',
              autoUpdateWhois: false, // 手动编辑的域名不自动更新
              lastManualEdit: new Date().toISOString()
            });
          }

          return new Response(JSON.stringify({ success: true, message: '域名更新成功' }), {
            headers: { 'Content-Type': 'application/json' }
          });

        case 'remove':
          await appState.customDomainManager.removeDomain(domain);
          return new Response(JSON.stringify({ success: true, message: '域名删除成功' }), {
            headers: { 'Content-Type': 'application/json' }
          });

        default:
          return new Response(JSON.stringify({ error: '无效的操作' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
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

export async function handleFrontend(request) {
  try {
    // 如果设置了访问密码,验证token
    if (appState.ACCESS_PASSWORD) {
      const token = getCookie(request, 'access_token');
      const payload = await verifyAuthToken(token, 'access');

      if (!payload) {
        return Response.redirect(`${new URL(request.url).origin}/login`, 302);
      }
    }

    console.log("获取Cloudflare域名信息...");
    const domains = await fetchCloudflareDomainsInfo();
    console.log('获取到 ' + domains.length + ' 个Cloudflare域名');

    console.log("补充域名详细信息...");
    const domainsWithInfo = await fetchDomainInfo(domains);
    console.log('处理完成，共 ' + domainsWithInfo.length + ' 个域名');

    return new Response(generateHTML(domainsWithInfo, false), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  } catch (error) {
    console.error('前台页面异常:', error);
    return new Response(`页面加载失败: ${error.message}`, { status: 500 });
  }
}

export async function handleAdmin(request) {
  try {
    // 验证管理员token
    const token = getCookie(request, 'admin_token');
    const payload = await verifyAuthToken(token, 'admin');

    if (!payload) {
      return Response.redirect(`${new URL(request.url).origin}/admin-login`, 302);
    }

    console.log("管理员获取域名信息...");
    const domains = await fetchCloudflareDomainsInfo();
    const domainsWithInfo = await fetchDomainInfo(domains);

    return new Response(generateHTML(domainsWithInfo, true), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
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

      if (secureCompare(password, appState.ACCESS_PASSWORD)) {
        console.log("前台登录成功");

        if (limiter) await limiter.clearFailedLogins(ip);
        if (logger) await logger.log(AUDIT_EVENTS.LOGIN_SUCCESS, {}, request);

        const token = await createAuthToken('access', 86400);
        const isHttps = request.url.startsWith('https://');

        return new Response("Login successful", {
          status: 302,
          headers: {
            "Location": "/",
            "Set-Cookie": createCookieHeader('access_token', token, 86400, isHttps)
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

      if (secureCompare(password, appState.ADMIN_PASSWORD)) {
        console.log("管理员登录成功");

        if (limiter) await limiter.clearFailedLogins(`admin:${ip}`);
        if (logger) await logger.log(AUDIT_EVENTS.ADMIN_LOGIN_SUCCESS, {}, request);

        const token = await createAuthToken('admin', 86400);
        const isHttps = request.url.startsWith('https://');

        return new Response("Admin login successful", {
          status: 302,
          headers: {
            "Location": "/admin",
            "Set-Cookie": createCookieHeader('admin_token', token, 86400, isHttps)
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
    const whoisInfo = await service.query(domain);

    // 如果是自定义域名且查询成功，仅在没有手动修改的情况下更新
    await appState.customDomainManager.loadFromKV();
    const customDomain = appState.customDomainManager.getDomain(domain);
    if (customDomain && whoisInfo && whoisInfo.registrar !== 'Unknown') {
      // 只有在原数据不完整或明确标记为可自动更新时才覆盖
      const shouldUpdate = customDomain.registrar === 'Unknown' ||
        customDomain.registrationDate === 'Unknown' ||
        !customDomain.registrationDate ||
        customDomain.autoUpdateWhois !== false; // 默认允许自动更新，除非明确禁止

      if (shouldUpdate) {
        try {
          await appState.customDomainManager.updateDomain(domain, {
            registrar: whoisInfo.registrar,
            registrationDate: whoisInfo.registrationDate,
            expirationDate: whoisInfo.expirationDate,
            lastWhoisUpdate: new Date().toISOString()
          });
          console.log('已更新自定义域名WHOIS信息: ' + domain);
        } catch (error) {
          console.warn('更新自定义域名WHOIS信息失败: ' + domain, error);
        }
      } else {
        console.log('域名 ' + domain + ' 已手动修改，跳过WHOIS自动更新');
      }
    }

    // 检查是否有原始数据
    let rawData = null;
    if (!appState.freeDomainManager.isFree(domain) && CONFIG.WHOIS_PROXY) {
      try {
        const response = await fetch(`${CONFIG.WHOIS_PROXY}/api/lookup?query=${domain}`, {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            'User-Agent': `DomainKeeper/${CONFIG.VERSION}`,
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

export async function handleRefreshAction(domain, force) {
  if (domain) {
    console.log('刷新单个域名: ' + domain + ' (强制: ' + force + ')');

    // 检查是否为免费域名且不是eu.org（永久域名）
    const isFreeDomain = appState.freeDomainManager.isFree(domain);
    const isEuOrg = domain.includes('eu.org');

    // 如果是免费域名且不是eu.org，则执行续期操作
    if (isFreeDomain && !isEuOrg) {
      // 加载自定义域名信息
      await appState.customDomainManager.loadFromKV();
      let customDomain = appState.customDomainManager.getDomain(domain);

      // 如果自定义域名存在且有有效的过期日期，则进行续期
      if (customDomain && customDomain.expirationDate && customDomain.expirationDate !== 'Unknown') {
        try {
          const currentExpDate = new Date(customDomain.expirationDate);
          // 将过期日期延长一年
          currentExpDate.setFullYear(currentExpDate.getFullYear() + 1);

          // 更新自定义域名的过期日期
          await appState.customDomainManager.updateDomain(domain, {
            ...customDomain,
            expirationDate: currentExpDate.toISOString().split('T')[0],
            lastUpdated: new Date().toISOString(),
            lastRenewal: new Date().toISOString() // 添加续期时间记录
          });

          console.log('免费域名续期成功: ' + domain);
          return {
            success: true,
            message: `免费域名 ${domain} 续期成功，过期日期已延长一年`,
            data: { ...customDomain, expirationDate: currentExpDate.toISOString().split('T')[0] }
          };
        } catch (error) {
          console.error('免费域名续期失败: ' + domain, error);
        }
      }
    }

    if (force) {
      await appState.cacheManager.delete(domain);
      console.log('已清除缓存: ' + domain);
    }

    const service = getWhoisService();
    const info = await service.query(domain);
    return {
      success: true,
      message: `域名 ${domain} 信息已更新`,
      data: info
    };
  } else {
    console.log("刷新所有域名");
    const domains = await fetchCloudflareDomainsInfo();

    if (force) {
      await appState.cacheManager.clearAll();
      console.log("已清除所有缓存");
    }

    const updated = await fetchDomainInfo(domains);
    return {
      success: true,
      message: `已更新 ${updated.length} 个域名信息`,
      count: updated.length,
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
  const results = [];

  for (const keyInfo of appState.apiKeyManager.keys) {
    const testResult = await testCloudflareApi(keyInfo.key, keyInfo.username);
    results.push({
      username: keyInfo.username,
      key: keyInfo.key.slice(0, 10) + '...',
      status: testResult.success ? '正常' : '异常',
      error: testResult.error || null,
      active: keyInfo.active,
      errorCount: keyInfo.errorCount
    });
  }

  return {
    success: true,
    message: "API密钥测试完成",
    results: results
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
