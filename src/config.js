// 配置与国际化模块

import { appState } from './app-state.js';

/**
 * 项目身份信息（品牌、链接）。
 * 这些值会出现在侧边栏、登录页与「关于」页，可通过环境变量覆盖，
 * 方便 fork 后换成自己的仓库与社群。
 */
export const PROJECT = {
  NAME: 'DSMC',
  FULL_NAME: 'Domain Status Manager for Cloudflare',
  DESCRIPTION: '基于 Cloudflare Workers 的域名状态管理系统',
  GITHUB: 'https://github.com/iougemini/domain-manager-cf',
  COMMUNITY: 'https://niege.app',
  WECHAT: 'niepantea',
  LICENSE: 'MIT'
};

export const CONFIG = {
  VERSION: "2.7.0",
  // 缓存版本与展示版本分开：改 UI / 改品牌不该导致全量 WHOIS 重新查询。
  // 1.3.0：v2.2.0 把 DNSHE 的 401 兜底值当成正常结果缓存了 7 天，
  // 导致"补好 Key 仍报认证失败"。升版本号让这些中毒缓存一次性作废。
  // 1.3.1：加 DNSHE 域名回显校验后，把可能挂错域名的旧结果一并作废。
  CACHE_VERSION: "1.3.1",
  TITLE: PROJECT.NAME,
  WHOIS_PROXY: "",
  CACHE_TTL: 7 * 24 * 60 * 60 * 1000,
  // 查询失败（第三方接口报错 / 认证失败）只留 5 分钟：
  // 既避免每次刷新都去打第三方，又不至于让一次配置失误挂上一周
  CACHE_FAILURE_TTL: 5 * 60 * 1000,
  MAX_RETRIES: 3,
  BATCH_SIZE: 5,
  TIMEOUT: 30000,
  DEFAULT_LOCALE: 'zh-CN',
  // 免费域名实时查询（DigitalPlat RDAP / DNSHE WHOIS / pp.ua WHOIS-TCP）
  FREE_DOMAIN_LIVE_LOOKUP: true,
  FREE_DOMAIN_LOOKUP_TIMEOUT: 8000,
  FREE_DOMAIN_LOOKUP_UA: '',
  // 按服务商限流：DNSHE 公共接口 30 次/分钟，留余量取 2s 一个；
  // TCP WHOIS 是逐个连接，1.2s 足够；RDAP 相对宽松
  PACE_DNSHE: 2000,
  PACE_WHOIS: 1200,
  PACE_RDAP: 300,
  /**
   * 页面渲染允许花在"实时查询"上的时间上限（毫秒）。
   *
   * 冷缓存下把所有域名查一遍要几十秒（DNSHE 2 秒一个排队），浏览器就一直转圈。
   * 加了这道闸之后：缓存里有的立刻用，没有的按预算查，超预算的先占位渲染、
   * 由 ctx.waitUntil 在后台继续补。页面首字节不再受第三方接口速度支配。
   */
  PAGE_LOOKUP_BUDGET: 4000,
  /** 后台补全时给的最大时长，超过就放弃，剩下的下次访问再补 */
  PAGE_BACKGROUND_BUDGET: 25000,

  /* ---------------- 健康巡检（v2.7） ---------------- */
  /** DoH 单次查询超时。1.1.1.1 通常几十毫秒，5 秒已经算很宽容 */
  HEALTH_DNS_TIMEOUT: 5000,
  /** 单轮巡检的域名上限。Cron 有执行时长限制，宁可分几天轮完也不要一次超时全丢 */
  HEALTH_MAX_DOMAINS: 40,
  /** 同一域名在这个间隔内不重复探测（每天一次巡检，留 4 小时余量） */
  HEALTH_MIN_INTERVAL: 20 * 60 * 60 * 1000,
  /** 巡检结果在 KV 里保留 2 天：某次 Cron 失败不至于让整片记录一起消失 */
  HEALTH_TTL: 2 * 24 * 60 * 60 * 1000
};

export const I18N = {
  'zh-CN': {
    login: {
      title: '登录 DSMC',
      password: '请输入访问密码',
      submit: '登录',
      error: '密码错误',
      rateLimited: '尝试次数过多，请 {seconds} 秒后重试',
      locked: '账户已锁定，请30分钟后重试'
    },
    admin: {
      title: '管理员登录',
      password: '请输入管理员密码',
      submit: '登录',
      error: '管理员密码错误'
    },
    domain: {
      name: '域名',
      registrar: '注册商',
      expires: '到期时间',
      status: '状态',
      owner: '所有者',
      tags: '标签',
      actions: '操作',
      whois: 'WHOIS查询',
      expiringSoon: '即将到期',
      expired: '已过期',
      active: '正常'
    },
    common: {
      loading: '加载中...',
      error: '发生错误',
      success: '操作成功',
      cancel: '取消',
      confirm: '确认',
      save: '保存',
      delete: '删除',
      edit: '编辑',
      add: '添加',
      search: '搜索',
      refresh: '刷新',
      logout: '退出登录',
      noData: '暂无数据'
    },
    errors: {
      AUTH_FAILED: '认证失败',
      AUTH_EXPIRED: '登录已过期，请重新登录',
      RATE_LIMITED: '请求过于频繁，请稍后重试',
      VALIDATION_ERROR: '输入验证失败',
      NOT_FOUND: '未找到请求的资源',
      INTERNAL_ERROR: '服务器内部错误',
      CONFIG_ERROR: '配置错误',
      API_ERROR: 'API调用失败'
    }
  },
  'en-US': {
    login: {
      title: 'Sign in to DSMC',
      password: 'Enter access password',
      submit: 'Login',
      error: 'Invalid password',
      rateLimited: 'Too many attempts, please retry in {seconds} seconds',
      locked: 'Account locked, please try again in 30 minutes'
    },
    admin: {
      title: 'Admin Sign In',
      password: 'Enter admin password',
      submit: 'Login',
      error: 'Invalid admin password'
    },
    domain: {
      name: 'Domain',
      registrar: 'Registrar',
      expires: 'Expires',
      status: 'Status',
      owner: 'Owner',
      tags: 'Tags',
      actions: 'Actions',
      whois: 'WHOIS Lookup',
      expiringSoon: 'Expiring Soon',
      expired: 'Expired',
      active: 'Active'
    },
    common: {
      loading: 'Loading...',
      error: 'An error occurred',
      success: 'Operation successful',
      cancel: 'Cancel',
      confirm: 'Confirm',
      save: 'Save',
      delete: 'Delete',
      edit: 'Edit',
      add: 'Add',
      search: 'Search',
      refresh: 'Refresh',
      logout: 'Logout',
      noData: 'No data available'
    },
    errors: {
      AUTH_FAILED: 'Authentication failed',
      AUTH_EXPIRED: 'Session expired, please login again',
      RATE_LIMITED: 'Too many requests, please try again later',
      VALIDATION_ERROR: 'Validation failed',
      NOT_FOUND: 'Resource not found',
      INTERNAL_ERROR: 'Internal server error',
      CONFIG_ERROR: 'Configuration error',
      API_ERROR: 'API call failed'
    }
  }
};

export function getLocale(request) {
  const acceptLanguage = request.headers.get('Accept-Language') || '';
  if (acceptLanguage.includes('zh')) return 'zh-CN';
  if (acceptLanguage.includes('en')) return 'en-US';
  return CONFIG.DEFAULT_LOCALE;
}

export function t(locale, key, params = {}) {
  const keys = key.split('.');
  let value = I18N[locale] || I18N[CONFIG.DEFAULT_LOCALE];

  for (const k of keys) {
    if (value && typeof value === 'object') {
      value = value[k];
    } else {
      return key;
    }
  }

  if (typeof value === 'string') {
    return value.replace(/\{(\w+)\}/g, (match, paramKey) => {
      return params[paramKey] !== undefined ? params[paramKey] : match;
    });
  }

  return key;
}

// 硬编码 fallback 值 (生产环境必须通过环境变量配置)
export const CF_API_KEYS_FALLBACK = [];
export const USERNAMES_FALLBACK = [];
export const ACCESS_PASSWORD_FALLBACK = "";
export const ADMIN_PASSWORD_FALLBACK = "";

export function validateConfig() {
  const errors = [];

  if (!appState.CF_API_KEYS || appState.CF_API_KEYS.length === 0) {
    errors.push('CF_API_KEYS 未配置');
  }

  if (!appState.USERNAMES || appState.USERNAMES.length === 0) {
    errors.push('USERNAMES 未配置');
  }

  if (appState.CF_API_KEYS.length !== appState.USERNAMES.length) {
    errors.push('CF_API_KEYS 和 USERNAMES 数量不匹配');
  }

  if (!appState.ACCESS_PASSWORD) {
    errors.push('ACCESS_PASSWORD 未配置');
  }

  if (!appState.ADMIN_PASSWORD) {
    errors.push('ADMIN_PASSWORD 未配置');
  }

  return errors;
}