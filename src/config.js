// 配置与国际化模块

import { appState } from './app-state.js';

export const CONFIG = {
  VERSION: "1.2.0",
  TITLE: "Domain Manager",
  WHOIS_PROXY: "",
  CACHE_TTL: 7 * 24 * 60 * 60 * 1000,
  MAX_RETRIES: 3,
  BATCH_SIZE: 5,
  TIMEOUT: 30000,
  DEFAULT_LOCALE: 'zh-CN'
};

export const I18N = {
  'zh-CN': {
    login: {
      title: '域名管理系统',
      password: '请输入访问密码',
      submit: '登录',
      error: '密码错误',
      rateLimited: '尝试次数过多，请 {seconds} 秒后重试',
      locked: '账户已锁定，请30分钟后重试'
    },
    admin: {
      title: '管理后台',
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
      title: 'Domain Manager',
      password: 'Enter access password',
      submit: 'Login',
      error: 'Invalid password',
      rateLimited: 'Too many attempts, please retry in {seconds} seconds',
      locked: 'Account locked, please try again in 30 minutes'
    },
    admin: {
      title: 'Admin Panel',
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