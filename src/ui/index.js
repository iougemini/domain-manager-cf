// UI 入口：保持 handlers.js 依赖的 generateHTML / generateLoginHTML 签名不变
import { CONFIG, PROJECT } from '../config.js';
import { appState } from '../app-state.js';
import { normalizeDomains, buildStats, escapeHtml } from './data.js';
import { renderPage } from './shell.js';
import { renderLogin } from './login.js';
import { publicSettings } from '../managers/settings-store.js';
import { publicCredential } from '../managers/dnshe-store.js';
import { publicNotifyConfig } from '../managers/notify-store.js';
import { channelMetas } from '../services/notify.js';

export function generateHTML(domains, isAdmin, extras = {}) {
  try {
    const list = normalizeDomains(domains);
    const stats = buildStats(list);
    // 免费域名白名单由「免费域名」页面直接维护，这里读的是已合并三层配置的结果
    const manager = appState.freeDomainManager;
    const keyManager = appState.apiKeyManager;

    return renderPage({
      domains: list,
      stats,
      isAdmin: Boolean(isAdmin),
      // 前台是否开启了访问密码 —— 决定要不要显示"退出登录"
      authEnabled: Boolean(appState.ACCESS_PASSWORD || appState.ACCESS_PASSWORD_HASH),
      version: CONFIG.VERSION,
      project: PROJECT,
      freeDomains: manager ? manager.listAll() : [],

      // 管理页需要的数据：账户 / DNSHE 凭证 / 设置 / 通知
      accounts: keyManager ? keyManager.getAllAccounts() : [],
      accountSource: appState.accountSource || 'none',
      dnsheCredentials: (appState.dnsheAll || []).map(publicCredential),
      dnsheEnv: appState.dnsheEnv || { hasKey: false, hasSecret: false },
      settings: publicSettings(appState.settings, appState.env),
      notify: publicNotifyConfig(appState.notifyConfig),
      notifyState: appState.notifyState || null,
      notifyTypes: channelMetas(),
      sessionHours: appState.SESSION_HOURS,
      // 本次渲染没来得及查询的域名数量（页面顶部据此提示"正在后台补全"）
      pending: Number(extras.pending) || 0
    });
  } catch (error) {
    console.error('HTML生成异常:', error);
    return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>页面生成失败</title></head>' +
      '<body style="font-family:system-ui;padding:40px"><h1>页面生成失败</h1><p>' + escapeHtml(error.message) + '</p></body></html>';
  }
}

export function generateLoginHTML(title, action, errorMessage = '') {
  try {
    return renderLogin(title, action, errorMessage);
  } catch (error) {
    console.error('登录页生成异常:', error);
    return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>登录</title></head>' +
      '<body style="font-family:system-ui;padding:40px"><h1>登录页加载失败</h1><p>' + escapeHtml(error.message) + '</p></body></html>';
  }
}
