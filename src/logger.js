// 结构化日志与审计日志模块

import { appState } from './app-state.js';

export const LOG_LEVELS = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };

export const logger = {
  level: LOG_LEVELS.INFO, // 默认日志级别

  _format(level, message, data = {}) {
    const timestamp = new Date().toISOString();
    const requestId = appState.requestId || '';
    const ridStr = requestId ? ` [${requestId}]` : '';
    const dataStr = Object.keys(data).length > 0 ? ` ${JSON.stringify(data)}` : '';
    return `[${timestamp}] [${level}]${ridStr} ${message}${dataStr}`;
  },

  debug(msg, data = {}) {
    if (this.level <= LOG_LEVELS.DEBUG) {
      console.log(this._format('DEBUG', msg, data));
    }
  },

  info(msg, data = {}) {
    if (this.level <= LOG_LEVELS.INFO) {
      console.log(this._format('INFO', msg, data));
    }
  },

  warn(msg, data = {}) {
    if (this.level <= LOG_LEVELS.WARN) {
      console.warn(this._format('WARN', msg, data));
    }
  },

  error(msg, data = {}) {
    if (this.level <= LOG_LEVELS.ERROR) {
      console.error(this._format('ERROR', msg, data));
    }
  },

  setLevel(level) {
    if (typeof level === 'string') {
      this.level = LOG_LEVELS[level.toUpperCase()] ?? LOG_LEVELS.INFO;
    } else {
      this.level = level;
    }
  }
};

export const AUDIT_EVENTS = {
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILED: 'LOGIN_FAILED',
  ADMIN_LOGIN_SUCCESS: 'ADMIN_LOGIN_SUCCESS',
  ADMIN_LOGIN_FAILED: 'ADMIN_LOGIN_FAILED',
  LOGOUT: 'LOGOUT',
  ADMIN_LOGOUT: 'ADMIN_LOGOUT',
  API_KEY_ADDED: 'API_KEY_ADDED',
  API_KEY_REMOVED: 'API_KEY_REMOVED',
  SETTINGS_CHANGED: 'SETTINGS_CHANGED',
  DOMAIN_TAG_UPDATED: 'DOMAIN_TAG_UPDATED'
};

export class AuditLogger {
  constructor(kvNamespace) {
    this.kv = kvNamespace;
    this.maxLogs = 1000;
  }

  async log(event, details = {}, request = null) {
    if (!this.kv) return;

    const logEntry = {
      timestamp: new Date().toISOString(),
      event: event,
      details: details,
      ip: request ? (request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown') : 'unknown',
      userAgent: request ? (request.headers.get('User-Agent') || 'unknown') : 'unknown'
    };

    try {
      const logsKey = 'audit:logs';
      const existingLogs = await this.kv.get(logsKey, { type: 'json' }) || [];

      existingLogs.unshift(logEntry);

      if (existingLogs.length > this.maxLogs) {
        existingLogs.length = this.maxLogs;
      }

      await this.kv.put(logsKey, JSON.stringify(existingLogs));
    } catch (error) {
      console.error('Audit log error:', error);
    }
  }

  async getLogs(limit = 100, offset = 0) {
    if (!this.kv) return [];

    try {
      const logs = await this.kv.get('audit:logs', { type: 'json' }) || [];
      return logs.slice(offset, offset + limit);
    } catch (error) {
      console.error('Get audit logs error:', error);
      return [];
    }
  }

  async clearOldLogs(daysToKeep = 30) {
    if (!this.kv) return;

    try {
      const logs = await this.kv.get('audit:logs', { type: 'json' }) || [];
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

      const filteredLogs = logs.filter(log => new Date(log.timestamp) > cutoffDate);
      await this.kv.put('audit:logs', JSON.stringify(filteredLogs));
    } catch (error) {
      console.error('Clear old logs error:', error);
    }
  }
}

export function getAuditLogger(env) {
  if (!appState.auditLogger && env && env.DOMAIN_INFO) {
    appState.auditLogger = new AuditLogger(env.DOMAIN_INFO);
  }
  return appState.auditLogger;
}