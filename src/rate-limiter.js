// 限流模块 - 防止暴力破解与 API 滥用

import { appState } from './app-state.js';

export const RATE_LIMIT_CONFIG = {
  LOGIN_MAX_ATTEMPTS: 5,
  LOGIN_WINDOW_MS: 15 * 60 * 1000,
  API_MAX_REQUESTS: 100,
  API_WINDOW_MS: 60 * 1000,
  LOCKOUT_DURATION_MS: 30 * 60 * 1000
};

export class RateLimiter {
  constructor(kvNamespace) {
    this.kv = kvNamespace;
  }

  async checkLimit(key, maxAttempts, windowMs) {
    if (!this.kv) return { allowed: true, remaining: maxAttempts };

    const kvKey = `ratelimit:${key}`;
    const now = Date.now();

    try {
      const data = await this.kv.get(kvKey, { type: 'json' });

      if (!data) {
        await this.kv.put(kvKey, JSON.stringify({
          count: 1,
          firstAttempt: now,
          lastAttempt: now
        }), { expirationTtl: Math.ceil(windowMs / 1000) });
        return { allowed: true, remaining: maxAttempts - 1 };
      }

      if (now - data.firstAttempt > windowMs) {
        await this.kv.put(kvKey, JSON.stringify({
          count: 1,
          firstAttempt: now,
          lastAttempt: now
        }), { expirationTtl: Math.ceil(windowMs / 1000) });
        return { allowed: true, remaining: maxAttempts - 1 };
      }

      const newCount = data.count + 1;
      await this.kv.put(kvKey, JSON.stringify({
        count: newCount,
        firstAttempt: data.firstAttempt,
        lastAttempt: now
      }), { expirationTtl: Math.ceil(windowMs / 1000) });

      if (newCount > maxAttempts) {
        return {
          allowed: false,
          remaining: 0,
          retryAfter: Math.ceil((data.firstAttempt + windowMs - now) / 1000)
        };
      }

      return { allowed: true, remaining: maxAttempts - newCount };
    } catch (error) {
      console.error('Rate limit check error:', error);
      return { allowed: true, remaining: maxAttempts };
    }
  }

  async checkLoginLimit(ip) {
    return this.checkLimit(
      `login:${ip}`,
      RATE_LIMIT_CONFIG.LOGIN_MAX_ATTEMPTS,
      RATE_LIMIT_CONFIG.LOGIN_WINDOW_MS
    );
  }

  async checkApiLimit(ip) {
    return this.checkLimit(
      `api:${ip}`,
      RATE_LIMIT_CONFIG.API_MAX_REQUESTS,
      RATE_LIMIT_CONFIG.API_WINDOW_MS
    );
  }

  async recordFailedLogin(ip) {
    const kvKey = `lockout:${ip}`;
    const failKey = `loginfail:${ip}`;

    if (!this.kv) return;

    try {
      const failData = await this.kv.get(failKey, { type: 'json' }) || { count: 0 };
      failData.count++;

      if (failData.count >= RATE_LIMIT_CONFIG.LOGIN_MAX_ATTEMPTS) {
        await this.kv.put(kvKey, 'locked', {
          expirationTtl: Math.ceil(RATE_LIMIT_CONFIG.LOCKOUT_DURATION_MS / 1000)
        });
        await this.kv.delete(failKey);
      } else {
        await this.kv.put(failKey, JSON.stringify(failData), {
          expirationTtl: Math.ceil(RATE_LIMIT_CONFIG.LOGIN_WINDOW_MS / 1000)
        });
      }
    } catch (error) {
      console.error('Record failed login error:', error);
    }
  }

  async isLockedOut(ip) {
    if (!this.kv) return false;

    try {
      const locked = await this.kv.get(`lockout:${ip}`);
      return locked === 'locked';
    } catch (error) {
      return false;
    }
  }

  async clearFailedLogins(ip) {
    if (!this.kv) return;

    try {
      await this.kv.delete(`loginfail:${ip}`);
      await this.kv.delete(`lockout:${ip}`);
    } catch (error) {
      console.error('Clear failed logins error:', error);
    }
  }
}

export function getRateLimiter(env) {
  if (!appState.rateLimiter && env && env.DOMAIN_INFO) {
    appState.rateLimiter = new RateLimiter(env.DOMAIN_INFO);
  }
  return appState.rateLimiter;
}