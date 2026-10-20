import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { RateLimiter, RATE_LIMIT_CONFIG } from '../src/rate-limiter.js';

function makeMockKV() {
  const store = new Map();
  return {
    async get(key, opts) {
      if (!store.has(key)) return null;
      const value = store.get(key);
      if (opts && opts.type === 'json') {
        try { return JSON.parse(value); } catch { return value; }
      }
      return value;
    },
    async put(key, value, opts) {
      store.set(key, value);
    },
    async delete(key) {
      store.delete(key);
    },
    async list() {
      return { keys: [] };
    }
  };
}

describe('RateLimiter', () => {
  it('无 kv 时直接放行', async () => {
    const rl = new RateLimiter(null);
    const r = await rl.checkLoginLimit('1.1.1.1');
    assert.equal(r.allowed, true);
  });

  it('超过登录上限后拒绝', async () => {
    const rl = new RateLimiter(makeMockKV());
    let last;
    for (let i = 0; i <= RATE_LIMIT_CONFIG.LOGIN_MAX_ATTEMPTS; i++) {
      last = await rl.checkLoginLimit('1.1.1.1');
    }
    assert.equal(last.allowed, false);
    assert.equal(last.remaining, 0);
  });

  it('失败登录达到上限后锁定账户', async () => {
    const rl = new RateLimiter(makeMockKV());
    for (let i = 0; i < RATE_LIMIT_CONFIG.LOGIN_MAX_ATTEMPTS; i++) {
      await rl.recordFailedLogin('2.2.2.2');
    }
    assert.equal(await rl.isLockedOut('2.2.2.2'), true);
  });

  it('clearFailedLogins 清除锁定', async () => {
    const rl = new RateLimiter(makeMockKV());
    for (let i = 0; i < RATE_LIMIT_CONFIG.LOGIN_MAX_ATTEMPTS; i++) {
      await rl.recordFailedLogin('3.3.3.3');
    }
    assert.equal(await rl.isLockedOut('3.3.3.3'), true);
    await rl.clearFailedLogins('3.3.3.3');
    assert.equal(await rl.isLockedOut('3.3.3.3'), false);
  });
});