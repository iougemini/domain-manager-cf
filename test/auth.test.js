import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { appState } from '../src/app-state.js';
import { secureCompare, createAuthToken, verifyAuthToken, createCookieHeader } from '../src/auth.js';

describe('secureCompare', () => {
  it('相同字符串返回 true', () => {
    assert.equal(secureCompare('abc', 'abc'), true);
  });

  it('不同字符串返回 false', () => {
    assert.equal(secureCompare('abc', 'abd'), false);
  });

  it('长度不同返回 false', () => {
    assert.equal(secureCompare('abc', 'abcd'), false);
  });

  it('空值返回 false', () => {
    assert.equal(secureCompare(null, 'abc'), false);
    assert.equal(secureCompare('', ''), false);
  });
});

describe('createAuthToken / verifyAuthToken', () => {
  before(() => {
    appState.TOKEN_SECRET = 'test-token-secret';
    appState.ADMIN_PASSWORD = 'admin-pass';
    appState.ACCESS_PASSWORD = 'access-pass';
  });

  it('签发并校验 access token', async () => {
    const token = await createAuthToken('access', 3600);
    assert.equal(typeof token, 'string');
    const payload = await verifyAuthToken(token, 'access');
    assert.notEqual(payload, null);
    assert.equal(payload.type, 'access');
    assert.ok(payload.exp > payload.iat);
  });

  it('类型不匹配返回 null', async () => {
    const token = await createAuthToken('access', 3600);
    assert.equal(await verifyAuthToken(token, 'admin'), null);
  });

  it('篡改签名返回 null', async () => {
    const token = await createAuthToken('admin', 3600);
    const [payloadB64] = token.split('.');
    assert.equal(await verifyAuthToken(`${payloadB64}.deadbeef`, 'admin'), null);
  });

  it('非法 token 返回 null', async () => {
    assert.equal(await verifyAuthToken('not-a-token', 'admin'), null);
    assert.equal(await verifyAuthToken(null, 'admin'), null);
  });
});

describe('createCookieHeader', () => {
  it('包含 HttpOnly 和 SameSite=Strict', () => {
    const h = createCookieHeader('access_token', 'abc');
    assert.ok(h.includes('access_token=abc'));
    assert.ok(h.includes('HttpOnly'));
    assert.ok(h.includes('SameSite=Strict'));
  });

  it('secure=true 时包含 Secure', () => {
    assert.ok(createCookieHeader('a', 'b', 3600, true).includes('Secure'));
    assert.ok(!createCookieHeader('a', 'b', 3600, false).includes('Secure'));
  });
});