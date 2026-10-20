import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { validateDomain, validateApiKey, validateAction } from '../src/validators.js';

describe('validateDomain', () => {
  it('接受合法域名并归一化', () => {
    assert.equal(validateDomain('example.com'), 'example.com');
    assert.equal(validateDomain('Sub.Example.com'), 'sub.example.com');
    assert.equal(validateDomain('sub.example.com'), 'sub.example.com');
  });

  it('拒绝空域名', () => {
    assert.throws(() => validateDomain(''), /不能为空/);
    assert.throws(() => validateDomain(null), /不能为空/);
  });

  it('拒绝超长域名', () => {
    assert.doesNotThrow(() => validateDomain('a.com'));
    assert.throws(() => validateDomain('a'.repeat(254)), /253/);
  });

  it('拒绝 XSS/非法字符', () => {
    assert.throws(() => validateDomain('<script>.com'), /非法字符|格式无效/);
    assert.throws(() => validateDomain('exam ple.com'), /非法字符|格式无效/);
  });

  it('拒绝路径遍历', () => {
    assert.throws(() => validateDomain('../etc/passwd'));
    assert.throws(() => validateDomain('a..b.com'));
  });

  it('拒绝缺少点的域名', () => {
    assert.throws(() => validateDomain('example'), /点/);
  });
});

describe('validateApiKey', () => {
  it('接受 20-200 字符的密钥', () => {
    const key = 'a'.repeat(50);
    assert.equal(validateApiKey(key), key);
  });

  it('拒绝过短密钥', () => {
    assert.throws(() => validateApiKey('short-key'), /长度无效/);
  });

  it('拒绝非法字符', () => {
    assert.throws(() => validateApiKey('k'.repeat(30) + '<'), /非法字符/);
    assert.throws(() => validateApiKey("k".repeat(30) + "'"), /非法字符/);
  });
});

describe('validateAction', () => {
  it('接受白名单 action 并归一化', () => {
    assert.equal(validateAction('ADD', ['add', 'remove']), 'add');
    assert.equal(validateAction(' Remove ', ['add', 'remove']), 'remove');
  });

  it('拒绝非白名单 action', () => {
    assert.throws(() => validateAction('delete', ['add', 'remove']), /无效的操作类型/);
  });

  it('拒绝空 action', () => {
    assert.throws(() => validateAction('', ['add']), /不能为空/);
    assert.throws(() => validateAction(null, ['add']), /不能为空/);
  });
});