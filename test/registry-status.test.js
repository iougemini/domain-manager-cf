// 注册局状态解析
//
// 这个模块的价值全在"分得清哪些状态要告警"上。测的重点不是解析字符串，
// 而是那条容易踩的线：几乎所有正常域名都带 clientTransferProhibited，
// 一旦把它算成异常，整张表就会全红，告警随即失效。

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseRegistryStatus,
  normalizeStatusCode,
  isActionable
} from '../src/services/registry-status.js';

test('normalizeStatusCode 认得空格、连字符、下划线与大小写四种写法', () => {
  const expected = 'clienttransferprohibited';
  for (const input of [
    'clientTransferProhibited',
    'client transfer prohibited',
    'CLIENT TRANSFER PROHIBITED',
    'client_transfer_prohibited',
    'client-transfer-prohibited'
  ]) {
    assert.equal(normalizeStatusCode(input), expected, input);
  }
});

test('clientHold 判定为危险并标记 suspended', () => {
  const s = parseRegistryStatus(['client hold']);
  assert.equal(s.level, 'danger');
  assert.equal(s.suspended, true);
  assert.deepEqual(s.dangerCodes, ['clienthold']);
  assert.deepEqual(s.labels, ['注册商暂停解析']);
});

test('serverHold 同样标记 suspended', () => {
  const s = parseRegistryStatus('serverHold');
  assert.equal(s.suspended, true);
  assert.equal(s.level, 'danger');
});

test('clientTransferProhibited 不算危险 —— 正常域名都带它', () => {
  const s = parseRegistryStatus(['client transfer prohibited']);
  assert.equal(s.level, 'ok');
  assert.equal(s.suspended, false);
  assert.deepEqual(s.dangerCodes, []);
  assert.equal(isActionable(s), false);
});

test('常见的防盗组合不会被误报', () => {
  const s = parseRegistryStatus([
    'client transfer prohibited',
    'client delete prohibited',
    'client update prohibited'
  ]);
  assert.equal(s.level, 'ok');
  assert.equal(s.dangerCodes.length, 0);
});

test('危险状态与保护状态混合时，取最高级别', () => {
  const s = parseRegistryStatus('client transfer prohibited, client hold');
  assert.equal(s.level, 'danger');
  assert.equal(s.suspended, true);
  assert.ok(s.labels.includes('禁止转移'));
  assert.ok(s.labels.includes('注册商暂停解析'));
});

test('pendingDelete 与 redemptionPeriod 是危险但不算 suspended', () => {
  for (const code of ['pending delete', 'redemption period']) {
    const s = parseRegistryStatus(code);
    assert.equal(s.level, 'danger', code);
    assert.equal(s.suspended, false, code + ' 不涉及暂停解析');
    assert.equal(isActionable(s), true);
  }
});

test('pendingTransfer 只是 info，不进待处理清单', () => {
  const s = parseRegistryStatus(['pending transfer']);
  assert.equal(s.level, 'info');
  assert.equal(isActionable(s), false);
});

test('warn 级别进待处理清单', () => {
  const s = parseRegistryStatus(['pending restore']);
  assert.equal(s.level, 'warn');
  assert.equal(isActionable(s), true);
});

test('分号分隔也能拆开', () => {
  const s = parseRegistryStatus('client hold; client transfer prohibited');
  assert.equal(s.level, 'danger');
  assert.equal(s.codes.length, 2);
});

test('重复的状态码去重', () => {
  const s = parseRegistryStatus(['client hold', 'clientHold', 'CLIENT HOLD']);
  assert.equal(s.codes.length, 1);
});

test('未知状态码保留原文，且不影响级别判定', () => {
  const s = parseRegistryStatus(['some future code']);
  assert.equal(s.level, 'ok');
  assert.deepEqual(s.unknown, ['some future code']);
});

test('空值一律当作正常', () => {
  for (const input of [null, undefined, '', [], '   ', 0]) {
    const s = parseRegistryStatus(input);
    assert.equal(s.level, 'ok', String(input));
    assert.equal(s.codes.length, 0);
    assert.equal(s.suspended, false);
  }
});

test('对象类型不会被误当数组处理', () => {
  const s = parseRegistryStatus({ status: 'client hold' });
  assert.equal(s.level, 'ok');
  assert.equal(s.codes.length, 0);
});

test('isActionable 对空值安全', () => {
  assert.equal(isActionable(null), false);
  assert.equal(isActionable(undefined), false);
});
