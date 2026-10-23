// 自定义域名记录合并规则
//
// 新增域名时会先查一次 WHOIS，结果和 KV 里的记录合并后展示。合并规则出错的
// 后果是静默的：页面 200、字段恒为 Unknown、到期日回退成占位文本——看页面
// 发现不了，只能靠单测盯住。

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  knownValue,
  hasUsableExpiry,
  mergeCustomDomainRecord
} from '../src/services/domain-merge.js';

test('knownValue：各家表达"没有值"的写法统一归为 null', () => {
  for (const v of ['', '  ', 'Unknown', 'unknown', 'N/A', 'Error', 'null', 'undefined', null, undefined]) {
    assert.equal(knownValue(v), null, '应视为无值：' + String(v));
  }
  assert.equal(knownValue('2028-04-03'), '2028-04-03');
  assert.equal(knownValue(' Auto-Renewal '), 'Auto-Renewal');
  assert.equal(knownValue(0), '0', '数字 0 是有效值，不能被当成空');
});

test('实时查询优先于本地记录', () => {
  const merged = mergeCustomDomainRecord(
    { registrar: '旧注册商', expirationDate: '2027-01-01' },
    { registrar: 'DNSHE', expirationDate: '2028-04-03', dataSource: 'dnshe' }
  );
  assert.equal(merged.registrar, 'DNSHE');
  assert.equal(merged.expirationDate, '2028-04-03');
  assert.equal(merged.lookupStatus, 'ok');
  assert.equal(merged.dataSource, 'dnshe');
});

test('实时值是 N/A 时回退到本地记录，不能把 N/A 写进页面', () => {
  const merged = mergeCustomDomainRecord(
    { registrar: '手填注册商', registrationDate: '2024-05-01', expirationDate: '2029-05-01' },
    { registrar: 'N/A', registrationDate: 'N/A', expirationDate: 'N/A', whoisError: 'WHOIS proxy not configured' }
  );
  assert.equal(merged.registrar, '手填注册商');
  assert.equal(merged.registrationDate, '2024-05-01');
  assert.equal(merged.expirationDate, '2029-05-01');
  // 有数据就不该再挂"查询失败"，否则用户以为这条数据不可信
  assert.equal(merged.lookupError, null);
  assert.equal(merged.lookupStatus, 'ok');
});

test('两边都没有到期信息：标记 missing 并保留查询错误', () => {
  const merged = mergeCustomDomainRecord(
    { registrar: 'Unknown', expirationDate: 'Unknown' },
    { registrar: 'N/A', expirationDate: 'N/A', whoisError: 'WHOIS proxy not configured' }
  );
  assert.equal(merged.expirationDate, 'Unknown');
  assert.equal(merged.lookupStatus, 'missing');
  assert.equal(merged.lookupError, 'WHOIS proxy not configured');
  assert.equal(hasUsableExpiry(merged), false);
});

test('没有实时结果也能用本地记录（页面渲染时缓存未命中）', () => {
  const merged = mergeCustomDomainRecord({ registrar: 'DNSHE', expirationDate: '2028-04-03', dataSource: 'dnshe' }, null);
  assert.equal(merged.expirationDate, '2028-04-03');
  assert.equal(merged.dataSource, 'dnshe');
  assert.equal(merged.lookupStatus, 'ok');
});

test('用户手工改过的记录：以本地为准，来源标 manual', () => {
  const merged = mergeCustomDomainRecord(
    { registrar: '手工', expirationDate: '2030-01-01', autoUpdateWhois: false },
    { registrar: 'DNSHE', expirationDate: '2028-04-03', dataSource: 'dnshe' }
  );
  assert.equal(merged.registrar, 'DNSHE', '缺的字段仍可由实时结果补上');
  assert.equal(merged.dataSource, 'manual');
  assert.equal(merged.lookupStatus, 'manual');
});

test('手工记录没填日期时仍是 missing（提醒用户补）', () => {
  const merged = mergeCustomDomainRecord({ expirationDate: 'Unknown', autoUpdateWhois: false }, null);
  assert.equal(merged.lookupStatus, 'missing');
});

test('2999 哨兵日期识别为永久域名', () => {
  const merged = mergeCustomDomainRecord({}, { expirationDate: '2999-12-31', dataSource: 'dnshe' });
  assert.equal(merged.isPermanent, true);
  assert.equal(merged.lookupStatus, 'ok');
});

test('注册表标记的永久域名即使没有日期也算完整', () => {
  const merged = mergeCustomDomainRecord({ isPermanent: true, expirationDate: 'Unknown' }, null);
  assert.equal(merged.isPermanent, true);
  assert.equal(merged.lookupStatus, 'ok');
});

test('nameServers：实时结果为空时回退本地', () => {
  const merged = mergeCustomDomainRecord(
    { nameServers: ['ns1.local', 'ns2.local'] },
    { nameServers: [], expirationDate: '2028-04-03' }
  );
  assert.deepEqual(merged.nameServers, ['ns1.local', 'ns2.local']);

  const merged2 = mergeCustomDomainRecord(
    { nameServers: ['ns1.local'] },
    { nameServers: ['ns1.dnshe.com'], expirationDate: '2028-04-03' }
  );
  assert.deepEqual(merged2.nameServers, ['ns1.dnshe.com']);
});

test('pending 透传：后台还在补的时候别显示成"查不到"', () => {
  const merged = mergeCustomDomainRecord({ expirationDate: 'Unknown' }, { expirationDate: 'Unknown', pending: true });
  assert.equal(merged.pending, true);
});
