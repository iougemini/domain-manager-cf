// 巡检结论如何影响主状态徽标
//
// 这里最容易出的错是"过度告警"：把 clientTransferProhibited 这类防盗状态
// 也做成红色徽标，整张表全红，用户就不看了。
// 另一半是"排序错位"：域名已被暂停，却因为还有 200 天到期而排在列表中间。

import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeDomains, statusOf, buildStats, groupByAccount } from '../src/ui/data.js';

function futureDate(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString().slice(0, 10);
}

function healthWith(registry, dns = 'ok') {
  return {
    checkedAt: new Date().toISOString(),
    summary: {
      level: registry && registry.level === 'danger' ? 'danger' : 'ok',
      dns,
      dnsLabel: dns === 'nxdomain' ? '解析丢失' : '解析正常',
      registry,
      problems: []
    }
  };
}

test('没有巡检记录时状态不受影响', () => {
  const [d] = normalizeDomains([{ name: 'a.com', expirationDate: futureDate(200) }]);
  assert.equal(d.status.key, 'ok');
  assert.equal(d.registryAlert, null);
  assert.equal(d.health, null);
});

test('clientHold 让主徽标变成已暂停', () => {
  const [d] = normalizeDomains([{
    name: 'a.com',
    expirationDate: futureDate(200),
    health: healthWith({ level: 'danger', suspended: true, labels: ['注册商暂停解析'], codes: ['clienthold'] })
  }]);

  assert.equal(d.status.key, 'suspended');
  assert.equal(d.status.label, '已暂停');
  assert.equal(d.status.group, 'suspended');
  assert.equal(d.status.tone, 'danger');
});

test('已暂停的域名仍然保留剩余天数', () => {
  const [d] = normalizeDomains([{
    name: 'a.com',
    expirationDate: futureDate(100),
    health: healthWith({ level: 'danger', suspended: true, labels: ['注册商暂停解析'], codes: ['clienthold'] })
  }]);

  assert.equal(d.status.days, 100, '暂停不等于到期，剩余天数要能看到');
});

test('pendingDelete 归入 suspended 分组但标签不同', () => {
  const [d] = normalizeDomains([{
    name: 'a.com',
    expirationDate: futureDate(0),
    health: healthWith({ level: 'danger', suspended: false, labels: ['即将删除'], codes: ['pendingdelete'] })
  }]);

  assert.equal(d.status.key, 'redemption');
  assert.equal(d.status.label, '即将删除');
  assert.equal(d.status.group, 'suspended');
});

test('只有防盗保护状态时不改主徽标', () => {
  const [d] = normalizeDomains([{
    name: 'a.com',
    expirationDate: futureDate(200),
    health: healthWith({ level: 'ok', suspended: false, labels: ['禁止转移'], codes: ['clienttransferprohibited'] })
  }]);

  assert.equal(d.status.key, 'ok');
  assert.equal(d.registryAlert, null);
  assert.ok(d.health, '巡检结论仍然保留，详情页要显示');
});

test('warn 级别的注册局状态不改主徽标', () => {
  const [d] = normalizeDomains([{
    name: 'a.com',
    expirationDate: futureDate(200),
    health: {
      summary: {
        level: 'warn', dns: 'ok', dnsLabel: '解析正常',
        registry: { level: 'warn', suspended: false, labels: ['恢复处理中'], codes: ['pendingrestore'] },
        problems: []
      }
    }
  }]);

  assert.equal(d.status.key, 'ok');
  assert.equal(d.registryAlert, null);
});

test('已暂停的域名排在列表最前，即使到期日很远', () => {
  const list = normalizeDomains([
    { name: 'soon.com', expirationDate: futureDate(2) },
    { name: 'held.com', expirationDate: futureDate(300), health: healthWith({ level: 'danger', suspended: true, labels: ['注册商暂停解析'], codes: ['clienthold'] }) },
    { name: 'later.com', expirationDate: futureDate(200) }
  ]);

  assert.equal(list[0].name, 'held.com');
  assert.equal(list[1].name, 'soon.com');
});

test('暂停计入 critical，首页告警数字要算上它', () => {
  const list = normalizeDomains([
    { name: 'held.com', expirationDate: futureDate(300), health: healthWith({ level: 'danger', suspended: true, labels: ['注册商暂停解析'], codes: ['clienthold'] }) }
  ]);
  const stats = buildStats(list);

  assert.equal(stats.suspended, 1);
  assert.equal(stats.critical, 1);
  assert.equal(stats.ok, 0);
});

test('按账户统计也带上暂停数', () => {
  const list = normalizeDomains([
    { name: 'a.com', username: 'acct', expirationDate: futureDate(300), health: healthWith({ level: 'danger', suspended: true, labels: ['注册商暂停解析'], codes: ['clienthold'] }) }
  ]);
  const groups = groupByAccount(list);
  assert.equal(groups[0].suspended, 1);
});

test('statusOf 直接接收 registryAlert 也能工作', () => {
  const s = statusOf({
    expirationDate: futureDate(50),
    registryAlert: { suspended: true, labels: ['注册商暂停解析'], level: 'danger' }
  });
  assert.equal(s.key, 'suspended');
  assert.equal(s.days, 50);
});

test('没有到期日时暂停状态的 days 为 null，不会算出负数', () => {
  const s = statusOf({
    expirationDate: 'Unknown',
    registryAlert: { suspended: true, labels: ['注册商暂停解析'], level: 'danger' }
  });
  assert.equal(s.days, null);
});

test('解析丢失（NXDOMAIN）升为主徽标 —— 这是事故，不是"没配解析"', () => {
  const [d] = normalizeDomains([{
    name: 'lost.com',
    expirationDate: futureDate(159),
    health: {
      checkedAt: new Date().toISOString(),
      summary: {
        level: 'danger', dns: 'nxdomain', dnsLabel: '解析丢失',
        registry: { level: 'ok', suspended: false, labels: ['禁止转移'], codes: ['clienttransferprohibited'] },
        problems: [{ kind: 'dns', label: '解析丢失' }]
      }
    }
  }]);

  assert.equal(d.status.key, 'dns-lost');
  assert.equal(d.status.label, '解析丢失');
  assert.equal(d.status.group, 'suspended');
  assert.equal(d.dnsLost, true);
});

test('nodata 不升主徽标 —— 囤着没配解析的域名属于常态', () => {
  const [d] = normalizeDomains([{
    name: 'idle.com',
    expirationDate: futureDate(275),
    health: {
      summary: {
        level: 'ok', dns: 'nodata', dnsLabel: '未配置解析',
        registry: { level: 'ok', suspended: false, labels: [], codes: [] },
        problems: []
      }
    }
  }]);

  assert.equal(d.status.key, 'ok');
  assert.equal(d.dnsLost, false);
});

test('探测失败（error）不升主徽标 —— 探测器坏了不代表域名坏了', () => {
  const [d] = normalizeDomains([{
    name: 'x.com',
    expirationDate: futureDate(100),
    health: {
      summary: {
        level: 'unknown', dns: 'error', dnsLabel: '探测失败',
        registry: null, problems: []
      }
    }
  }]);

  assert.equal(d.status.key, 'ok');
});

test('注册局暂停优先于解析丢失 —— 前者是根因', () => {
  const [d] = normalizeDomains([{
    name: 'both.com',
    expirationDate: futureDate(50),
    health: {
      summary: {
        level: 'danger', dns: 'nxdomain', dnsLabel: '解析丢失',
        registry: { level: 'danger', suspended: true, labels: ['注册商暂停解析'], codes: ['clienthold'] },
        problems: []
      }
    }
  }]);

  assert.equal(d.status.key, 'suspended');
});
