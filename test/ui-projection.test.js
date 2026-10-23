// 客户端数据投影的完整性
//
// 页面把域名数据序列化进 <script id="dsmc-data">，客户端只认这份投影。
// 投影少一个字段不会报错：页面 200、没有 JS 异常，只是那个字段恒为 undefined，
// 表现成"徽标不对""按钮不对"这类看起来像逻辑错误的怪现象。
//
// 本轮就踩了一次：status 里漏了 group，抽屉判断不出「已暂停」，
// 于是给一个已被注册局暂停的域名继续主推「标记已续费」。

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateHTML } from '../src/ui/index.js';
import { appState } from '../src/app-state.js';
import { FreeDomainManager } from '../src/managers/free-domain.js';

// generateHTML 会从 appState 读白名单，给它一个真实的实例即可
appState.freeDomainManager = new FreeDomainManager();
appState.SESSION_HOURS = 24;

function sampleDomains() {
  return [
    {
      name: 'held.com',
      username: 'acct',
      registrar: 'Namecheap',
      registrationDate: '2025-01-01',
      expirationDate: '2027-01-01',
      isFree: false,
      plan: 'Free Website',
      nameServers: ['ns1.example.com'],
      health: {
        checkedAt: '2026-10-23T04:00:00.000Z',
        summary: {
          level: 'danger',
          dns: 'ok',
          dnsLabel: '解析正常',
          registry: { level: 'danger', suspended: true, labels: ['注册商暂停解析'], codes: ['clienthold'] },
          problems: [{ kind: 'registry', label: '注册商暂停解析', level: 'danger' }]
        }
      }
    },
    {
      name: 'plain.com',
      username: 'acct',
      registrar: 'GoDaddy',
      registrationDate: '2025-01-01',
      expirationDate: '2027-06-01',
      isFree: false,
      plan: 'Free Website',
      nameServers: []
    }
  ];
}

function extractData(html) {
  const match = html.match(/<script type="application\/json" id="dsmc-data">([\s\S]*?)<\/script>/);
  assert.ok(match, '页面里找不到 dsmc-data');
  return JSON.parse(match[1]);
}

test('status 投影带上 group —— 抽屉靠它区分已暂停', () => {
  const data = extractData(generateHTML(sampleDomains(), true));
  const held = data.domains.find(d => d.name === 'held.com');

  assert.ok(held.status.group, 'status 缺 group');
  assert.equal(held.status.group, 'suspended');
  assert.equal(held.status.key, 'suspended');
});

test('health 投影带齐抽屉要用的字段', () => {
  const data = extractData(generateHTML(sampleDomains(), true));
  const held = data.domains.find(d => d.name === 'held.com');

  assert.ok(held.health, 'health 没进投影');
  assert.equal(held.health.dns, 'ok');
  assert.equal(held.health.dnsLabel, '解析正常');
  assert.equal(held.health.registry.suspended, true);
  assert.deepEqual(held.health.registry.labels, ['注册商暂停解析']);
  assert.ok(held.health.checkedAt, 'checkedAt 丢了，详情页会显示「—」');
});

test('没有巡检记录的域名 health 为 null，不是 undefined', () => {
  const data = extractData(generateHTML(sampleDomains(), true));
  const plain = data.domains.find(d => d.name === 'plain.com');

  assert.equal(plain.health, null);
  assert.equal(plain.status.group, 'ok');
});

test('页面里不出现明文 Token 字段', () => {
  const html = generateHTML(sampleDomains(), true);
  assert.ok(!/"token"\s*:/.test(html), '页面数据里出现了 token 字段');
});

test('已暂停的域名在服务端渲染里带上 data-alert 标记', () => {
  const html = generateHTML(sampleDomains(), true);
  assert.match(html, /data-alert="1"/);
});
