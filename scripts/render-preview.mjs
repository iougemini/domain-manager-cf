// 无凭据预览：用假数据走同一套服务端渲染，产出可直接打开的 HTML
// 用法：node scripts/render-preview.mjs  →  design/preview/*.html
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { generateHTML, generateLoginHTML } from '../src/ui/index.js';
import { appState } from '../src/app-state.js';
import { FreeDomainManager } from '../src/managers/free-domain.js';
import { publicNotifyConfig } from '../src/managers/notify-store.js';

// 用真实注册表补齐免费域名语义，避免预览与线上判定出现第二份真相
const freeDomains = new FreeDomainManager();
// generateHTML 会从 appState 读白名单来渲染「免费域名」页面
appState.freeDomainManager = freeDomains;

/* ---------- 管理页预览数据（账户 / DNSHE / 设置 / 通知） ---------- */
// 这些页面读的是 appState，预览时用假数据顶上，保证渲染路径与线上一致
appState.SESSION_HOURS = 24;
// 前台开了访问密码，预览里才会渲染"退出登录"
appState.ACCESS_PASSWORD = 'demo-access-password';
appState.ADMIN_PASSWORD = 'demo-admin-password';
appState.dnsheEnv = { hasKey: false, hasSecret: false };

appState.accountSource = 'kv';
appState.apiKeyManager = {
  getAllAccounts: () => ([
    { id: 'acct_1', label: '主账户', username: 'gemini', tokenMasked: 'abcd12••••••••wxyz', active: true, errorCount: 0, lastUsed: Date.now() - 120000, note: '主站与客户站点' },
    { id: 'acct_2', label: '实验室', username: 'labs', tokenMasked: 'efgh34••••••••uvwx', active: true, errorCount: 0, lastUsed: Date.now() - 900000, note: '' },
    { id: 'acct_3', label: '归档', username: 'archive', tokenMasked: 'ijkl56••••••••stuv', active: false, errorCount: 3, lastUsed: Date.now() - 86400000, note: 'Token 已过期，等待轮换' }
  ])
};

appState.dnsheAll = [
  { id: 'dnshe_1', label: 'DNSHE 主账户', key: 'cfsd_9f2a7c41b8e3', secret: 'sk_7d1e5a9c2b4f', enabled: true, createdAt: '2026-09-01T10:00:00Z', updatedAt: '2026-10-12T08:20:00Z' },
  { id: 'dnshe_2', label: '备用账户', key: 'cfsd_3b8d6e0a1c9f', secret: 'sk_2a4c8e0f6b1d', enabled: false, createdAt: '2026-09-20T14:00:00Z', updatedAt: '2026-10-02T11:00:00Z' }
];

appState.settings = {
  accessPassword: { hash: 'demo', salt: 'demo' },
  adminPassword: { hash: 'demo', salt: 'demo' },
  tokenSecret: '',
  sessionHours: 24,
  whoisProxy: 'https://whois.example.com',
  freeDomainLiveLookup: true,
  freeDomainLookupTimeout: 8000,
  freeDomainLookupUa: '',
  paceDnshe: 2000,
  paceWhois: 1200,
  paceRdap: 300
};

// 走一遍 publicNotifyConfig：预览里看到的掩码效果与线上完全一致，
// 否则预览会把明文凭证画出来，掩盖掉掩码失效这类问题。
appState.notifyConfig = publicNotifyConfig({
  enabled: true,
  rules: { daysBefore: 30, includeExpired: true, timezoneOffset: 8 },
  channels: [
    { id: 'ch_1', type: 'feishu', label: '运维群', enabled: true, config: { webhook: 'https://open.feishu.cn/open-apis/bot/v2/hook/9f2a7c41b8e3', secret: 'demo-secret' }, createdAt: '2026-09-10T09:00:00Z' },
    { id: 'ch_2', type: 'telegram', label: '个人 TG', enabled: true, config: { token: '123456:ABC-DEF', chatId: '100200300' }, createdAt: '2026-09-12T09:00:00Z' },
    { id: 'ch_3', type: 'bark', label: 'iPhone', enabled: false, config: { key: 'barkkey123' }, createdAt: '2026-09-15T09:00:00Z' },
    { id: 'ch_4', type: 'webhook', label: '自建中转', enabled: true, config: { url: 'https://hook.example.com/dsmc?sign=7d1e5a9c' }, createdAt: '2026-09-18T09:00:00Z' }
  ]
});

appState.notifyState = {
  lastRunAt: new Date(Date.now() - 3600000).toISOString(),
  lastFingerprint: 'demo',
  lastResult: [
    { id: 'ch_1', type: 'feishu', label: '运维群', ok: true, error: null },
    { id: 'ch_2', type: 'telegram', label: '个人 TG', ok: false, error: 'HTTP 400：chat not found' }
  ],
  sentOn: new Date().toISOString().slice(0, 10)
};

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, '..', '..', 'design', 'preview');
mkdirSync(outDir, { recursive: true });

const DAY = 86400000;
const today = new Date();
today.setHours(0, 0, 0, 0);
const add = n => new Date(today.getTime() + n * DAY);
const iso = d => d.toISOString().slice(0, 10);

const NAMES = ['lumen', 'atlas', 'orbit', 'nimbus', 'vertex', 'harbor', 'pixel', 'signal', 'cobalt', 'ember', 'quartz', 'drift', 'haven', 'mint', 'onyx', 'prism', 'river', 'solace', 'terra', 'vista', 'willow', 'zenith', 'arc', 'brisk', 'cedar', 'delta', 'echo', 'flux', 'glide', 'halo', 'iris', 'jade', 'kite', 'lotus', 'mesa', 'nova', 'opal', 'pine', 'quill', 'raven', 'slate', 'tide', 'umber', 'vale', 'wren', 'yarn', 'zephyr', 'cove', 'dune', 'fern', 'grove', 'hollow', 'isle', 'juniper', 'knoll', 'loom', 'moss', 'north', 'oak', 'pebble', 'quarry', 'ridge', 'stone'];
const TLDS = ['com', 'dev', 'io', 'app', 'net', 'xyz', 'cc', 'me', 'co', 'site', 'tech', 'online'];
const REG = ['Cloudflare, Inc.', 'GoDaddy.com, LLC', 'Namecheap, Inc.', 'Alibaba Cloud', 'Dynadot LLC', 'Porkbun LLC'];
const FREE_SUFFIX = ['.pp.ua', '.us.kg', '.dpdns.org', '.us.ci', '.qd.je', '.de5.net', '.ccwu.cc'];
const NS = ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'];

let n = 0;
const nm = () => NAMES[n++ % NAMES.length];
const pick = i => REG[i % REG.length];
const domains = [];

const paid = [3, 5, 12, 18, 27, 29, 60, 120, 240, 365, 420, 600, 800, 900];
const accts = ['gemini', 'gemini', 'gemini', 'gemini', 'gemini', 'labs', 'labs', 'labs', 'studio', 'studio', 'archive', 'archive', 'gemini', 'labs'];
paid.forEach((off, i) => domains.push({
  name: nm() + '.' + TLDS[i % TLDS.length], username: accts[i],
  registrar: pick(i), registrationDate: iso(add(-600 - i * 40)), expirationDate: iso(add(off)),
  whoisError: null, isFree: false, plan: i % 4 === 0 ? 'Pro Website' : 'Free Website',
  dataSource: 'whois-proxy',
  notes: i === 0 ? '客户主站，续费前确认预算' : '', nameServers: NS
}));

for (let i = 0; i < 12; i++) domains.push({
  name: nm() + '.eu.org', username: i % 3 ? 'gemini' : 'labs', registrar: 'NIC.EU.ORG',
  registrationDate: 'N/A', expirationDate: 'Unknown', whoisError: null,
  isFree: true, plan: 'Free Website', dataSource: 'registry', notes: '', nameServers: NS
});

for (let i = 0; i < 29; i++) domains.push({
  name: nm() + FREE_SUFFIX[i % FREE_SUFFIX.length], username: i % 4 ? 'gemini' : 'archive',
  registrar: 'DIGITALPLAT.ORG', registrationDate: iso(add(-500)), expirationDate: 'Auto-Renewal',
  whoisError: null, isFree: true, plan: 'Free Website', dataSource: 'registry', notes: '', nameServers: NS
});

// pp.ua：走 TCP WHOIS 拿到真实到期日，用来演示数据来源徽标
[['yuedu.pp.ua', 210], ['notes.pp.ua', 46]].forEach(([name, off]) => domains.push({
  name, username: 'labs', registrar: 'NIC.UA LLC', registrationDate: iso(add(-420)),
  expirationDate: iso(add(off)), whoisError: null, isFree: true, plan: 'Free Website',
  dataSource: 'whois', notes: '', nameServers: NS
}));

// 自动发现候选：WHOIS 查不到注册商的三级域名
['demo.pages.dev', 'app.example.dev'].forEach(name => domains.push({
  name, username: 'studio', registrar: 'Unknown', registrationDate: 'Unknown',
  expirationDate: 'Unknown', whoisError: null, isFree: false, plan: 'Free Website',
  dataSource: null, notes: '', nameServers: NS
}));

[2, 8, 16, 21, 25, 28, 30].forEach(off => domains.push({
  name: nm() + FREE_SUFFIX[off % FREE_SUFFIX.length], username: 'studio', registrar: '免费域名计划',
  registrationDate: iso(add(-400)), expirationDate: iso(add(off)), whoisError: null,
  isFree: true, plan: 'Free Website', notes: '免费额度，需手动续期', nameServers: NS
}));

[
  ['atelier-nord.fr', 'Gandi SAS', -36, '已过期 36 天，客户未确认是否续费'],
  ['studio-koi.jp', 'Namecheap, Inc.', 180, ''],
  ['monogram.co', 'Alibaba Cloud', 300, '备案信息待更新'],
  ['fernwood.studio', 'Porkbun LLC', 420, ''],
  ['kiteandco.com', 'GoDaddy.com, LLC', 45, '品牌主站'],
  ['northwind.shop', 'Dynadot LLC', 90, '']
].forEach(([name, registrar, off, notes]) => domains.push({
  name, username: '自定义域名', registrar, registrationDate: iso(add(-700)),
  expirationDate: iso(add(off)), whoisError: null, isFree: false, isCustomDomain: true,
  dataSource: 'manual',
  serviceProvider: '外部 DNS', notes, nameServers: ['ns1.digitalocean.com', 'ns2.digitalocean.com']
}));

// 新增后没查到 WHOIS 的域名：列表里应显示「待补充」，抽屉主操作是「补充信息」
domains.push({
  name: 'otime.cn.mt', username: '自定义域名', registrar: 'Unknown',
  registrationDate: 'Unknown', expirationDate: 'Unknown', whoisError: null,
  isFree: true, isCustomDomain: true, dataSource: null, serviceProvider: '外部 DNS',
  lookupStatus: 'missing', lookupError: 'WHOIS 代理未配置，且该后缀没有可用的实时查询',
  notes: 'DNSHE 域名，不能挂到 Cloudflare', nameServers: ['tim.ns.cloudflare.com', 'sneh.ns.cloudflare.com']
});

// DNSHE 升级为永久域名：接口返回 2999-12-31 这类哨兵日期，应显示为「永久」
domains.push({
  name: 'forever.us.ci', username: 'labs', registrar: 'DNSHE',
  registrationDate: iso(add(-300)), expirationDate: '2999-12-31',
  whoisError: null, isFree: true, plan: 'Free Website', dataSource: 'dnshe',
  notes: '已在 DNSHE 控制台升级为永久域名', nameServers: NS
});

// 巡检样例：注册局暂停（站点已挂，但到期日还有 240 天）与解析丢失。
// 这两个状态是 v2.7 的重点，预览里必须有，否则界面改坏了也看不出来
domains.push({
  name: 'held-demo.com', username: 'studio', registrar: 'Namecheap, Inc.',
  registrationDate: iso(add(-500)), expirationDate: iso(add(240)),
  whoisError: null, isFree: false, plan: 'Free Website', dataSource: 'rdap',
  notes: '注册邮箱未验证，域名被注册商暂停', nameServers: NS,
  health: {
    checkedAt: new Date(Date.now() - 3600 * 1000).toISOString(),
    summary: {
      level: 'danger', dns: 'ok', dnsLabel: '解析正常',
      registry: { level: 'danger', suspended: true, labels: ['注册商暂停解析'], codes: ['clienthold'] },
      problems: [{ kind: 'registry', label: '注册商暂停解析', level: 'danger' }]
    }
  }
});

domains.push({
  name: 'lost-dns.dev', username: 'studio', registrar: 'Porkbun LLC',
  registrationDate: iso(add(-200)), expirationDate: iso(add(160)),
  whoisError: null, isFree: false, plan: 'Free Website', dataSource: 'rdap',
  notes: '', nameServers: ['ns1.parkingcrew.net', 'ns2.parkingcrew.net'],
  health: {
    checkedAt: new Date(Date.now() - 5 * 3600 * 1000).toISOString(),
    summary: {
      level: 'danger', dns: 'nxdomain', dnsLabel: '解析丢失',
      registry: { level: 'ok', suspended: false, labels: ['禁止转移'], codes: ['clienttransferprohibited'] },
      problems: [{ kind: 'dns', label: '解析丢失' }]
    }
  }
});

// 囤着没配解析的域名：nodata 不该报警，详情页只作说明
domains.push({
  name: 'idle-stash.net', username: 'archive', registrar: 'Dynadot LLC',
  registrationDate: iso(add(-90)), expirationDate: iso(add(275)),
  whoisError: null, isFree: false, plan: 'Free Website', dataSource: 'rdap',
  notes: '', nameServers: NS,
  health: {
    checkedAt: new Date(Date.now() - 26 * 3600 * 1000).toISOString(),
    summary: {
      level: 'ok', dns: 'nodata', dnsLabel: '未配置解析',
      registry: { level: 'ok', suspended: false, labels: ['禁止转移'], codes: ['clienttransferprohibited'] },
      problems: []
    }
  }
});

// 统一用真实白名单回填 isFree / isPermanent，避免手写字段与线上语义漂移
for (const d of domains) {
  d.isFree = freeDomains.isFree(d.name);
  // 永久判定有两条来源：注册表规则 + 哨兵日期（2999）
  d.isPermanent = freeDomains.isPermanent(d.name) || /^2[9-9]\d{2}-/.test(String(d.expirationDate));
}

writeFileSync(join(outDir, 'admin.html'), generateHTML(domains, true));
writeFileSync(join(outDir, 'guest.html'), generateHTML(domains, false));
writeFileSync(join(outDir, 'login.html'), generateLoginHTML('登录 DSMC', '/login', '密码错误'));
writeFileSync(join(outDir, 'admin-login.html'), generateLoginHTML('管理员登录', '/admin-login'));

console.log('rendered ' + domains.length + ' domains → design/preview/');
