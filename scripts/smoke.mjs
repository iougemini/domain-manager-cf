// 端到端冒烟测试：把 Worker 打成一个可在 Node 里 import 的包，
// 然后用假 KV + 假 ctx 真跑一遍路由，确认各页面能返回预期状态且关键内容在位。
//
// 这不是替代单测，而是补一层"模块能装起来、路由没接错"的验证——
// 单测覆盖了函数级行为，但 `import` 链断裂、路由漏注册这类问题只有跑起来才看得见。
//
// 运行：node scripts/smoke.mjs
import { build } from 'esbuild';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const outDir = join(root, '.smoke');
const outFile = join(outDir, 'worker.mjs');

mkdirSync(outDir, { recursive: true });

await build({
  entryPoints: [join(root, 'src/index.js')],
  bundle: true,
  format: 'esm',
  platform: 'neutral',
  target: 'es2022',
  outfile: outFile,
  alias: { 'cloudflare:sockets': join(root, 'test/_sockets-stub.js') },
  logLevel: 'warning'
});

/* ---------------- 假 KV ---------------- */
function fakeKV(initial = {}) {
  const store = new Map(Object.entries(initial));
  return {
    // 必须支持 get(key, { type: 'json' })：真实 KV 会按 type 解析，假 KV 不解析的话
    // 调用方拿到的是字符串，`existingLogs.unshift is not a function` 这类
    // 错误会被 catch 吞掉，审计日志在冒烟里等于从没写成功过
    async get(key, options) {
      if (!store.has(key)) return null;
      const value = store.get(key);
      const type = typeof options === 'string' ? options : (options && options.type);
      if (type === 'json') {
        try { return JSON.parse(value); } catch { return null; }
      }
      return value;
    },
    async put(key, value) { store.set(key, String(value)); },
    async delete(key) { store.delete(key); },
    async list({ prefix = '' } = {}) {
      return { keys: [...store.keys()].filter(k => k.startsWith(prefix)).map(name => ({ name })) };
    },
    // 限流计数器按 IP 存 KV。冒烟里所有请求都来自同一个 IP，
    // 不做重置的话第 6 次登录就会被锁 30 分钟——测的是功能，不是限流
    reset(prefix) {
      for (const key of [...store.keys()]) {
        if (key.startsWith(prefix)) store.delete(key);
      }
    }
  };
}

const kv = fakeKV({
  'config:accounts': JSON.stringify([
    { id: 'acct_1', label: '主账户', username: 'demo', token: 'demo-token-value-1234567890', active: true }
  ]),
  'config:dnshe': JSON.stringify([
    { id: 'dnshe_1', label: '主账户', key: 'cfsd_demo_key_1234', secret: 'sk_demo_secret', enabled: true }
  ]),
  'config:notify': JSON.stringify({
    enabled: false,
    rules: { daysBefore: 30, includeExpired: true, timezoneOffset: 8 },
    channels: [{
      id: 'ch_1', type: 'feishu', label: '运维群', enabled: true,
      config: { webhook: 'https://open.feishu.cn/open-apis/bot/v2/hook/abcdef123456', secret: 'real-secret' }
    }]
  })
});

const ctx = { waitUntil() {}, passThroughOnException() {} };
const worker = (await import(pathToFileURL(outFile).href)).default;

// 两种部署形态都要覆盖：公开站点、有访问密码
const envPublic = { DOMAIN_INFO: kv, ADMIN_PASSWORD: 'admin-test-pass', ACCESS_PASSWORD: '' };
const envProtected = { DOMAIN_INFO: kv, ADMIN_PASSWORD: 'admin-test-pass', ACCESS_PASSWORD: 'access-test-pass' };

const get = (path, env, headers = {}) =>
  worker.fetch(new Request('https://demo.test' + path, { headers }), env, ctx);

const postForm = (path, body, env) =>
  worker.fetch(new Request('https://demo.test' + path, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body
  }), env, ctx);

/* ---------------- 断言 ---------------- */
const results = [];
const check = (name, fn) => results.push([name, fn]);

check('GET /login 返回登录页', async () => {
  const res = await get('/login', envProtected);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /<form/);
  assert.match(html, /DSMC/);
});

check('GET /admin-login 返回管理员登录页', async () => {
  const res = await get('/admin-login', envProtected);
  assert.equal(res.status, 200);
  assert.match(await res.text(), /管理员/);
});

check('未设访问密码时首页公开可访问', async () => {
  const res = await get('/', envPublic);
  assert.equal(res.status, 200);
  assert.match(await res.text(), /<!DOCTYPE html>/i);
});

check('设了访问密码后未登录访问首页被重定向', async () => {
  const res = await get('/', envProtected);
  assert.ok([302, 303, 307].includes(res.status), '实际状态 ' + res.status);
  assert.match(res.headers.get('location') || '', /\/login$/);
});

check('访问密码错误返回 401 且提示错误', async () => {
  const res = await postForm('/login', 'password=wrong-password', envProtected);
  assert.equal(res.status, 401);
  assert.match(await res.text(), /密码|错误|失败/);
});

check('访问密码正确下发 access_token', async () => {
  const res = await postForm('/login', 'password=access-test-pass', envProtected);
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/');
  const cookie = res.headers.get('set-cookie') || '';
  assert.match(cookie, /access_token=/);
  assert.match(cookie, /HttpOnly/i);
});

check('管理员密码正确下发 admin_token', async () => {
  const res = await postForm('/admin-login', 'password=admin-test-pass', envProtected);
  assert.equal(res.status, 302);
  const cookie = res.headers.get('set-cookie') || '';
  assert.match(cookie, /admin_token=/);
  assert.match(cookie, /HttpOnly/i);
});

check('管理员密码错误不下发 cookie', async () => {
  const res = await postForm('/admin-login', 'password=nope', envProtected);
  assert.ok(res.status >= 400 || !(res.headers.get('set-cookie') || '').includes('admin_token='),
    '状态 ' + res.status);
});

check('GET /logout 清 access_token 并回登录页', async () => {
  const res = await get('/logout', envProtected);
  assert.equal(res.status, 302);
  assert.match(res.headers.get('location') || '', /\/login$/);
  const cookie = res.headers.get('set-cookie') || '';
  assert.match(cookie, /access_token=;/);
  assert.match(cookie, /Max-Age=0/);
});

check('GET /admin-logout 同时清掉 admin_token 与 access_token', async () => {
  const res = await get('/admin-logout', envProtected);
  assert.equal(res.status, 302);
  assert.match(res.headers.get('location') || '', /\/admin-login$/);
  const cookies = res.headers.getSetCookie
    ? res.headers.getSetCookie()
    : [res.headers.get('set-cookie') || ''];
  const joined = cookies.join(' | ');
  assert.match(joined, /admin_token=;/);
  assert.match(joined, /access_token=;/);
});

check('退出后带空 cookie 访问首页仍被要求登录', async () => {
  const res = await get('/', envProtected, { cookie: 'access_token=' });
  assert.ok([302, 303, 307].includes(res.status), '实际状态 ' + res.status);
});

check('页面顶部有退出登录入口', async () => {
  const login = await postForm('/admin-login', 'password=admin-test-pass', envProtected);
  const cookie = (login.headers.get('set-cookie') || '').split(';')[0];
  const html = await (await get('/admin', envProtected, { cookie })).text();
  assert.ok(html.includes('href="/admin-logout"'), '管理页缺少退出入口');

  const access = await postForm('/login', 'password=access-test-pass', envProtected);
  const acookie = (access.headers.get('set-cookie') || '').split(';')[0];
  const front = await (await get('/', envProtected, { cookie: acookie })).text();
  assert.ok(front.includes('href="/logout"'), '前台缺少退出入口');
});

check('未授权访问 /api/accounts 被拒', async () => {
  const res = await get('/api/accounts', envProtected);
  assert.ok([401, 403, 302].includes(res.status), '实际状态 ' + res.status);
});

check('未授权访问 /api/settings 被拒', async () => {
  const res = await get('/api/settings', envProtected);
  assert.ok([401, 403, 302].includes(res.status), '实际状态 ' + res.status);
});

check('未授权访问 /api/notify 被拒', async () => {
  const res = await get('/api/notify', envProtected);
  assert.ok([401, 403, 302].includes(res.status), '实际状态 ' + res.status);
});

check('未授权访问 /api/dnshe 被拒', async () => {
  const res = await get('/api/dnshe', envProtected);
  assert.ok([401, 403, 302].includes(res.status), '实际状态 ' + res.status);
});

check('未知路径不返回 5xx', async () => {
  const res = await get('/definitely-not-a-route', envProtected);
  assert.ok(res.status < 500, '实际状态 ' + res.status);
});

// 登录后用真 cookie 打开管理后台，确认四个新页面的导航项真的渲染出来了
check('登录后 /admin 渲染出侧栏导航与四个管理入口', async () => {
  const login = await postForm('/admin-login', 'password=admin-test-pass', envProtected);
  const cookie = (login.headers.get('set-cookie') || '').split(';')[0];
  assert.match(cookie, /admin_token=/);

  const res = await get('/admin', envProtected, { cookie });
  assert.equal(res.status, 200, '实际状态 ' + res.status);

  const html = await res.text();
  const rail = html.slice(html.indexOf('<aside class="rail">'), html.indexOf('</aside>'));
  for (const item of ['概览', '域名', '续费', '账户', '免费', '通知', '设置', '关于']) {
    assert.ok(rail.includes('>' + item + '<'), '侧栏缺少导航项：' + item);
  }
  // 标签统一后不该再出现旧名字，也不该再有独立的 DNSHE 页
  for (const old of ['域名库', '续费清单', '免费域名']) {
    assert.ok(!rail.includes(old), '侧栏残留旧标签：' + old);
  }
  assert.ok(!html.includes('data-view-link="dnshe"'), 'DNSHE 仍是独立页面');

  // 数据块必须能解析，否则前端脚本会整段挂掉
  const m = html.match(/<script type="application\/json" id="dsmc-data">([\s\S]*?)<\/script>/);
  assert.ok(m, '缺少 dsmc-data 数据块');
  const data = JSON.parse(m[1]);
  assert.ok(Array.isArray(data.domains), 'domains 不是数组');
  assert.ok(Array.isArray(data.accounts), 'accounts 不是数组');
  assert.ok(Array.isArray(data.dnshe), 'dnshe 不是数组');
  assert.ok(Array.isArray(data.notifyTypes) && data.notifyTypes.length === 9,
    'notifyTypes 应有 9 个渠道，实际 ' + (data.notifyTypes || []).length);
});

// 页脚要出现在三类页面上，且内容一致（版权链交流区、Powered by 链仓库）
check('管理页与登录页都渲染出统一页脚', async () => {
  const login = await postForm('/admin-login', 'password=admin-test-pass', envProtected);
  const cookie = (login.headers.get('set-cookie') || '').split(';')[0];

  for (const [label, res] of [
    ['/admin', await get('/admin', envProtected, { cookie })],
    ['/login', await get('/login', envProtected)]
  ]) {
    const html = await res.text();
    assert.ok(html.includes('class="site-foot'), label + ' 缺页脚');
    assert.match(html, /Copyright by NieGe Meta/, label + ' 页脚缺版权');
    assert.match(html, /Powered by DSMC/, label + ' 页脚缺 Powered by');
    assert.match(html, /Domain Status Manager for Cloudflare/, label + ' 页脚缺全名');
    assert.match(html, /href="https:\/\/niege\.app"/, label + ' 版权没有链到交流区');
    assert.match(html, /href="https:\/\/github\.com\/iougemini\/domain-manager-cf"/, label + ' 没有链到仓库');
  }
});

// 凭证不能以明文出现在页面里（包括注入给前端的数据块）
check('/admin 页面不含明文凭证', async () => {
  const login = await postForm('/admin-login', 'password=admin-test-pass', envProtected);
  const cookie = (login.headers.get('set-cookie') || '').split(';')[0];
  const html = await (await get('/admin', envProtected, { cookie })).text();

  for (const secret of ['demo-token-value-1234567890', 'sk_demo_secret', 'real-secret', 'abcdef123456']) {
    assert.ok(!html.includes(secret), '页面泄露了明文凭证：' + secret);
  }
});

// ETag 是这一轮性能优化的关键：数据没变时浏览器只该回几十字节。
// 单测只验证了 htmlResponse 本身，路由层把 request 传错、或者页面里混进了
// 每请求都变的字段，单测都发现不了——只有走完整路由才看得见。
check('/admin 二次访问走 304（ETag 生效）', async () => {
  const login = await postForm('/admin-login', 'password=admin-test-pass', envProtected);
  const cookie = (login.headers.get('set-cookie') || '').split(';')[0];

  const first = await get('/admin', envProtected, { cookie });
  assert.ok(first.headers.get('etag'), '页面响应缺少 ETag');
  await first.text();

  // 账户的失败计数、最近使用时间可能在两次请求之间变化，页面内容随之改变，
  // 这时 ETag 本来就该跟着变。取第二次的 ETag 再做条件请求。
  const second = await get('/admin', envProtected, { cookie });
  const etag = second.headers.get('etag');
  await second.text();

  const cond = await get('/admin', envProtected, { cookie, 'if-none-match': etag });
  assert.equal(cond.status, 304, '条件请求未返回 304，实际 ' + cond.status);
  assert.equal((await cond.text()).length, 0, '304 不应带响应体');
  assert.match(cond.headers.get('cache-control') || '', /no-cache/, '缓存策略应为 no-cache');
  assert.match(cond.headers.get('vary') || '', /cookie/i, '应按 Cookie 区分缓存');
});

check('改 DNSHE 凭证会清掉该后缀的旧缓存', async () => {  // 先塞一条"上次 401 的兜底值"，模拟用户改 Key 之前的状态
  await kv.put('whois_demo.us.ci', JSON.stringify({
    data: { lookupError: 'DNSHE 认证失败（401）' },
    timestamp: Date.now(),
    version: '1.3.0'
  }));

  const login = await postForm('/admin-login', 'password=admin-test-pass', envProtected);
  const cookie = (login.headers.get('set-cookie') || '').split(';')[0];

  const call = body => worker.fetch(new Request('https://demo.test/api/dnshe', {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify(body)
  }), envProtected, ctx);

  const data = await (await call({ action: 'toggle', id: 'dnshe_1' })).json();
  assert.ok(data.purged >= 1, 'purged 应为正数，实际 ' + data.purged);
  assert.equal(await kv.get('whois_demo.us.ci'), null, '旧缓存没被删掉');

  // 还原，别影响后面的检查
  await call({ action: 'toggle', id: 'dnshe_1' });
});

check('scheduled 在通知未启用时安全跳过', async () => {
  await worker.scheduled({ cron: '0 2 * * *', scheduledTime: Date.now() }, envPublic, ctx);
});

/* ---------------- 新增自定义域名：先查 WHOIS，查不到再让用户补 ---------------- */

const ADMIN_COOKIE = async () => {
  const login = await postForm('/admin-login', 'password=admin-test-pass', envProtected);
  return (login.headers.get('set-cookie') || '').split(';')[0];
};

const customCall = (cookie, body) => worker.fetch(new Request('https://demo.test/api/custom-domains', {
  method: 'POST',
  headers: { 'content-type': 'application/json', cookie },
  body: JSON.stringify(body)
}), envProtected, ctx);

const customList = async cookie => (await worker.fetch(
  new Request('https://demo.test/api/custom-domains', { headers: { cookie } }), envProtected, ctx
)).json();

check('新增域名只填域名：查不到时返回 needsManual 并已落库', async () => {
  const cookie = await ADMIN_COOKIE();

  // 冒烟环境没配 WHOIS 代理，普通域名必然查不到——正好覆盖"让用户补填"这条分支
  const res = await customCall(cookie, { action: 'add', domain: 'manual-demo.test', info: { notes: '手工添加' } });
  assert.equal(res.status, 200, '实际状态 ' + res.status);

  const data = await res.json();
  assert.equal(data.needsManual, true, '查不到时应提示补填');
  assert.equal(data.record.lookupStatus, 'missing');
  assert.equal(data.record.notes, '手工添加', '备注要存下来');
  assert.equal(data.record.expirationDate, 'Unknown', '不该编造到期日');

  const list = await customList(cookie);
  assert.ok(list.domains.some(d => d.domain === 'manual-demo.test'), '域名没写进 KV');
});

check('重复添加同一域名返回 409 而不是 500', async () => {
  const cookie = await ADMIN_COOKIE();
  const res = await customCall(cookie, { action: 'add', domain: 'manual-demo.test', info: {} });
  assert.equal(res.status, 409, '实际状态 ' + res.status);
  assert.match((await res.json()).error, /已在列表/);
});

check('只改备注不会关闭 WHOIS 自动更新', async () => {
  const cookie = await ADMIN_COOKIE();

  await customCall(cookie, {
    action: 'update',
    domain: 'manual-demo.test',
    info: { notes: '只改备注' }
  });

  const rec = (await customList(cookie)).domains.find(d => d.domain === 'manual-demo.test');
  assert.equal(rec.notes, '只改备注');
  assert.notEqual(rec.autoUpdateWhois, false, '只改备注不该冻结自动更新');
});

check('改了到期日才关闭自动更新，并标记为人工维护', async () => {
  const cookie = await ADMIN_COOKIE();

  await customCall(cookie, {
    action: 'update',
    domain: 'manual-demo.test',
    info: { registrar: 'DNSHE', registrationDate: '2024-01-01', expirationDate: '2028-04-03' }
  });

  const rec = (await customList(cookie)).domains.find(d => d.domain === 'manual-demo.test');
  assert.equal(rec.expirationDate, '2028-04-03');
  assert.equal(rec.autoUpdateWhois, false, '改了日期就该停止自动更新');
  assert.equal(rec.lookupStatus, 'manual');
});

// 放在最后：这一项会把这个 IP 锁在限流状态里
check('连续登录失败会被限流（429）', async () => {
  let last = null;
  for (let i = 0; i < 8; i++) {
    last = await postForm('/admin-login', 'password=wrong-password', envProtected);
    if (last.status === 429) break;
  }
  assert.equal(last.status, 429, '连续失败登录应被限流，实际 ' + last.status);
});

/* ---------------- 执行 ---------------- */
let failed = 0;
for (const [name, fn] of results) {
  try {
    // 每项检查从"没被限流过"的状态开始
    kv.reset('ratelimit:');
    await fn();
    console.log('  ok   ' + name);
  } catch (e) {
    failed++;
    console.log('  FAIL ' + name + '\n       ' + e.message);
  }
}

rmSync(outDir, { recursive: true, force: true });

console.log('\n' + (results.length - failed) + '/' + results.length + ' 项通过');
if (failed) process.exit(1);
