import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  toYmd,
  isPermanentDate,
  PERMANENT_YEAR,
  findRegistrar,
  parseRdap,
  parseDnshe,
  FreeDomainLookup
} from '../src/services/free-domain-lookup.js';
import { FreeDomainManager, DEFAULT_SUFFIXES } from '../src/managers/free-domain.js';
import { WhoisService } from '../src/services/whois.js';

// DigitalPlat RDAP 真实响应样例（来自官方文档）
const RDAP_SAMPLE = {
  entities: [
    {
      handle: 'DIGITALPLAT',
      objectClassName: 'entity',
      publicIds: [{ identifier: '9999', type: 'IANA Registrar ID' }],
      roles: ['registrar'],
      vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'DigitalPlat One']]]
    },
    {
      handle: 'REDACTED-FOR-PRIVACY',
      objectClassName: 'entity',
      roles: ['registrant'],
      vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'REDACTED FOR PRIVACY']]]
    }
  ],
  events: [
    { eventAction: 'registration', eventDate: '2024-05-30T00:00:00Z' },
    { eventAction: 'expiration', eventDate: '2027-05-30T00:00:00Z' }
  ],
  handle: 'NIEGE.DPDNS.ORG',
  ldhName: 'niege.dpdns.org',
  nameservers: [
    { ldhName: 'magali.ns.cloudflare.com', objectClassName: 'nameserver' },
    { ldhName: 'hal.ns.cloudflare.com', objectClassName: 'nameserver' }
  ],
  objectClassName: 'domain',
  status: ['active']
};

// DNSHE 真实响应样例（来自官方文档）
const DNSHE_REGISTERED = {
  success: true,
  domain: 'foo.us.ci',
  status: 'active',
  registered_at: '2025-01-10 08:30:00',
  expires_at: '2026-01-10 08:30:00',
  registrant_email: 'whois@example.com',
  nameservers: ['ns1.example.net', 'ns2.example.net'],
  rate_limit: { limit: 2, remaining: 1, reset_at: '2025-01-10 08:31:00' }
};

const DNSHE_UNREGISTERED = {
  success: true,
  domain: 'foo.us.ci',
  registered: false,
  status: 'unregistered',
  message: 'domain not registered'
};

const fakeFetch = (payload, status = 200) => async () => ({
  ok: status >= 200 && status < 300,
  status,
  text: async () => JSON.stringify(payload)
});

describe('toYmd', () => {
  it('解析 ISO 时间戳', () => {
    assert.equal(toYmd('2024-05-30T00:00:00Z'), '2024-05-30');
  });

  it('解析空格分隔格式', () => {
    assert.equal(toYmd('2025-01-10 08:30:00'), '2025-01-10');
  });

  it('非法输入返回 null', () => {
    assert.equal(toYmd(''), null);
    assert.equal(toYmd(null), null);
    assert.equal(toYmd('Unknown'), null);
    assert.equal(toYmd('2024-13-01'), null);
    assert.equal(toYmd('1800-01-01'), null);
  });

  // 回归：2100 上限曾把永久域名的哨兵日期整条丢掉，页面显示成「待设置」
  it('接受 2999 / 9999 哨兵年份', () => {
    assert.equal(toYmd('2999-12-31'), '2999-12-31');
    assert.equal(toYmd('9999-12-31T00:00:00Z'), '9999-12-31');
  });
});

describe('isPermanentDate / PERMANENT_YEAR', () => {
  it('2999 哨兵日期判定为永久', () => {
    assert.equal(isPermanentDate('2999-12-31'), true);
    assert.equal(isPermanentDate('2999-12-31T00:00:00Z'), true);
    assert.equal(isPermanentDate('9999-12-31'), true);
  });

  it('常规续期日期不是永久', () => {
    assert.equal(isPermanentDate('2027-01-01'), false);
    assert.equal(isPermanentDate('2099-12-31'), false);
    assert.equal(isPermanentDate('2899-12-31'), false);
  });

  it('空值与非法值安全返回 false', () => {
    assert.equal(isPermanentDate(''), false);
    assert.equal(isPermanentDate(null), false);
    assert.equal(isPermanentDate(undefined), false);
    assert.equal(isPermanentDate('Unknown'), false);
    assert.equal(isPermanentDate('永久'), false);
  });

  it('阈值常量为 2900', () => {
    assert.equal(PERMANENT_YEAR, 2900);
    assert.equal(isPermanentDate('2900-01-01'), true);
  });
});

describe('findRegistrar', () => {
  it('从 vcard 的 fn 字段取注册商名', () => {
    assert.equal(findRegistrar(RDAP_SAMPLE.entities), 'DigitalPlat One');
  });

  it('跳过非 registrar 角色', () => {
    const only = [RDAP_SAMPLE.entities[1]];
    assert.equal(findRegistrar(only), null);
  });

  it('空输入返回 null', () => {
    assert.equal(findRegistrar(null), null);
    assert.equal(findRegistrar([]), null);
  });
});

describe('parseRdap', () => {
  it('解析出注册日与到期日', () => {
    const r = parseRdap(RDAP_SAMPLE);
    assert.equal(r.registrationDate, '2024-05-30');
    assert.equal(r.expirationDate, '2027-05-30');
    assert.equal(r.registered, true);
  });

  it('解析注册商与域名服务器', () => {
    const r = parseRdap(RDAP_SAMPLE);
    assert.equal(r.registrar, 'DigitalPlat One');
    assert.deepEqual(r.nameServers, ['magali.ns.cloudflare.com', 'hal.ns.cloudflare.com']);
    assert.equal(r.source, 'rdap');
  });

  it('缺失 events 时日期为 Unknown，不抛错', () => {
    const r = parseRdap({ ldhName: 'x.dpdns.org' });
    assert.equal(r.registrationDate, 'Unknown');
    assert.equal(r.expirationDate, 'Unknown');
    assert.deepEqual(r.nameServers, []);
  });

  it('errorCode 404 视为未注册', () => {
    assert.equal(parseRdap({ errorCode: 404 }).registered, false);
  });
});

describe('parseDnshe', () => {
  it('解析已注册域名', () => {
    const r = parseDnshe(DNSHE_REGISTERED);
    assert.equal(r.registrationDate, '2025-01-10');
    assert.equal(r.expirationDate, '2026-01-10');
    assert.deepEqual(r.nameServers, ['ns1.example.net', 'ns2.example.net']);
    assert.equal(r.source, 'dnshe');
  });

  it('未注册是有效结果，不是错误', () => {
    const r = parseDnshe(DNSHE_UNREGISTERED);
    assert.equal(r.registered, false);
    assert.equal(r.error, undefined);
  });

  it('success:false 转成 error', () => {
    const r = parseDnshe({ success: false, message: 'API Key 无效' });
    assert.equal(r.error, 'API Key 无效');
  });

  it('普通域名不带永久标记', () => {
    assert.equal(parseDnshe(DNSHE_REGISTERED).isPermanent, false);
  });

  // 用户需求：DNSHE 可升级永久域名，到期日为 2999 年即视为永久
  it('到期日 2999 标记为永久域名', () => {
    const r = parseDnshe({
      ...DNSHE_REGISTERED,
      domain: 'forever.us.ci',
      expires_at: '2999-12-31 00:00:00'
    });
    assert.equal(r.expirationDate, '2999-12-31');
    assert.equal(r.isPermanent, true);
    assert.equal(r.registered, true);
  });

  it('到期日缺失时不误判为永久', () => {
    const r = parseDnshe({ success: true, domain: 'x.us.ci', status: 'active' });
    assert.equal(r.expirationDate, 'Unknown');
    assert.equal(r.isPermanent, false);
  });

  // 事故复盘：DNSHE 曾在响应里回显另一个域名，如果我们照单全收，
  // 就会把别人的到期日挂到当前域名上——续费提醒跟着一起错。
  it('回显域名与请求不符时丢弃整条数据', () => {
    const r = parseDnshe({
      success: true,
      domain: 'otime.ccwu.cc',
      status: 'active',
      registered_at: '2026-08-03 10:06:00',
      expires_at: '2036-08-03 10:06:00'
    }, 'otime.cn.mt');

    assert.match(r.error, /另一个域名/);
    assert.equal(r.expirationDate, undefined);
    assert.equal(r.registrationDate, undefined);
  });

  it('回显域名一致时正常解析（忽略大小写与结尾点）', () => {
    const r = parseDnshe({
      success: true,
      domain: 'OTIME.CN.MT.',
      status: 'active',
      registered_at: '2026-04-03 10:06:00',
      expires_at: '2028-04-03 10:06:00'
    }, 'otime.cn.mt');

    assert.equal(r.error, undefined);
    assert.equal(r.registrationDate, '2026-04-03');
    assert.equal(r.expirationDate, '2028-04-03');
  });

  it('响应没有回显域名时不做校验（兼容旧接口）', () => {
    const r = parseDnshe({
      success: true,
      status: 'active',
      registered_at: '2026-04-03 10:06:00',
      expires_at: '2028-04-03 10:06:00'
    }, 'otime.cn.mt');

    assert.equal(r.error, undefined);
    assert.equal(r.expirationDate, '2028-04-03');
  });
});

describe('FreeDomainLookup 网络层', () => {
  const spec = { type: 'rdap', endpoint: 'https://rdap.digitalplat.org/domain/{domain}' };

  it('成功时返回解析结果', async () => {
    const lookup = new FreeDomainLookup({ fetchImpl: fakeFetch(RDAP_SAMPLE) });
    const r = await lookup.lookup('niege.dpdns.org', spec);
    assert.equal(r.expirationDate, '2027-05-30');
  });

  it('URL 里的 {domain} 会被替换并编码', async () => {
    let called = '';
    const lookup = new FreeDomainLookup({
      fetchImpl: async url => { called = url; return { ok: true, status: 200, text: async () => JSON.stringify(RDAP_SAMPLE) }; }
    });
    await lookup.lookup('niege.dpdns.org', spec);
    assert.equal(called, 'https://rdap.digitalplat.org/domain/niege.dpdns.org');
  });

  it('默认带浏览器 UA（DigitalPlat 前置 WAF 会拦 curl UA）', async () => {
    let ua = '';
    const lookup = new FreeDomainLookup({
      fetchImpl: async (url, init) => {
        ua = init.headers['User-Agent'];
        return { ok: true, status: 200, text: async () => JSON.stringify(RDAP_SAMPLE) };
      }
    });
    await lookup.lookup('niege.dpdns.org', spec);
    assert.match(ua, /Mozilla\/5\.0/);
  });

  it('403 给出 WAF 提示而不是裸状态码', async () => {
    const lookup = new FreeDomainLookup({
      fetchImpl: async () => ({ ok: false, status: 403, text: async () => '<!DOCTYPE html><html>Challenge' })
    });
    const r = await lookup.lookup('x.dpdns.org', spec);
    assert.match(r.error, /WAF/);
  });

  it('401 且没有任何凭证时，明确提示"没配"而不是"填错了"', async () => {
    const lookup = new FreeDomainLookup({
      fetchImpl: async () => ({ ok: false, status: 401, text: async () => '{}' })
    });
    const r = await lookup.lookup('x.us.ci', { type: 'dnshe', endpoint: 'https://api005.dnshe.com/{domain}' });
    assert.match(r.error, /没有可用凭证/);
    assert.match(r.error, /DNSHE_API_KEY/);
  });

  it('401 时把服务端原话带进错误信息', async () => {
    const lookup = new FreeDomainLookup({
      dnsheCredentials: [{ key: 'cfsd_abcdefgh', secret: 'secretvalue1' }],
      fetchImpl: async () => ({
        ok: false,
        status: 401,
        text: async () => JSON.stringify({ error: 'Invalid API key', error_code: 'auth_invalid_credentials' })
      })
    });
    const r = await lookup.lookup('x.us.ci', { type: 'dnshe', endpoint: 'https://api005.dnshe.com/{domain}' });
    assert.equal(r.authFailed, true);
    assert.match(r.error, /Invalid API key/);
    // 有凭证却被拒 ≠ 没配凭证，提示要能区分
    assert.match(r.error, /被服务端拒绝/);
  });

  it('只有 Key 没有 Secret 时不发半套请求头，直接报"凭证不完整"', async () => {
    let called = 0;
    const lookup = new FreeDomainLookup({
      dnsheCredentials: [{ key: 'cfsd_abcdefgh', secret: '' }],
      fetchImpl: async () => { called++; return { ok: true, status: 200, text: async () => '{}' }; }
    });
    const r = await lookup.lookup('x.us.ci', { type: 'dnshe', endpoint: 'https://api005.dnshe.com/{domain}' });
    assert.equal(called, 0);
    assert.equal(r.authFailed, true);
    assert.match(r.error, /缺少 API Secret/);
  });

  it('Key 与 Secret 成对发送', async () => {
    let seen = null;
    const lookup = new FreeDomainLookup({
      dnsheCredentials: [{ key: 'cfsd_abcdefgh', secret: 'secretvalue1' }],
      fetchImpl: async (url, init) => {
        seen = init.headers;
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ success: true, registered: true, expires_at: '2027-01-01 00:00:00' })
        };
      }
    });
    await lookup.lookup('x.us.ci', { type: 'dnshe', endpoint: 'https://api005.dnshe.com/{domain}' });
    assert.equal(seen['X-API-Key'], 'cfsd_abcdefgh');
    assert.equal(seen['X-API-Secret'], 'secretvalue1');
  });

  it('返回 HTML 挑战页时给出可读错误', async () => {
    const lookup = new FreeDomainLookup({
      fetchImpl: async () => ({ ok: true, status: 200, text: async () => '<!DOCTYPE html><html><title>Challenge</title>' })
    });
    const r = await lookup.lookup('x.dpdns.org', spec);
    assert.match(r.error, /不是 JSON/);
  });

  it('404 返回未注册而不是错误', async () => {
    const lookup = new FreeDomainLookup({ fetchImpl: fakeFetch({}, 404) });
    const r = await lookup.lookup('nope.dpdns.org', spec);
    assert.equal(r.registered, false);
    assert.equal(r.error, undefined);
  });

  it('HTTP 500 返回 error，不抛异常', async () => {
    const lookup = new FreeDomainLookup({ fetchImpl: fakeFetch({}, 500) });
    const r = await lookup.lookup('x.dpdns.org', spec);
    assert.match(r.error, /HTTP 500/);
  });

  it('超时返回可读错误', async () => {
    const lookup = new FreeDomainLookup({
      fetchImpl: async () => { const e = new Error('aborted'); e.name = 'AbortError'; throw e; }
    });
    const r = await lookup.lookup('x.dpdns.org', spec);
    assert.match(r.error, /超时/);
  });

  it('关闭开关后不发起请求', async () => {
    let called = false;
    const lookup = new FreeDomainLookup({
      enabled: false,
      fetchImpl: async () => { called = true; return { ok: true, status: 200, text: async () => '{}' }; }
    });
    const r = await lookup.lookup('x.dpdns.org', spec);
    assert.equal(r, null);
    assert.equal(called, false);
  });

  it('未知查询类型返回 error', async () => {
    const lookup = new FreeDomainLookup({ fetchImpl: fakeFetch({}) });
    const r = await lookup.lookup('x.dpdns.org', { type: 'nope', endpoint: 'https://x/{domain}' });
    assert.match(r.error, /不支持/);
  });

  it('DNSHE 会带上 API Key 头', async () => {
    let headers = null;
    const lookup = new FreeDomainLookup({
      dnsheKey: 'cfsd_test',
      dnsheSecret: 'secret',
      fetchImpl: async (url, init) => {
        headers = init.headers;
        return { ok: true, status: 200, text: async () => JSON.stringify(DNSHE_REGISTERED) };
      }
    });
    await lookup.lookup('foo.us.ci', { type: 'dnshe', endpoint: 'https://api005.dnshe.com/{domain}' });
    assert.equal(headers['X-API-Key'], 'cfsd_test');
    assert.equal(headers['X-API-Secret'], 'secret');
  });
});

describe('注册表内置查询端点', () => {
  const m = new FreeDomainManager();

  it('多级后缀按最长匹配，不会被相邻后缀抢走', () => {
    // 事故复盘：otime.cn.mt 曾被报成 parent=ccwu.cc。
    // 后缀表里 cn.mt 与 ccwu.cc 都只有 5/7 个字符，很容易在"按长度降序"这一步出错，
    // 这条用例把两个域名的归属钉死。
    const cnmt = m.getInfo('otime.cn.mt');
    assert.equal(cnmt.parent, 'cn.mt');
    assert.equal(cnmt.provider, 'DNSHE');
    assert.match(cnmt.description, /MT/);

    const ccwu = m.getInfo('otime.ccwu.cc');
    assert.equal(ccwu.parent, 'ccwu.cc');
    assert.match(ccwu.description, /CC/);

    // 互为子串的两组后缀不能串味
    assert.equal(m.getInfo('a.us.ci').parent, 'us.ci');
    assert.equal(m.getInfo('a.kz.ci').parent, 'kz.ci');
  });

  it('DigitalPlat 五个后缀都配了 RDAP', () => {
    for (const s of ['us.kg', 'dpdns.org', 'xx.kg', 'qzz.io', 'qd.je']) {
      const info = m.getInfo('demo.' + s);
      assert.ok(info, s + ' 未注册');
      assert.equal(info.lookup.type, 'rdap', s + ' 缺少 rdap 配置');
      assert.match(info.lookup.endpoint, /rdap\.digitalplat\.org/);
    }
  });

  it('DNSHE 十个后缀都配了 whois 接口', () => {
    const list = ['us.ci', 'cc.cd', 'new.tg', 'de5.net', 'ccwu.cc', 'bbroot.com', 'kz.ci', 'xyz.ci', 'pc.ci', 'cn.mt'];
    for (const s of list) {
      const info = m.getInfo('demo.' + s);
      assert.ok(info, s + ' 未注册');
      assert.equal(info.lookup.type, 'dnshe', s + ' 缺少 dnshe 配置');
      assert.match(info.lookup.endpoint, /api005\.dnshe\.com/);
    }
  });

  it('pp.ua 配了 WHOIS/TCP 查询接口', () => {
    const info = m.getInfo('demo.pp.ua');
    assert.equal(info.lookup.type, 'whois');
    assert.equal(info.lookup.endpoint, 'whois.pp.ua:43');
  });

  it('eu.org / is-a.dev / js.org 这类公益域名只用元数据（永久，无需查询）', () => {
    assert.equal(m.getInfo('demo.eu.org').lookup, null);
    assert.equal(m.getInfo('demo.is-a.dev').lookup, null);
    assert.equal(m.getInfo('demo.js.org').lookup, null);
  });

  it('ip6.arpa 视为永久域名，且不挂必然 404 的查询', () => {    const apex = m.getInfo('ip6.arpa');
    assert.equal(apex.isPermanent, true);
    assert.equal(apex.category, 'public');
    assert.equal(apex.lookup, null);
    assert.equal(apex.registrationDate, '2001-11-10');

    // HE.net 委派的多级反向区
    const zone = m.getInfo('1.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa');
    assert.equal(zone.isPermanent, true);
    assert.equal(zone.isFreeSubdomain, true);
    assert.equal(zone.parent, 'ip6.arpa');
  });

  it('总后缀数符合预期', () => {
    assert.equal(m.size, DEFAULT_SUFFIXES.length);
    assert.equal(m.size, 20);
  });

  it('list() 会带出 lookup 配置', () => {
    const withLookup = m.list().filter(e => e.lookup);
    assert.equal(withLookup.length, 16);
  });
});

describe('WhoisService 免费域名合并', () => {
  const cache = { get: async () => null, set: async () => {} };

  const makeService = lookupImpl => new WhoisService('', cache, new FreeDomainManager(), {
    freeLookup: { lookup: lookupImpl }
  });

  it('实时查询成功时用真实到期日覆盖兜底值', async () => {
    const svc = makeService(async () => ({
      registered: true, registrar: 'DigitalPlat One',
      registrationDate: '2024-05-30', expirationDate: '2027-05-30',
      nameServers: ['magali.ns.cloudflare.com'], status: 'active', source: 'rdap'
    }));
    const r = await svc.query('niege.dpdns.org');
    assert.equal(r.expirationDate, '2027-05-30');
    assert.equal(r.registrationDate, '2024-05-30');
    assert.equal(r.liveLookup, true);
    assert.equal(r.dataSource, 'rdap');
    assert.equal(r.isFree, undefined); // 合并层不负责免费标记，由 state 层补
    assert.equal(r.isPermanent, false);
  });

  it('实时查询失败时回退到 Auto-Renewal，且不设置 whoisError', async () => {
    const svc = makeService(async () => ({ error: 'RDAP HTTP 503' }));
    const r = await svc.query('niege.dpdns.org');
    assert.equal(r.expirationDate, 'Auto-Renewal');
    assert.equal(r.whoisError, undefined);
    assert.equal(r.lookupError, 'RDAP HTTP 503');
    assert.equal(r.dataSource, 'registry');
  });

  it('域名未注册时标记 lookupSkipped', async () => {
    const svc = makeService(async () => ({ registered: false, status: 'not-registered' }));
    const r = await svc.query('nope.us.ci');
    assert.equal(r.lookupSkipped, true);
    assert.equal(r.lookupError, null);
  });

  it('没有 lookup 配置的后缀直接返回元数据', async () => {
    let called = false;
    const svc = makeService(async () => { called = true; return null; });
    const r = await svc.query('demo.eu.org');
    assert.equal(r.isPermanent, true);
    assert.equal(called, false);
  });

  it('未注册域名不是免费域名时走通用 WHOIS 分支', async () => {
    const svc = makeService(async () => ({ registered: true }));
    const r = await svc.query('example.com');
    assert.equal(r.whoisError, 'WHOIS proxy not configured');
  });
});
