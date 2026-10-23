import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { parseWhoisText, parseWhoisDate, FreeDomainLookup } from '../src/services/free-domain-lookup.js';
import { FreeDomainManager } from '../src/managers/free-domain.js';
import { normalizeSuffixPayload } from '../src/handlers.js';
import {
  upsertEntry,
  dropEntry,
  loadFreeDomainEntries,
  saveFreeDomainEntries,
  invalidateFreeDomainConfig
} from '../src/managers/free-domain-store.js';

// whois.pp.ua 的真实响应（字段冒号后没有空格，这一点很容易解析错）
const PPUA_REGISTERED = `
Domain ID:1070071_PPUA-DRS
Domain Name:YUEDU.PP.UA
Created On:10-Oct-2022 06:55:49 UTC
Last Updated On:10-Sep-2026 05:12:23 UTC
Expiration Date:10-Oct-2027 06:55:49 UTC
Sponsoring Registrar:NIC.UA LLC (nic-mnt-cunic)
Status:serverDeleteProhibited
Registrant Name:Coleman Betty G
Admin Name:<not disclosed>
Name Server:JACK.NS.CLOUDFLARE.COM
Name Server:TEAGAN.NS.CLOUDFLARE.COM

`;

const PPUA_APEX = `
Domain ID:69013_UA-DRS
Domain Name:PP.UA
Created On:06-Nov-2009 11:56:47 UTC
Expiration Date:UNKNOWN
Sponsoring Registrar:Service Online LLC (root-mnt-cunic)
Status:ok
Name Server:NS1.UADNS.COM
`;

describe('parseWhoisText', () => {
  it('解析 pp.ua 的真实文本响应', () => {
    const r = parseWhoisText(PPUA_REGISTERED);
    assert.equal(r.registered, true);
    assert.equal(r.registrationDate, '2022-10-10');
    assert.equal(r.expirationDate, '2027-10-10');
    assert.equal(r.source, 'whois');
  });

  it('去掉注册商后面的 handle', () => {
    const r = parseWhoisText(PPUA_REGISTERED);
    assert.equal(r.registrar, 'NIC.UA LLC');
  });

  it('收集多个 nameserver 并转小写', () => {
    const r = parseWhoisText(PPUA_REGISTERED);
    assert.deepEqual(r.nameServers, ['jack.ns.cloudflare.com', 'teagan.ns.cloudflare.com']);
  });

  it('未注册返回 registered=false，而不是解析失败', () => {
    const r = parseWhoisText('No entries found.\r\n\r\n');
    assert.equal(r.registered, false);
    assert.equal(r.status, 'not-registered');
  });

  it('Expiration Date:UNKNOWN 视为未知日期', () => {
    const r = parseWhoisText(PPUA_APEX);
    assert.equal(r.registered, true);
    assert.equal(r.expirationDate, 'Unknown');
    assert.equal(r.registrationDate, '2009-11-06');
  });

  it('空输入返回 null', () => {
    assert.equal(parseWhoisText(''), null);
    assert.equal(parseWhoisText(null), null);
  });

  it('缺少 Domain Name 的文本不当作有效结果', () => {
    assert.equal(parseWhoisText('Status: ok\nRegistrar: foo'), null);
  });
});

describe('parseWhoisDate', () => {
  it('支持 DD-Mon-YYYY', () => {
    assert.equal(parseWhoisDate('10-Oct-2022 06:55:49 UTC'), '2022-10-10');
    assert.equal(parseWhoisDate('1-jan-2024'), '2024-01-01');
  });

  it('支持 ISO', () => {
    assert.equal(parseWhoisDate('2024-05-30T00:00:00Z'), '2024-05-30');
  });

  it('非法值返回 null', () => {
    assert.equal(parseWhoisDate('UNKNOWN'), null);
    assert.equal(parseWhoisDate(''), null);
    assert.equal(parseWhoisDate(undefined), null);
  });
});

describe('pp.ua 接入注册表', () => {
  it('pp.ua 配置了 whois/TCP 查询', () => {
    const m = new FreeDomainManager();
    const info = m.getInfo('yuedu.pp.ua');
    assert.ok(info);
    assert.equal(info.lookup.type, 'whois');
    assert.equal(info.lookup.endpoint, 'whois.pp.ua:43');
    assert.equal(info.renewMode, 'manual');
  });

  it('查询失败时回退为人工维护（不会静默变成自动续期）', () => {
    const m = new FreeDomainManager();
    const info = m.getInfo('yuedu.pp.ua');
    assert.equal(info.expirationDate, null);
    assert.equal(info.isPermanent, false);
  });
});

describe('公益域名', () => {
  const m = new FreeDomainManager();

  it('is-a.dev / js.org / eu.org 都按永久处理', () => {
    for (const d of ['foo.is-a.dev', 'bar.js.org', 'baz.eu.org']) {
      assert.equal(m.isFree(d), true, d);
      assert.equal(m.isPermanent(d), true, d);
    }
  });

  it('自动匹配注册商', () => {
    assert.equal(m.getInfo('foo.is-a.dev').registrar, 'is-a.dev');
    assert.equal(m.getInfo('bar.js.org').registrar, 'JS.ORG');
    assert.equal(m.getInfo('baz.eu.org').registrar, 'NIC.EU.ORG');
  });

  it('子域名没有伪造的注册日期', () => {
    assert.equal(m.getInfo('foo.is-a.dev').registrationDate, 'N/A');
  });

  it('category 标记为 public', () => {
    assert.equal(m.getInfo('foo.is-a.dev').category, 'public');
    assert.equal(m.getInfo('foo.us.kg').category, 'free');
  });
});

describe('禁用条目', () => {
  it('KV 的 disabled 标记让内置后缀失效，但仍能在列表里看到', () => {
    const m = new FreeDomainManager({ kvEntries: [{ suffix: 'eu.org', disabled: true }] });

    assert.equal(m.isFree('foo.eu.org'), false);
    const entry = m.listAll().find(e => e.suffix === 'eu.org');
    assert.ok(entry);
    assert.equal(entry.disabled, true);
    // 禁用不应该丢掉内置的注册商信息
    assert.equal(entry.registrar, 'NIC.EU.ORG');
  });

  it('禁用后 size 不把它算进去', () => {
    const base = new FreeDomainManager().size;
    const m = new FreeDomainManager({ kvEntries: [{ suffix: 'eu.org', disabled: true }] });
    assert.equal(m.size, base - 1);
  });
});

describe('FreeDomainLookup · WHOIS/TCP', () => {
  const spec = { type: 'whois', endpoint: 'whois.pp.ua:43' };

  it('注入 transport 后能拿到真实日期', async () => {
    let seen = null;
    const lookup = new FreeDomainLookup({
      whoisTransport: async (host, port, query) => {
        seen = { host, port, query };
        return PPUA_REGISTERED;
      }
    });

    const r = await lookup.lookup('yuedu.pp.ua', spec);
    assert.equal(r.expirationDate, '2027-10-10');
    assert.deepEqual(seen, { host: 'whois.pp.ua', port: 43, query: 'yuedu.pp.ua' });
  });

  it('没有 transport 时降级为 error，不抛异常', async () => {
    const lookup = new FreeDomainLookup({});
    const r = await lookup.lookup('yuedu.pp.ua', spec);
    assert.ok(r.error);
  });

  it('transport 抛错时降级为 error', async () => {
    const lookup = new FreeDomainLookup({
      whoisTransport: async () => { throw new Error('connect ECONNREFUSED'); }
    });
    const r = await lookup.lookup('yuedu.pp.ua', spec);
    assert.match(r.error, /ECONNREFUSED/);
  });

  it('endpoint 省略端口时默认 43', async () => {
    let port = null;
    const lookup = new FreeDomainLookup({
      whoisTransport: async (host, p) => { port = p; return PPUA_REGISTERED; }
    });
    await lookup.lookup('yuedu.pp.ua', { type: 'whois', endpoint: 'whois.pp.ua' });
    assert.equal(port, 43);
  });
});

describe('KV 配置存储', () => {
  function fakeKV() {
    const store = new Map();
    return {
      store,
      async get(key) { return store.has(key) ? store.get(key) : null; },
      async put(key, value) { store.set(key, value); }
    };
  }

  it('upsertEntry 同后缀只保留一条', () => {
    const out = upsertEntry(
      [{ suffix: 'a.dev', renew: 'auto' }, { suffix: 'b.dev' }],
      { suffix: 'A.dev', renew: 'permanent' }
    );
    assert.equal(out.length, 2);
    assert.equal(out.find(e => e.suffix === 'A.dev').renew, 'permanent');
  });

  it('dropEntry 按后缀删除（大小写不敏感）', () => {
    const out = dropEntry([{ suffix: 'a.dev' }, { suffix: 'b.dev' }], 'A.DEV');
    assert.deepEqual(out.map(e => e.suffix), ['b.dev']);
  });

  it('save 后 load 能读到，且 60 秒内走缓存', async () => {
    const kv = fakeKV();
    invalidateFreeDomainConfig();

    await saveFreeDomainEntries(kv, [{ suffix: 'x.dev', renew: 'auto' }]);
    const first = await loadFreeDomainEntries(kv);
    assert.equal(first.length, 1);

    // 绕过缓存直接改 KV：缓存期内仍返回旧值，这正是"60 秒生效"的含义
    kv.store.set('config:free-domains', JSON.stringify([]));
    const cached = await loadFreeDomainEntries(kv);
    assert.equal(cached.length, 1);

    invalidateFreeDomainConfig();
    const fresh = await loadFreeDomainEntries(kv);
    assert.equal(fresh.length, 0);
  });

  it('KV 里是坏 JSON 时返回空数组而不是抛错', async () => {
    const kv = fakeKV();
    kv.store.set('config:free-domains', '{not json');
    invalidateFreeDomainConfig();
    assert.deepEqual(await loadFreeDomainEntries(kv), []);
  });

  it('未绑定 KV 时返回空数组', async () => {
    invalidateFreeDomainConfig();
    assert.deepEqual(await loadFreeDomainEntries(null), []);
  });
});

describe('normalizeSuffixPayload（白名单写入校验）', () => {
  it('归一化大小写与首尾点号', () => {
    const e = normalizeSuffixPayload({ suffix: ' .Is-A.Dev. ' });
    assert.equal(e.suffix, 'is-a.dev');
  });

  it('续期模式默认 auto', () => {
    assert.equal(normalizeSuffixPayload({ suffix: 'a.dev' }).renew, 'auto');
  });

  it('拒绝非法后缀', () => {
    for (const bad of ['', 'http://x', 'a b', 'x..y', '-']) {
      assert.throws(() => normalizeSuffixPayload({ suffix: bad }), /后缀格式不正确/, bad);
    }
  });

  it('拒绝未知续期模式', () => {
    assert.throws(() => normalizeSuffixPayload({ suffix: 'a.dev', renew: 'forever' }), /续期模式/);
  });

  it('选了查询方式却没填端点时报错', () => {
    assert.throws(() => normalizeSuffixPayload({ suffix: 'a.dev', lookupType: 'rdap' }), /必须填写端点/);
  });

  it('拒绝未知查询类型', () => {
    assert.throws(() => normalizeSuffixPayload({ suffix: 'a.dev', lookupType: 'ftp', endpoint: 'x' }), /查询方式/);
  });

  it('WHOIS/TCP 端点必须是 host 或 host:port', () => {
    assert.throws(
      () => normalizeSuffixPayload({ suffix: 'a.dev', lookupType: 'whois', endpoint: 'https://x/y' }),
      /WHOIS\/TCP 端点/
    );
    const ok = normalizeSuffixPayload({ suffix: 'a.dev', lookupType: 'whois', endpoint: 'whois.pp.ua:43' });
    assert.deepEqual(ok.lookup, { type: 'whois', endpoint: 'whois.pp.ua:43' });
  });

  it('不填查询方式时 lookup 为空（只用元数据）', () => {
    assert.equal(normalizeSuffixPayload({ suffix: 'a.dev' }).lookup, undefined);
  });
});

