import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { FreeDomainManager, DEFAULT_SUFFIXES, parseSuffixConfig } from '../src/managers/free-domain.js';

describe('FreeDomainManager 内置白名单', () => {
  it('默认载入全部内置后缀', () => {
    const m = new FreeDomainManager();
    assert.equal(m.size, DEFAULT_SUFFIXES.length);
  });

  it('识别二级子域名', () => {
    const m = new FreeDomainManager();
    assert.equal(m.isFree('demo.eu.org'), true);
    assert.equal(m.isFree('demo.us.kg'), true);
    assert.equal(m.isFree('a.b.pp.ua'), true);
  });

  it('识别 apex 本身', () => {
    const m = new FreeDomainManager();
    assert.equal(m.isFree('eu.org'), true);
    assert.equal(m.isFree('dpdns.org'), true);
  });

  it('不误判相似域名', () => {
    const m = new FreeDomainManager();
    assert.equal(m.isFree('notau.org'), false);
    assert.equal(m.isFree('eu.org.example.com'), false);
    assert.equal(m.isFree('example.com'), false);
    assert.equal(m.isFree(''), false);
    assert.equal(m.isFree(null), false);
  });

  it('大小写与结尾点号归一化', () => {
    const m = new FreeDomainManager();
    assert.equal(m.isFree('Demo.EU.ORG'), true);
    assert.equal(m.isFree('demo.eu.org.'), true);
  });

  it('isPermanent 只对 renew=permanent 生效', () => {
    const m = new FreeDomainManager();
    assert.equal(m.isPermanent('demo.eu.org'), true);
    assert.equal(m.isPermanent('eu.org'), true);
    assert.equal(m.isPermanent('demo.us.kg'), false);
    assert.equal(m.isPermanent('example.com'), false);
  });

  it('isAutoRenew 覆盖自动续期的免费域名', () => {
    const m = new FreeDomainManager();
    assert.equal(m.isAutoRenew('demo.us.kg'), true);
    assert.equal(m.isAutoRenew('demo.dpdns.org'), true);
    assert.equal(m.isAutoRenew('demo.eu.org'), false);
    // pp.ua 需要每年人工续期，查不到到期日时不能被当成自动续期掩盖过去
    assert.equal(m.isAutoRenew('demo.pp.ua'), false);
  });
});

describe('FreeDomainManager.getInfo 向后兼容', () => {
  it('子域名不伪造注册日期', () => {
    const m = new FreeDomainManager();
    const info = m.getInfo('demo.eu.org');
    assert.equal(info.registrationDate, 'N/A');
    assert.equal(info.level, 'subdomain');
    assert.equal(info.parent, 'eu.org');
    assert.equal(info.isFreeSubdomain, true);
  });

  it('apex 返回父域注册日期', () => {
    const m = new FreeDomainManager();
    const info = m.getInfo('eu.org');
    assert.equal(info.registrationDate, '1996-04-29');
    assert.equal(info.level, 'apex');
    assert.equal(info.isFreeSubdomain, false);
    assert.equal(info.parent, null);
  });

  it('自动续期域名输出 Auto-Renewal 占位，永久域名输出 null', () => {
    const m = new FreeDomainManager();
    assert.equal(m.getInfo('demo.us.kg').expirationDate, 'Auto-Renewal');
    assert.equal(m.getInfo('demo.eu.org').expirationDate, null);
  });

  it('未匹配返回 null', () => {
    const m = new FreeDomainManager();
    assert.equal(m.getInfo('example.com'), null);
  });
});

describe('FreeDomainManager 配置覆盖', () => {
  it('支持追加新后缀（字符串）', () => {
    const m = new FreeDomainManager({ overrides: 'foo.dev' });
    assert.equal(m.isFree('demo.foo.dev'), true);
    assert.equal(m.size, DEFAULT_SUFFIXES.length + 1);
  });

  it('支持追加新后缀（JSON 数组）', () => {
    const m = new FreeDomainManager({
      overrides: '[{"suffix":"bar.dev","registrar":"EXAMPLE","renew":"permanent"}]'
    });
    assert.equal(m.isFree('x.bar.dev'), true);
    assert.equal(m.isPermanent('x.bar.dev'), true);
  });

  it('覆盖同后缀的元数据', () => {
    const m = new FreeDomainManager({
      overrides: [{ suffix: 'eu.org', registrar: 'CUSTOM', renew: 'auto' }]
    });
    assert.equal(m.getInfo('demo.eu.org').registrar, 'CUSTOM');
    assert.equal(m.isPermanent('demo.eu.org'), false);
  });

  it('最长后缀优先匹配', () => {
    const m = new FreeDomainManager({
      entries: [
        { suffix: 'org', renew: 'auto' },
        { suffix: 'eu.org', renew: 'permanent' }
      ]
    });
    assert.equal(m.match('a.eu.org').entry.suffix, 'eu.org');
    assert.equal(m.match('a.example.org').entry.suffix, 'org');
  });

  it('允许一级免费 TLD（Freenom 类 .tk/.ml/.ga）', () => {
    const m = new FreeDomainManager({ entries: ['tk'] });
    assert.equal(m.isFree('demo.tk'), true);
    assert.equal(m.isFree('tk'), true);
  });

  it('拒绝非法后缀，避免污染匹配表', () => {
    const m = new FreeDomainManager({ entries: ['', ' ', 'a', '.dev.', 'a..b', 'bad suffix', 'x_y.dev'] });
    assert.equal(m.size, 1); // 只有 '.dev.' 去掉首尾点后是合法的 'dev'
    assert.equal(m.isFree('anything.dev'), true);
  });

  it('配置写错时不抛错，回退到内置表', () => {
    const m = new FreeDomainManager({ overrides: '[{bad json' });
    assert.equal(m.size, DEFAULT_SUFFIXES.length);
  });
});

describe('parseSuffixConfig', () => {
  it('空值返回空数组', () => {
    assert.deepEqual(parseSuffixConfig(undefined), []);
    assert.deepEqual(parseSuffixConfig(''), []);
    assert.deepEqual(parseSuffixConfig(null), []);
  });

  it('逗号分隔字符串', () => {
    assert.deepEqual(parseSuffixConfig('a.dev, b.dev ,c.dev'), ['a.dev', 'b.dev', 'c.dev']);
  });

  it('JSON 数组', () => {
    assert.deepEqual(parseSuffixConfig('["a.dev","b.dev"]'), ['a.dev', 'b.dev']);
  });

  it('已是数组时原样返回', () => {
    assert.deepEqual(parseSuffixConfig(['a.dev']), ['a.dev']);
  });

  it('JSON 结构非法时返回空数组', () => {
    assert.deepEqual(parseSuffixConfig('{"a":1}'), []);
  });
});

describe('list 输出', () => {
  it('按后缀字母序返回（管理页面直接可读）', () => {
    const suffixes = new FreeDomainManager().list().map(e => e.suffix);
    assert.deepEqual(suffixes, [...suffixes].sort((a, b) => a.localeCompare(b)));
  });

  it('匹配时仍然优先最长后缀', () => {
    const m = new FreeDomainManager({
      entries: [{ suffix: 'org', renew: 'auto' }, { suffix: 'eu.org', renew: 'permanent' }]
    });
    assert.equal(m.getInfo('a.eu.org').renewMode, 'permanent');
    assert.equal(m.getInfo('a.example.org').renewMode, 'auto');
  });

  it('返回副本，外部修改不影响内部状态', () => {
    const m = new FreeDomainManager();
    const first = m.list()[0];
    first.registrar = 'HACKED';
    assert.notEqual(m.list()[0].registrar, 'HACKED');
  });
});
