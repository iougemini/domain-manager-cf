// DNS 解析探测
//
// 核心不是"能不能查通"，而是"查不通的时候怎么定性"：
//   nxdomain 是域名没了（事故），nodata 是没配解析（常态），error 是探测器自己坏了。
// 三者混为一谈，要么漏报事故，要么天天误报。

import test from 'node:test';
import assert from 'node:assert/strict';
import { DnsChecker, isDnsProblem, describeDnsStatus } from '../src/services/dns-check.js';

/** 按 type 参数返回预设响应；值为 Error 时模拟网络失败 */
function fakeFetch(map) {
  return async (url) => {
    const type = Number(new URL(url).searchParams.get('type'));
    const preset = map[type];

    if (preset instanceof Error) throw preset;
    if (preset === undefined) {
      return { ok: true, json: async () => ({ Status: 0 }) };
    }
    if (preset.httpError) {
      return { ok: false, status: preset.httpError, json: async () => ({}) };
    }
    return { ok: true, json: async () => preset };
  };
}

const A = 1;
const CNAME = 5;
const AAAA = 28;

test('有 A 记录判定为解析正常', async () => {
  const checker = new DnsChecker({
    fetchImpl: fakeFetch({ [A]: { Status: 0, Answer: [{ data: '104.21.1.1' }] } })
  });
  const result = await checker.check('example.com');

  assert.equal(result.status, 'ok');
  assert.deepEqual(result.records.a, ['104.21.1.1']);
  assert.equal(result.error, null);
});

test('只有 AAAA 也算正常', async () => {
  const checker = new DnsChecker({
    fetchImpl: fakeFetch({ [AAAA]: { Status: 0, Answer: [{ data: '2606:4700::1' }] } })
  });
  assert.equal((await checker.check('example.com')).status, 'ok');
});

test('只有 CNAME 也算正常', async () => {
  const checker = new DnsChecker({
    fetchImpl: fakeFetch({ [CNAME]: { Status: 0, Answer: [{ data: 'target.example.net' }] } })
  });
  const result = await checker.check('example.com');
  assert.equal(result.status, 'ok');
  assert.deepEqual(result.records.cname, ['target.example.net']);
});

test('NXDOMAIN 判定为解析丢失', async () => {
  const checker = new DnsChecker({
    fetchImpl: fakeFetch({ [A]: { Status: 3 }, [AAAA]: { Status: 3 }, [CNAME]: { Status: 3 } })
  });
  const result = await checker.check('gone.example');
  assert.equal(result.status, 'nxdomain');
  assert.equal(isDnsProblem(result), true);
});

test('NOERROR 但无记录判定为未配置解析', async () => {
  const checker = new DnsChecker({
    fetchImpl: fakeFetch({ [A]: { Status: 0 }, [AAAA]: { Status: 0 }, [CNAME]: { Status: 0 } })
  });
  const result = await checker.check('idle.example');
  assert.equal(result.status, 'nodata');
  assert.equal(isDnsProblem(result), false, '囤着没配解析的域名不该报警');
});

test('全部查询失败判定为探测失败，而不是域名有问题', async () => {
  const checker = new DnsChecker({
    fetchImpl: fakeFetch({
      [A]: new Error('network down'),
      [AAAA]: new Error('network down'),
      [CNAME]: new Error('network down')
    })
  });
  const result = await checker.check('example.com');
  assert.equal(result.status, 'error');
  assert.match(result.error, /network down/);
  assert.equal(isDnsProblem(result), false, '探测器自己坏了，不能算域名事故');
});

test('部分类型失败但有记录时仍算正常', async () => {
  const checker = new DnsChecker({
    fetchImpl: fakeFetch({
      [A]: { Status: 0, Answer: [{ data: '1.2.3.4' }] },
      [AAAA]: new Error('timeout'),
      [CNAME]: new Error('timeout')
    })
  });
  const result = await checker.check('example.com');
  assert.equal(result.status, 'ok');
  assert.deepEqual(result.records.a, ['1.2.3.4']);
});

test('HTTP 错误归入探测失败', async () => {
  const checker = new DnsChecker({
    fetchImpl: fakeFetch({
      [A]: { httpError: 502 },
      [AAAA]: { httpError: 502 },
      [CNAME]: { httpError: 502 }
    })
  });
  const result = await checker.check('example.com');
  assert.equal(result.status, 'error');
  assert.match(result.error, /502/);
});

test('重复记录去重', async () => {
  const checker = new DnsChecker({
    fetchImpl: fakeFetch({
      [A]: { Status: 0, Answer: [{ data: '1.1.1.1' }, { data: '1.1.1.1' }] }
    })
  });
  assert.deepEqual((await checker.check('example.com')).records.a, ['1.1.1.1']);
});

test('请求带 accept: application/dns-json', async () => {
  let seen = null;
  const checker = new DnsChecker({
    fetchImpl: async (url, init) => {
      seen = init;
      return { ok: true, json: async () => ({ Status: 0 }) };
    }
  });
  await checker.check('example.com');
  assert.equal(seen.headers.accept, 'application/dns-json');
  assert.ok(seen.signal, '缺少超时信号');
});

test('结果带 checkedAt 时间戳', async () => {
  const checker = new DnsChecker({ fetchImpl: fakeFetch({}) });
  const result = await checker.check('example.com');
  assert.ok(!Number.isNaN(Date.parse(result.checkedAt)));
});

test('describeDnsStatus 覆盖四种状态', () => {
  assert.equal(describeDnsStatus('ok'), '解析正常');
  assert.equal(describeDnsStatus('nxdomain'), '解析丢失');
  assert.equal(describeDnsStatus('nodata'), '未配置解析');
  assert.equal(describeDnsStatus('error'), '探测失败');
  assert.equal(describeDnsStatus(undefined), '未探测');
});
