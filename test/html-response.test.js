// 页面响应的条件请求行为
//
// 页面原本是 Cache-Control: no-store，每次导航都要重下整页。改成 ETag +
// no-cache 之后，"数据没变"的访问只回几十字节。这里盯三件事：
//   1. 首次请求照常 200，并带上 ETag
//   2. 带着同一个 ETag 回来 → 304 且没有 body
//   3. 内容变了 → ETag 必须跟着变（否则用户永远看不到新数据）

import test from 'node:test';
import assert from 'node:assert/strict';
import { htmlResponse } from '../src/handlers.js';

const URL_BASE = 'https://demo.test/admin';

function request(headers = {}) {
  return new Request(URL_BASE, { headers });
}

test('首次请求返回 200 并带 ETag', async () => {
  const res = htmlResponse(request(), '<html>hi</html>');

  assert.equal(res.status, 200);
  assert.equal(await res.text(), '<html>hi</html>');
  assert.ok(res.headers.get('etag'), '缺少 ETag');
  assert.match(res.headers.get('cache-control'), /no-cache/);
  assert.ok(!/no-store/.test(res.headers.get('cache-control')), '不该再用 no-store');
});

test('ETag 相同时返回 304 且无响应体', async () => {
  const first = htmlResponse(request(), '<html>hi</html>');
  const etag = first.headers.get('etag');

  const second = htmlResponse(request({ 'if-none-match': etag }), '<html>hi</html>');

  assert.equal(second.status, 304);
  assert.equal(await second.text(), '');
  assert.equal(second.headers.get('etag'), etag);
});

test('内容变化后 ETag 不同，不会错误地返回 304', async () => {
  const first = htmlResponse(request(), '<html>a</html>');
  const etag = first.headers.get('etag');

  const changed = htmlResponse(request({ 'if-none-match': etag }), '<html>b</html>');

  assert.equal(changed.status, 200);
  assert.notEqual(changed.headers.get('etag'), etag);
});

test('ETag 支持逗号分隔的多值', async () => {
  const first = htmlResponse(request(), '<html>hi</html>');
  const etag = first.headers.get('etag');

  const res = htmlResponse(request({ 'if-none-match': '"other", ' + etag }), '<html>hi</html>');
  assert.equal(res.status, 304);
});

test('Vary: Cookie，避免不同会话共用缓存', async () => {
  const res = htmlResponse(request(), '<html>hi</html>');
  assert.match(res.headers.get('vary') || '', /Cookie/i);
});
