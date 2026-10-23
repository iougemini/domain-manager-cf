// 版本号一致性
//
// 版本号在四个地方各写了一遍：src/config.js（运行时真实值）、package.json、
// README 的 badge 与 UA 示例、CHANGELOG 的最新条目。发版时漏改任何一处，
// 页面不会有任何报错——只是对外显示旧版本，或者文档里写着上一个版本的行为。
//
// 这类"改了但没全改"的问题靠人眼复查不可靠，交给测试盯。

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { CONFIG } from '../src/config.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function read(relative) {
  return readFileSync(join(ROOT, relative), 'utf8');
}

const VERSION = CONFIG.VERSION;

test('CONFIG.VERSION 是合法的 x.y.z', () => {
  assert.match(VERSION, /^\d+\.\d+\.\d+$/);
});

test('package.json 的 version 与 CONFIG.VERSION 一致', () => {
  const pkg = JSON.parse(read('package.json'));
  assert.equal(
    pkg.version,
    VERSION,
    `package.json 是 ${pkg.version}，代码里是 ${VERSION}`
  );
});

test('README 的版本徽章与 CONFIG.VERSION 一致', () => {
  const readme = read('README.md');
  const match = readme.match(/img\.shields\.io\/badge\/version-([\d.]+)-/);

  // badge 被删掉时不能算通过，否则这条断言会静默失效
  assert.ok(match, 'README 里找不到版本徽章');
  assert.equal(match[1], VERSION, `README 徽章是 ${match[1]}，代码里是 ${VERSION}`);
});

test('README 里的 UA 示例与 CONFIG.VERSION 一致', () => {
  const matches = [...read('README.md').matchAll(/DSMC\/(\d+\.\d+\.\d+)/g)];
  assert.ok(matches.length > 0, 'README 里找不到 UA 示例');

  for (const [, found] of matches) {
    assert.equal(found, VERSION, `README 文档里的 UA 版本是 ${found}，代码里是 ${VERSION}`);
  }
});

test('CHANGELOG 的最新条目与 CONFIG.VERSION 一致', () => {
  const first = read('CHANGELOG.md').match(/^## \[(\d+\.\d+\.\d+)\]/m);
  assert.ok(first, 'CHANGELOG 里找不到版本条目');
  assert.equal(
    first[1],
    VERSION,
    `CHANGELOG 最新是 ${first[1]}，代码里是 ${VERSION}`
  );
});

test('README 声明支持的 Node 版本不低于实际使用的最低特性', () => {
  // 项目用了 node:test / node:fs 的现代 API，README 写 18+，这里只防它被改低
  const match = read('README.md').match(/Node\.js (\d+) 或更高/);
  assert.ok(match, 'README 里找不到 Node 版本要求');
  assert.ok(Number(match[1]) >= 18, `README 写的 Node 版本是 ${match[1]}，低于项目实际要求`);
});
