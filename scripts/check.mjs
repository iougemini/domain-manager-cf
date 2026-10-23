// 一键自检：单测 → 端到端冒烟 → 打包。
//
// 为什么不用 `npm test && npm run smoke && npm run bundle`：
// Windows 下 npm 的脚本 runner 跑带 `&&` 和带引号 glob 的复合命令会偶发
// Segmentation fault（tests 已经跑完，后续步骤却没执行）。用 Node 顺序 spawn
// 就绕开了这层 shell 解析，输出也更清楚。
import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

// 动态列测试文件，新加用例不用改这里
const testFiles = readdirSync(join(root, 'test'))
  .filter(f => f.endsWith('.test.js'))
  .sort()
  .map(f => 'test/' + f);

const steps = [
  ['单元测试', process.execPath, ['--test', ...testFiles]],
  ['端到端冒烟', process.execPath, ['scripts/smoke.mjs']],
  // 用 node 跑 esbuild 的 JS 入口：node_modules/.bin/esbuild 在 Windows 上是
  // 一个 sh 脚本，直接 spawn 会失败（需要 shell:true 才能解析）
  ['esbuild 打包', process.execPath, [
    join(root, 'node_modules/esbuild/bin/esbuild'),
    'src/index.js', '--bundle', '--format=esm', '--platform=browser', '--target=es2022',
    '--external:cloudflare:sockets', '--outfile=dist/worker.js', '--log-level=warning'
  ]]
];

let failed = 0;
for (const [name, cmd, args] of steps) {
  process.stdout.write(`\n▶ ${name} … `);
  const r = spawnSync(cmd, args, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' });
  const out = (r.stdout || '') + (r.stderr || '');

  if (r.status === 0) {
    // 单测只摘总数，避免刷屏
    const m = out.match(/# tests (\d+)[\s\S]*?# pass (\d+)[\s\S]*?# fail (\d+)/);
    if (m) process.stdout.write(`${m[2]}/${m[1]} 通过\n`);
    else if (/项通过/.test(out)) process.stdout.write(out.match(/(\d+\/\d+) 项通过/)[1] + ' 项通过\n');
    else process.stdout.write('通过\n');
  } else {
    failed++;
    process.stdout.write('失败\n');
    console.log(out.split('\n').slice(-40).join('\n'));
  }
}

console.log('\n' + (failed ? `${failed} 个步骤失败` : '全部通过'));
process.exit(failed ? 1 : 0);
