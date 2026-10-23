// TCP WHOIS 通道（Cloudflare Workers 专用）
//
// Workers 里唯一能发起任意 TCP 连接的方式是 cloudflare:sockets 的 connect()。
// 把这段隔离在单独模块，好处是：
//   1. 只有这里依赖 workerd 内建模块，Node 单测完全不碰它（注入假 transport 即可）
//   2. 将来换实现（比如改成走 HTTP 代理）只改这一个文件
//
// 注意：esbuild 打包校验时需要 --external:cloudflare:sockets，
// wrangler 自身已把它当作内建模块处理，不需要额外配置。
import { connect } from 'cloudflare:sockets';

/**
 * 向 WHOIS 服务器发送一个查询并读回纯文本。
 * @param {string} host      例如 whois.pp.ua
 * @param {number} port      默认 43
 * @param {string} query     例如 yuedu.pp.ua
 * @param {number} timeoutMs 整体超时
 * @returns {Promise<string>}
 */
export async function tcpWhois(host, port, query, timeoutMs = 8000) {
  const socket = connect({ hostname: host, port });

  let timer = null;
  let timedOut = false;
  let text = '';

  try {
    const writer = socket.writable.getWriter();
    try {
      await writer.write(new TextEncoder().encode(query + '\r\n'));
    } finally {
      writer.releaseLock();
    }

    const reader = socket.readable.getReader();
    const decoder = new TextDecoder();

    // 用 close() 打断阻塞的 read()：比 Promise.race 干净，不会留下未处理的 rejection
    timer = setTimeout(() => {
      timedOut = true;
      try { socket.close(); } catch (e) { /* 已经关闭 */ }
    }, timeoutMs);

    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) text += decoder.decode(value, { stream: true });
        // WHOIS 响应通常只有几 KB，超过 64KB 视为异常并截断，防止内存放大
        if (text.length > 65536) break;
      }
    } finally {
      try { await reader.cancel(); } catch (e) { /* 已结束 */ }
    }
  } finally {
    if (timer) clearTimeout(timer);
    try { socket.close(); } catch (e) { /* 已关闭 */ }
  }

  if (timedOut && !text) {
    throw new Error(`WHOIS/TCP 查询超时（${host}:${port}）`);
  }

  return text;
}
