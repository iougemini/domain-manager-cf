// DNS 解析探测
//
// 到期日告诉你"这个域名还能用多久"，解析状态告诉你"它现在还能不能用"。
// 后者出事时通常没人通知你：域名过期、被注册商暂停、NS 被改走，
// 表现都是同一个 —— 解析不出来了。
//
// 这里用 DoH（DNS over HTTPS）查 A / AAAA / CNAME，不依赖系统解析器，
// 在 Workers 里就是一次普通 fetch。

export const DEFAULT_DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';

const TYPE_A = 1;
const TYPE_AAAA = 28;
const TYPE_CNAME = 5;

// DoH JSON 里的 Status 字段就是 DNS RCODE
const RCODE_NOERROR = 0;
const RCODE_NXDOMAIN = 3;

/**
 * 解析结果分类：
 *   ok        查到 A / AAAA / CNAME，域名解析正常
 *   nxdomain  域名不存在（NXDOMAIN）—— 过期删除、拼错、或被注册局摘除
 *   nodata    域名存在但没有任何地址记录 —— 通常是没配解析（囤域名属正常）
 *   error     查询本身失败（网络、超时、接口异常），不代表域名有问题
 *
 * nxdomain 和 nodata 要分开：前者是真事故，后者往往只是"这个域名还没用起来"。
 * 混成一个状态会让一堆囤着的域名天天报警。
 */
export class DnsChecker {
  /**
   * @param {object} [options]
   * @param {string} [options.endpoint] DoH 端点，默认 Cloudflare
   * @param {number} [options.timeoutMs] 单次查询超时
   * @param {Function} [options.fetchImpl] 便于测试注入
   */
  constructor(options = {}) {
    this.endpoint = options.endpoint || DEFAULT_DOH_ENDPOINT;
    this.timeoutMs = Number.isFinite(options.timeoutMs) && options.timeoutMs > 0
      ? options.timeoutMs
      : 5000;
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
  }

  async query(domain, type) {
    const url = `${this.endpoint}?name=${encodeURIComponent(domain)}&type=${type}`;
    const response = await this.fetchImpl(url, {
      headers: { accept: 'application/dns-json' },
      signal: AbortSignal.timeout(this.timeoutMs)
    });

    if (!response.ok) {
      throw new Error(`DoH HTTP ${response.status}`);
    }

    const data = await response.json();
    return {
      status: typeof data.Status === 'number' ? data.Status : RCODE_NOERROR,
      answers: Array.isArray(data.Answer) ? data.Answer : []
    };
  }

  /**
   * @param {string} domain
   * @returns {Promise<{status: string, records: object, error: string|null, checkedAt: string}>}
   */
  async check(domain) {
    const checkedAt = new Date().toISOString();
    const records = { a: [], aaaa: [], cname: [] };
    const failures = [];
    let sawNxdomain = false;
    let sawNoError = false;

    const tasks = [
      { type: TYPE_A, key: 'a' },
      { type: TYPE_AAAA, key: 'aaaa' },
      { type: TYPE_CNAME, key: 'cname' }
    ];

    const settled = await Promise.allSettled(
      tasks.map(t => this.query(domain, t.type))
    );

    settled.forEach((result, index) => {
      const { key } = tasks[index];

      if (result.status === 'rejected') {
        failures.push(result.reason && result.reason.message ? result.reason.message : '查询失败');
        return;
      }

      const { status, answers } = result.value;

      // NXDOMAIN 是权威否定：域名根本不存在，不必再看其他类型
      if (status === RCODE_NXDOMAIN) {
        sawNxdomain = true;
        return;
      }

      if (status === RCODE_NOERROR) {
        sawNoError = true;
        for (const answer of answers) {
          if (answer && answer.data && !records[key].includes(answer.data)) {
            records[key].push(answer.data);
          }
        }
      } else {
        failures.push(`RCODE ${status}`);
      }
    });

    const hasRecords = records.a.length > 0 || records.aaaa.length > 0 || records.cname.length > 0;

    if (hasRecords) {
      return { status: 'ok', records, error: null, checkedAt };
    }
    if (sawNxdomain) {
      return { status: 'nxdomain', records, error: null, checkedAt };
    }
    if (sawNoError) {
      return { status: 'nodata', records, error: null, checkedAt };
    }
    return {
      status: 'error',
      records,
      error: failures.length ? failures.join('; ') : '全部查询失败',
      checkedAt
    };
  }
}

/**
 * 巡检结果是否值得提醒。
 * nodata 不算问题 —— 大量域名是囤着没用的，把它们算进告警会淹掉真事故。
 */
export function isDnsProblem(result) {
  return Boolean(result) && (result.status === 'nxdomain');
}

export function describeDnsStatus(status) {
  switch (status) {
    case 'ok': return '解析正常';
    case 'nxdomain': return '解析丢失';
    case 'nodata': return '未配置解析';
    case 'error': return '探测失败';
    default: return '未探测';
  }
}
