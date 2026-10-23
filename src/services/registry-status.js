// 注册局状态（EPP status）解析
//
// RDAP / WHOIS 的 `status` 字段返回的是 EPP 状态码，它描述域名在注册局眼里的
// 处境，比"还有多少天到期"更紧急：
//
//   clientHold     注册商暂停解析 —— 邮箱未验证、欠费、争议，站点会直接打不开
//   serverHold     注册局暂停解析 —— 通常因为滥用投诉或资料造假
//   pendingDelete  已进入删除流程，几天内域名就没了
//   redemptionPeriod  已过期，处在赎回期，赎回价通常几十到上百美元
//
// 但这里有个陷阱：**绝大多数正常域名都带 clientTransferProhibited**
// （禁止转移，防盗保护），有些还带 clientDeleteProhibited / clientUpdateProhibited。
// 把它们当告警，会让整张表全部飘红，告警就没人看了。
// 所以本模块只把真正影响解析/持有的状态标成危险，其余归为"正常保护状态"。

/**
 * EPP 状态码字典。键是归一化后的形式（小写、去掉空格与连字符）。
 * level 语义：
 *   danger 域名已不可用或即将消失，需要立刻处理
 *   warn   处在过渡期，多半会自己好，但要盯
 *   info   操作进行中，纯信息
 *   ok     正常，或防盗保护（不要告警）
 */
const CODES = {
  clienthold: { level: 'danger', label: '注册商暂停解析' },
  serverhold: { level: 'danger', label: '注册局暂停解析' },
  pendingdelete: { level: 'danger', label: '即将删除' },
  redemptionperiod: { level: 'danger', label: '赎回期' },
  pendingrestore: { level: 'warn', label: '恢复处理中' },
  autorenewperiod: { level: 'warn', label: '自动续费宽限期' },
  pendingtransfer: { level: 'info', label: '转移中' },
  pendingrenew: { level: 'info', label: '续费处理中' },
  pendingcreate: { level: 'info', label: '创建处理中' },
  pendingupdate: { level: 'info', label: '更新处理中' },
  clienttransferprohibited: { level: 'ok', label: '禁止转移' },
  servertransferprohibited: { level: 'ok', label: '禁止转移' },
  clientdeleteprohibited: { level: 'ok', label: '禁止删除' },
  serverdeleteprohibited: { level: 'ok', label: '禁止删除' },
  clientupdateprohibited: { level: 'ok', label: '禁止更新' },
  serverupdateprohibited: { level: 'ok', label: '禁止更新' },
  clientrenewprohibited: { level: 'ok', label: '禁止续费' },
  associated: { level: 'ok', label: '已关联' },
  active: { level: 'ok', label: '正常' },
  ok: { level: 'ok', label: '正常' }
};

const LEVEL_WEIGHT = { ok: 0, info: 1, warn: 2, danger: 3 };

/**
 * 把各种写法归一成一个键。
 * RDAP 返回 "client transfer prohibited"，ICANN 规范写法是 "clientTransferProhibited"，
 * 有些 WHOIS 服务返回全大写或带下划线 —— 这些都要认成同一个码。
 */
export function normalizeStatusCode(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[\s_-]+/g, '');
}

/**
 * 拆分原始 status。
 * RDAP 常见是数组，也见过用 ", " 拼好的字符串，还可能混着人类可读的描述。
 */
function splitStatus(input) {
  if (input === null || input === undefined) return [];
  if (Array.isArray(input)) return input.filter(Boolean);
  if (typeof input === 'object') return [];
  return String(input).split(/[,;]+/).map(s => s.trim()).filter(Boolean);
}

/**
 * @param {string|string[]|null|undefined} input
 * @returns {{
 *   level: 'ok'|'info'|'warn'|'danger',
 *   codes: Array<{code: string, level: string, label: string}>,
 *   dangerCodes: string[],
 *   labels: string[],
 *   unknown: string[],
 *   suspended: boolean
 * }}
 */
export function parseRegistryStatus(input) {
  const raw = splitStatus(input);
  const codes = [];
  const unknown = [];

  for (const item of raw) {
    const key = normalizeStatusCode(item);
    if (!key) continue;
    const known = CODES[key];
    if (known) {
      // 去重：RDAP 有时把同一个码重复返回
      if (!codes.some(c => c.code === key)) {
        codes.push({ code: key, level: known.level, label: known.label });
      }
    } else {
      unknown.push(String(item).trim());
    }
  }

  let level = 'ok';
  for (const c of codes) {
    if (LEVEL_WEIGHT[c.level] > LEVEL_WEIGHT[level]) level = c.level;
  }

  const dangerCodes = codes.filter(c => c.level === 'danger').map(c => c.code);

  return {
    level,
    codes,
    dangerCodes,
    labels: codes.map(c => c.label),
    unknown,
    // 暂停解析是唯一会直接让站点打不开的一类，单独给个布尔，UI 与通知要区别对待
    suspended: dangerCodes.some(c => c === 'clienthold' || c === 'serverhold')
  };
}

/** 该状态是否需要出现在"需要处理"清单里 */
export function isActionable(status) {
  return Boolean(status) && (status.level === 'danger' || status.level === 'warn');
}
