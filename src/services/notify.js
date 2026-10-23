// 到期提醒的通知模块
//
// 设计目标：一条到期摘要，能发到任何地方。
//
// 三个刻意的取舍：
// 1. **不引入 SDK**。飞书/钉钉/企业微信/Telegram/Bark/Server酱/PushPlus/Resend
//    全部是「一个 HTTPS 请求 + 一段 JSON」，为它们各装一个 npm 包既拖慢冷启动，
//    又会在 Workers 里引入 Node 依赖。这里全部手写请求体。
// 2. **构建请求与发送分离**。buildRequest 是纯函数（除了签名用的 HMAC），
//    单测可以直接断言 URL 和 body，不需要 mock fetch。
// 3. **发送失败不抛异常**。一个渠道挂了不能影响其它渠道，也不能让 cron 报错退出。
//
// 关于签名：飞书和钉钉的自定义机器人开启"加签"后，签名算法还不一样——
// 飞书是 `HMAC-SHA256(key = timestamp + "\n" + secret, data = "")`，
// 钉钉是 `HMAC-SHA256(key = secret, data = timestamp + "\n" + secret)`。
// 这两个反直觉的差异是踩过的坑，别"顺手统一"。

const encoder = new TextEncoder();

/* ---------------- 通用工具 ---------------- */

function base64(bytes) {
  let binary = '';
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i++) binary += String.fromCharCode(view[i]);
  return btoa(binary);
}

async function hmacSha256Base64(keyText, dataText) {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(keyText),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(dataText));
  return base64(signature);
}

function jsonInit(body, headers) {
  return {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(headers || {}) },
    body: JSON.stringify(body)
  };
}

/* ---------------- 日期与摘要 ---------------- */

/** 永久域名的年份哨兵：DNSHE 升级永久后到期日是 2999-12-31 这类值 */
export function isPermanentDate(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(value || ''));
  if (!m) return false;
  return Number(m[1]) >= 2900;
}

/**
 * 距今天数。按固定时区偏移算"今天"，避免 UTC 与本地日期跨天导致差一天。
 * @param {string} value 到期日
 * @param {number} offsetHours 时区偏移（默认 +8）
 * @param {number} [nowMs] 测试注入
 */
export function daysUntil(value, offsetHours = 8, nowMs = Date.now()) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(value || ''));
  if (!m) return null;

  const shifted = new Date(nowMs + offsetHours * 3600 * 1000);
  const today = Date.UTC(
    shifted.getUTCFullYear(),
    shifted.getUTCMonth(),
    shifted.getUTCDate()
  );
  const target = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  return Math.round((target - today) / 86400000);
}

export const DEFAULT_RULES = {
  daysBefore: 30,
  includeExpired: true,
  timezoneOffset: 8,
  maxItems: 60
};

/**
 * 构建到期摘要。
 * @param {Array} domains 原始域名记录（name / account / expirationDate / isPermanent）
 * @param {object} [rules]
 * @param {number} [nowMs]
 * @returns {{title: string, text: string, markdown: string, html: string, count: number, groups: object}}
 */
export function buildExpiryDigest(domains, rules = {}, nowMs = Date.now()) {
  const cfg = { ...DEFAULT_RULES, ...(rules || {}) };
  const daysBefore = Math.max(1, Math.min(365, Number(cfg.daysBefore) || 30));
  const offset = Number.isFinite(cfg.timezoneOffset) ? cfg.timezoneOffset : 8;

  const items = [];

  for (const d of domains || []) {
    if (!d || !d.name) continue;
    // 永久域名不参与告警：DNSHE 升级永久后到期日是 2999，算出来是 35 万天
    if (d.isPermanent || isPermanentDate(d.expirationDate)) continue;

    const days = daysUntil(d.expirationDate, offset, nowMs);
    if (days === null) continue;
    if (days > daysBefore) continue;
    if (days < 0 && !cfg.includeExpired) continue;

    items.push({
      name: d.name,
      account: d.account || '',
      registrar: d.registrar || '',
      expirationDate: String(d.expirationDate || '').slice(0, 10),
      days
    });
  }

  items.sort((a, b) => a.days - b.days);

  const expired = items.filter(i => i.days < 0);
  const week = items.filter(i => i.days >= 0 && i.days <= 7);
  const month = items.filter(i => i.days > 7);

  const shown = items.slice(0, Math.max(1, Number(cfg.maxItems) || 60));
  const stamp = new Date(nowMs + offset * 3600 * 1000)
    .toISOString().replace('T', ' ').slice(0, 16);

  const title = items.length
    ? 'DSMC 到期提醒 · ' + items.length + ' 个域名待处理'
    : 'DSMC 到期提醒 · 暂无需要处理的域名';

  const stat = '共 ' + items.length + ' 个待处理' +
    (expired.length ? '：已过期 ' + expired.length : '') +
    (week.length ? (expired.length ? '、' : '：') + '7 天内 ' + week.length : '') +
    (month.length ? ((expired.length || week.length) ? '、' : '：') + daysBefore + ' 天内 ' + month.length : '');

  const line = item => {
    const tail = item.days < 0 ? '超期 ' + Math.abs(item.days) + ' 天' : item.days + ' 天后到期';
    return item.name + ' — ' + tail +
      '（' + item.expirationDate + (item.account ? ' · ' + item.account : '') + '）';
  };

  const textLines = [
    'DSMC 域名到期提醒',
    '统计时间：' + stamp + ' (UTC' + (offset >= 0 ? '+' : '') + offset + ')',
    stat,
    ''
  ];
  if (expired.length) {
    textLines.push('[已过期 ' + expired.length + ']');
    expired.forEach(i => textLines.push('· ' + line(i)));
    textLines.push('');
  }
  if (week.length) {
    textLines.push('[7 天内到期 ' + week.length + ']');
    week.forEach(i => textLines.push('· ' + line(i)));
    textLines.push('');
  }
  if (month.length) {
    textLines.push('[' + daysBefore + ' 天内到期 ' + month.length + ']');
    month.forEach(i => textLines.push('· ' + line(i)));
    textLines.push('');
  }
  if (items.length > shown.length) {
    textLines.push('… 另有 ' + (items.length - shown.length) + ' 个域名未列出');
  }
  if (!items.length) textLines.push('所有域名都在安全期内，无需操作。');

  const mdLines = [
    '### ' + title,
    '',
    '**' + stat + '**',
    '',
    '_统计时间：' + stamp + ' (UTC' + (offset >= 0 ? '+' : '') + offset + ')_',
    ''
  ];
  const mdBlock = (label, list, tone) => {
    if (!list.length) return;
    mdLines.push('**' + label + '**');
    list.forEach(i => mdLines.push('- ' + (tone === 'danger' ? '🔴 ' : tone === 'warn' ? '🟠 ' : '🟡 ') + line(i)));
    mdLines.push('');
  };
  mdBlock('已过期', expired, 'danger');
  mdBlock('7 天内到期', week, 'warn');
  mdBlock(daysBefore + ' 天内到期', month, 'info');
  if (!items.length) mdLines.push('所有域名都在安全期内，无需操作。');

  const htmlRows = shown.map(i => {
    const color = i.days < 0 ? '#dc2626' : i.days <= 7 ? '#d97706' : '#2563eb';
    const label = i.days < 0 ? '超期 ' + Math.abs(i.days) + ' 天' : i.days + ' 天';
    return '<tr>' +
      '<td style="padding:8px 10px;border-bottom:1px solid #e5e7eb;font-family:ui-monospace,monospace">' + escapeHtml(i.name) + '</td>' +
      '<td style="padding:8px 10px;border-bottom:1px solid #e5e7eb;color:' + color + ';font-weight:600">' + label + '</td>' +
      '<td style="padding:8px 10px;border-bottom:1px solid #e5e7eb;color:#6b7280">' + escapeHtml(i.expirationDate) + '</td>' +
      '<td style="padding:8px 10px;border-bottom:1px solid #e5e7eb;color:#6b7280">' + escapeHtml(i.account) + '</td>' +
      '</tr>';
  }).join('');

  const html =
    '<div style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;max-width:640px">' +
      '<h2 style="font-size:18px;margin:0 0 6px">' + escapeHtml(title) + '</h2>' +
      '<p style="color:#6b7280;font-size:13px;margin:0 0 16px">' + escapeHtml(stat) + '<br>统计时间：' + stamp + ' (UTC' + (offset >= 0 ? '+' : '') + offset + ')</p>' +
      (items.length
        ? '<table style="width:100%;border-collapse:collapse;font-size:13px">' +
            '<thead><tr>' +
              '<th style="text-align:left;padding:8px 10px;border-bottom:1px solid #d1d5db;font-size:11px;color:#6b7280">域名</th>' +
              '<th style="text-align:left;padding:8px 10px;border-bottom:1px solid #d1d5db;font-size:11px;color:#6b7280">剩余</th>' +
              '<th style="text-align:left;padding:8px 10px;border-bottom:1px solid #d1d5db;font-size:11px;color:#6b7280">到期日</th>' +
              '<th style="text-align:left;padding:8px 10px;border-bottom:1px solid #d1d5db;font-size:11px;color:#6b7280">账户</th>' +
            '</tr></thead><tbody>' + htmlRows + '</tbody></table>'
        : '<p style="font-size:13px;color:#6b7280">所有域名都在安全期内，无需操作。</p>') +
      (items.length > shown.length
        ? '<p style="font-size:12px;color:#9ca3af">另有 ' + (items.length - shown.length) + ' 个域名未列出。</p>'
        : '') +
    '</div>';

  return {
    title,
    text: textLines.join('\n').trim(),
    markdown: mdLines.join('\n').trim(),
    html,
    count: items.length,
    // 名字列表用于"内容没变就别重复发"的去重判断
    names: shown.map(i => i.name),
    groups: { expired: expired.length, week: week.length, month: month.length }
  };
}

/**
 * 健康告警消息。
 *
 * 刻意与到期摘要分开成一条独立消息，不合并：
 *
 *   到期提醒是「提前预告」—— 还有 30 天，安排个时间处理就行
 *   健康告警是「现在出事了」—— 站点已经打不开，或者域名快没了
 *
 * 两者紧急程度差一个量级。混在一条里，用户扫一眼看到"30 个域名"，
 * 就不会注意到里面有一个是 clientHold。
 *
 * @param {Array<{name: string, level: string, problems: Array, registry?: object}>} alerts
 */
export function buildHealthDigest(alerts, nowMs = Date.now()) {
  const list = Array.isArray(alerts) ? alerts.filter(a => a && a.name) : [];
  const offset = 8;
  const stamp = new Date(nowMs + offset * 3600 * 1000)
    .toISOString().replace('T', ' ').slice(0, 16);

  const suspended = list.filter(a => a.registry && a.registry.suspended);
  const others = list.filter(a => !(a.registry && a.registry.suspended));

  const title = list.length
    ? 'DSMC 域名告警 · ' + list.length + ' 个域名异常'
    : 'DSMC 域名告警 · 一切正常';

  const detailOf = alert => {
    const parts = [];
    if (alert.registry && alert.registry.labels && alert.registry.labels.length) {
      parts.push(alert.registry.labels.join('、'));
    }
    if (alert.dnsLabel && alert.dns === 'nxdomain') {
      parts.push(alert.dnsLabel);
    }
    return parts.length ? parts.join('；') : '状态异常';
  };

  const line = alert => alert.name + ' — ' + detailOf(alert);

  const stat = suspended.length
    ? '共 ' + list.length + ' 个域名异常，其中 ' + suspended.length + ' 个已被暂停解析'
    : '共 ' + list.length + ' 个域名异常';

  const textLines = ['DSMC 域名告警', '统计时间：' + stamp + ' (UTC+' + offset + ')', stat, ''];

  if (suspended.length) {
    textLines.push('[暂停解析 ' + suspended.length + ']');
    suspended.forEach(a => textLines.push('· ' + line(a)));
    textLines.push('');
  }
  if (others.length) {
    textLines.push('[其他异常 ' + others.length + ']');
    others.forEach(a => textLines.push('· ' + line(a)));
    textLines.push('');
  }
  if (!list.length) textLines.push('所有域名的解析与注册局状态均正常。');

  const mdLines = ['### ' + title, '', '**' + stat + '**', '', '_统计时间：' + stamp + ' (UTC+' + offset + ')_', ''];
  if (suspended.length) {
    mdLines.push('**暂停解析（站点已不可用）**');
    suspended.forEach(a => mdLines.push('- 🔴 ' + line(a)));
    mdLines.push('');
  }
  if (others.length) {
    mdLines.push('**其他异常**');
    others.forEach(a => mdLines.push('- 🟠 ' + line(a)));
    mdLines.push('');
  }
  if (!list.length) mdLines.push('所有域名的解析与注册局状态均正常。');

  const htmlRows = list.map(a => {
    const isSuspended = Boolean(a.registry && a.registry.suspended);
    return '<tr>' +
      '<td style="padding:8px 10px;border-bottom:1px solid #e5e7eb;font-family:ui-monospace,monospace">' + escapeHtml(a.name) + '</td>' +
      '<td style="padding:8px 10px;border-bottom:1px solid #e5e7eb;color:' + (isSuspended ? '#dc2626' : '#d97706') + ';font-weight:600">' + escapeHtml(detailOf(a)) + '</td>' +
      '</tr>';
  }).join('');

  const html =
    '<div style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;max-width:640px">' +
      '<h2 style="font-size:18px;margin:0 0 6px">' + escapeHtml(title) + '</h2>' +
      '<p style="color:#6b7280;font-size:13px;margin:0 0 16px">' + escapeHtml(stat) + '<br>统计时间：' + stamp + ' (UTC+' + offset + ')</p>' +
      (list.length
        ? '<table style="width:100%;border-collapse:collapse;font-size:13px">' +
            '<thead><tr>' +
              '<th style="text-align:left;padding:8px 10px;border-bottom:1px solid #d1d5db;font-size:11px;color:#6b7280">域名</th>' +
              '<th style="text-align:left;padding:8px 10px;border-bottom:1px solid #d1d5db;font-size:11px;color:#6b7280">问题</th>' +
            '</tr></thead><tbody>' + htmlRows + '</tbody></table>'
        : '<p style="font-size:13px;color:#6b7280">所有域名的解析与注册局状态均正常。</p>') +
    '</div>';

  return {
    title,
    text: textLines.join('\n').trim(),
    markdown: mdLines.join('\n').trim(),
    html,
    count: list.length,
    // 指纹只取「域名 + 问题」：同一批异常不重复发，异常消失后再次出现要能重新发
    names: list.map(a => a.name + ':' + detailOf(a)),
    groups: { suspended: suspended.length, other: others.length }
  };
}

function escapeHtml(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ---------------- 渠道定义 ---------------- */

/**
 * 每个渠道：
 *   key/label/desc  — 页面展示
 *   fields          — 表单字段（页面据此动态生成，加渠道不用改前端）
 *   build(config, message, nowMs) — 返回 { url, init }
 *
 * message 形如 { title, text, markdown, html }
 */
export const CHANNELS = {
  webhook: {
    key: 'webhook',
    label: '通用 Webhook',
    desc: '向任意地址 POST 一段 JSON，适合自建服务或中间层转发',
    fields: [
      { name: 'url', label: 'Webhook 地址', placeholder: 'https://example.com/hook', required: true },
      { name: 'token', label: '鉴权 Header（可选）', placeholder: 'Authorization 的值', required: false }
    ],
    async build(config, message) {
      const headers = {};
      if (config.token) headers.Authorization = config.token;
      return {
        url: config.url,
        init: jsonInit({
          source: 'DSMC',
          event: 'domain.expiry',
          title: message.title,
          text: message.text,
          markdown: message.markdown,
          sentAt: new Date().toISOString()
        }, headers)
      };
    }
  },

  feishu: {
    key: 'feishu',
    label: '飞书机器人',
    desc: '群自定义机器人 Webhook，支持加签',
    fields: [
      { name: 'webhook', label: 'Webhook 地址', placeholder: 'https://open.feishu.cn/open-apis/bot/v2/hook/xxx', required: true },
      { name: 'secret', label: '签名密钥（可选）', placeholder: '开启「加签」后填写', required: false }
    ],
    async build(config, message, nowMs) {
      const body = {
        msg_type: 'text',
        content: { text: message.title + '\n\n' + message.text }
      };
      if (config.secret) {
        const timestamp = String(Math.floor((nowMs || Date.now()) / 1000));
        // 飞书的怪癖：secret 不是 HMAC 的 key，而是拼进 key 里，data 传空
        body.timestamp = timestamp;
        body.sign = await hmacSha256Base64(timestamp + '\n' + config.secret, '');
      }
      return { url: config.webhook, init: jsonInit(body) };
    }
  },

  dingtalk: {
    key: 'dingtalk',
    label: '钉钉机器人',
    desc: '群自定义机器人，支持加签',
    fields: [
      { name: 'accessToken', label: 'Access Token', placeholder: '机器人 Webhook 里的 access_token', required: true },
      { name: 'secret', label: '加签密钥（可选）', placeholder: 'SEC 开头的字符串', required: false }
    ],
    async build(config, message, nowMs) {
      const params = new URLSearchParams({ access_token: config.accessToken });
      if (config.secret) {
        const timestamp = String(nowMs || Date.now());
        const sign = await hmacSha256Base64(config.secret, timestamp + '\n' + config.secret);
        params.set('timestamp', timestamp);
        params.set('sign', sign);
      }
      return {
        url: 'https://oapi.dingtalk.com/robot/send?' + params.toString(),
        init: jsonInit({
          msgtype: 'markdown',
          markdown: { title: message.title, text: message.markdown }
        })
      };
    }
  },

  wecom: {
    key: 'wecom',
    label: '企业微信群机器人',
    desc: '群机器人 Webhook，支持 Markdown',
    fields: [
      { name: 'key', label: 'Webhook Key', placeholder: '机器人地址里的 key 参数', required: true }
    ],
    async build(config, message) {
      return {
        url: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=' + encodeURIComponent(config.key),
        init: jsonInit({
          msgtype: 'markdown',
          markdown: { content: message.markdown }
        })
      };
    }
  },

  telegram: {
    key: 'telegram',
    label: 'Telegram',
    desc: '通过 Bot 发送到指定会话',
    fields: [
      { name: 'token', label: 'Bot Token', placeholder: '123456:ABC-DEF…', required: true },
      { name: 'chatId', label: 'Chat ID', placeholder: '你的用户 ID 或群组 ID（-100…）', required: true }
    ],
    async build(config, message) {
      return {
        url: 'https://api.telegram.org/bot' + config.token + '/sendMessage',
        init: jsonInit({
          chat_id: config.chatId,
          text: message.title + '\n\n' + message.text,
          disable_web_page_preview: true
        })
      };
    }
  },

  serverchan: {
    key: 'serverchan',
    label: 'Server 酱',
    desc: '微信推送，SendKey 来自 sct.ftqq.com',
    fields: [
      { name: 'sendKey', label: 'SendKey', placeholder: 'SCT…', required: true }
    ],
    async build(config, message) {
      return {
        url: 'https://sctapi.ftqq.com/' + encodeURIComponent(config.sendKey) + '.send',
        init: {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ title: message.title, desp: message.markdown }).toString()
        }
      };
    }
  },

  pushplus: {
    key: 'pushplus',
    label: 'PushPlus',
    desc: '微信推送，支持 Markdown 模板',
    fields: [
      { name: 'token', label: 'Token', placeholder: 'pushplus 的 token', required: true }
    ],
    async build(config, message) {
      return {
        url: 'https://www.pushplus.plus/send',
        init: jsonInit({
          token: config.token,
          title: message.title,
          content: message.markdown,
          template: 'markdown'
        })
      };
    }
  },

  bark: {
    key: 'bark',
    label: 'Bark',
    desc: 'iOS 推送，支持自建服务器',
    fields: [
      { name: 'key', label: 'Device Key', placeholder: 'Bark App 里的推送 key', required: true },
      { name: 'server', label: '服务器（可选）', placeholder: 'https://api.day.app', required: false }
    ],
    async build(config, message) {
      const server = String(config.server || 'https://api.day.app').replace(/\/+$/, '');
      return {
        url: server + '/' + encodeURIComponent(config.key),
        init: jsonInit({
          title: message.title,
          body: message.text,
          group: 'DSMC'
        })
      };
    }
  },

  email: {
    key: 'email',
    label: '邮件（Resend）',
    desc: '通过 Resend API 发信，需要一个已验证的发件域名',
    fields: [
      { name: 'apiKey', label: 'Resend API Key', placeholder: 're_…', required: true },
      { name: 'from', label: '发件人', placeholder: 'DSMC <alert@yourdomain.com>', required: true },
      { name: 'to', label: '收件人', placeholder: 'a@x.com, b@y.com', required: true }
    ],
    async build(config, message) {
      const to = String(config.to || '')
        .split(/[,;\s]+/)
        .map(s => s.trim())
        .filter(Boolean);

      return {
        url: 'https://api.resend.com/emails',
        init: jsonInit({
          from: config.from,
          to,
          subject: message.title,
          html: message.html,
          text: message.text
        }, { Authorization: 'Bearer ' + config.apiKey })
      };
    }
  }
};

/** 供 UI 动态生成表单 */
export function channelMetas() {
  return Object.values(CHANNELS).map(c => ({
    key: c.key,
    label: c.label,
    desc: c.desc,
    fields: c.fields
  }));
}

/** 校验渠道配置，返回规范化后的对象 */
export function normalizeChannelConfig(type, config) {
  const def = CHANNELS[type];
  if (!def) throw new Error('不支持的通知渠道：' + type);

  const raw = config || {};
  const out = {};

  for (const field of def.fields) {
    const value = String(raw[field.name] === undefined ? '' : raw[field.name]).trim();
    if (field.required && !value) throw new Error('请填写' + field.label);
    if (value) out[field.name] = value;
  }

  // 有 URL 的渠道顺手做个格式检查，避免保存后才发现请求直接失败
  for (const key of ['url', 'webhook', 'server']) {
    if (out[key] && !/^https?:\/\/[^\s]+$/i.test(out[key])) {
      throw new Error('地址必须以 http(s):// 开头');
    }
  }

  return out;
}

/* ---------------- 响应判定 ---------------- */

/**
 * 各家成功判定的字段都不一样，而且失败时 HTTP 往往仍是 200。
 * 这里统一收敛成 { ok, error }。
 */
export function interpretResponse(type, status, bodyText) {
  if (status < 200 || status >= 300) {
    return { ok: false, error: 'HTTP ' + status + '：' + String(bodyText || '').slice(0, 160) };
  }

  let data = null;
  try {
    data = bodyText ? JSON.parse(bodyText) : null;
  } catch (e) {
    data = null;
  }

  if (!data || typeof data !== 'object') {
    // 通用 webhook 常常返回纯文本，HTTP 2xx 就算成功
    return { ok: true };
  }

  if (type === 'feishu') {
    const code = data.code !== undefined ? data.code : data.StatusCode;
    if (code !== undefined && Number(code) !== 0) {
      return { ok: false, error: String(data.msg || data.StatusMessage || '飞书返回错误码 ' + code) };
    }
    return { ok: true };
  }

  if (type === 'dingtalk' || type === 'wecom') {
    if (data.errcode !== undefined && Number(data.errcode) !== 0) {
      return { ok: false, error: String(data.errmsg || ('错误码 ' + data.errcode)) };
    }
    return { ok: true };
  }

  if (type === 'telegram') {
    if (data.ok === false) return { ok: false, error: String(data.description || 'Telegram 拒绝请求') };
    return { ok: true };
  }

  if (type === 'serverchan') {
    if (data.code !== undefined && Number(data.code) !== 0) {
      return { ok: false, error: String(data.message || ('错误码 ' + data.code)) };
    }
    return { ok: true };
  }

  if (type === 'pushplus') {
    if (data.code !== undefined && Number(data.code) !== 200) {
      return { ok: false, error: String(data.msg || ('错误码 ' + data.code)) };
    }
    return { ok: true };
  }

  if (type === 'bark') {
    if (data.code !== undefined && Number(data.code) !== 200) {
      return { ok: false, error: String(data.message || ('错误码 ' + data.code)) };
    }
    return { ok: true };
  }

  if (data.success === false) {
    return { ok: false, error: String(data.message || data.error || '渠道返回失败') };
  }

  return { ok: true };
}

/* ---------------- 发送 ---------------- */

export class NotificationService {
  constructor(options = {}) {
    this.timeout = Number(options.timeout) > 0 ? Number(options.timeout) : 10000;
    this.fetchImpl = options.fetchImpl || (typeof fetch === 'function' ? fetch.bind(globalThis) : null);
  }

  /**
   * 发送一条消息到单个渠道。
   * 任何失败都收敛成 { ok:false, error }，绝不抛异常。
   */
  async send(channel, message, nowMs) {
    const def = CHANNELS[channel && channel.type];
    if (!def) return { ok: false, error: '不支持的通知渠道：' + (channel && channel.type) };
    if (!this.fetchImpl) return { ok: false, error: '当前运行环境不支持 fetch' };

    let request;
    try {
      request = await def.build(channel.config || {}, message, nowMs);
    } catch (error) {
      return { ok: false, error: '构建请求失败：' + ((error && error.message) || '未知错误') };
    }

    try {
      const res = await this.fetchImpl(request.url, {
        ...request.init,
        signal: AbortSignal.timeout(this.timeout)
      });
      const text = await res.text();
      return interpretResponse(channel.type, res.status, text);
    } catch (error) {
      const reason = error && error.name === 'AbortError'
        ? '请求超时（' + this.timeout + 'ms）'
        : ((error && error.message) || '网络错误');
      return { ok: false, error: reason };
    }
  }

  /** 依次发送到多个渠道，返回逐条结果 */
  async broadcast(channels, message, nowMs) {
    const results = [];
    for (const channel of channels || []) {
      if (!channel || channel.enabled === false) continue;
      const result = await this.send(channel, message, nowMs);
      results.push({
        id: channel.id,
        type: channel.type,
        label: channel.label || channel.type,
        ok: result.ok,
        error: result.error || null
      });
    }
    return results;
  }
}

/** 测试消息：内容固定，用来验证配置是否正确 */
export function buildTestMessage() {
  const now = new Date();
  const stamp = now.toISOString().replace('T', ' ').slice(0, 16);
  const title = 'DSMC 通知测试';
  const text = '这是一条来自 DSMC 的测试消息。\n如果你收到了，说明该渠道配置正确。\n发送时间：' + stamp + ' UTC';

  return {
    title,
    text,
    markdown: '### ' + title + '\n\n' + text,
    html: '<div style="font-family:-apple-system,Segoe UI,sans-serif"><h2 style="font-size:17px">' +
      title + '</h2><p style="font-size:13px;color:#6b7280">这是一条来自 DSMC 的测试消息，' +
      '收到即表示渠道配置正确。</p><p style="font-size:12px;color:#9ca3af">发送时间：' + stamp + ' UTC</p></div>',
    count: 0,
    groups: { expired: 0, week: 0, month: 0 }
  };
}
