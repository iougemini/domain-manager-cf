// 认证工具模块 - HMAC-SHA256 签名 Token 与 Cookie

import { appState } from './app-state.js';

/**
 * 常量时间字符串比较 - 防止时序攻击
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function secureCompare(a, b) {
  if (!a || !b) return false;

  const aStr = String(a);
  const bStr = String(b);
  const maxLen = Math.max(aStr.length, bStr.length);

  let result = aStr.length ^ bStr.length;
  for (let i = 0; i < maxLen; i++) {
    const aChar = i < aStr.length ? aStr.charCodeAt(i) : 0;
    const bChar = i < bStr.length ? bStr.charCodeAt(i) : 0;
    result |= aChar ^ bChar;
  }
  return result === 0;
}

/**
 * 生成HMAC签名的认证token
 * @param {string} data - 要签名的数据
 * @param {string} secret - 密钥
 * @returns {Promise<string>} hex 编码的签名
 */
export async function generateHMAC(data, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(data)
  );

  const hashArray = Array.from(new Uint8Array(signature));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 获取 token 签名密钥
 * 优先使用独立 TOKEN_SECRET, 未配置时回退到对应密码(向后兼容)
 */
function getTokenSecret(type) {
  return appState.TOKEN_SECRET ||
    (type === 'admin' ? appState.ADMIN_PASSWORD : appState.ACCESS_PASSWORD);
}

/**
 * 创建带签名的认证token
 * @param {string} type - token类型 ('access' 或 'admin')
 * @param {number} expiresIn - 过期时间(秒),默认24小时
 * @returns {Promise<string>} 签名的token
 */
export async function createAuthToken(type, expiresIn = 86400) {
  const payload = {
    type: type,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expiresIn
  };

  const payloadStr = JSON.stringify(payload);
  const payloadB64 = btoa(payloadStr);

  const secret = getTokenSecret(type);
  const signature = await generateHMAC(payloadB64, secret);

  return `${payloadB64}.${signature}`;
}

/**
 * 验证认证token
 * @param {string} token - 待验证的token
 * @param {string} type - 预期的token类型
 * @returns {Promise<Object|null>} 解析的payload或null(验证失败)
 */
export async function verifyAuthToken(token, type) {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const parts = token.split('.');
  if (parts.length !== 2) {
    return null;
  }

  const [payloadB64, signature] = parts;

  try {
    const secret = getTokenSecret(type);
    const expectedSignature = await generateHMAC(payloadB64, secret);

    if (!secureCompare(signature, expectedSignature)) {
      console.warn('⚠️ Token签名验证失败');
      return null;
    }

    const payloadStr = atob(payloadB64);
    const payload = JSON.parse(payloadStr);

    if (payload.type !== type) {
      console.warn(`⚠️ Token类型不匹配: 期望 ${type}, 实际 ${payload.type}`);
      return null;
    }

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      console.warn('⚠️ Token已过期');
      return null;
    }

    return payload;
  } catch (error) {
    console.error('❌ Token验证错误:', error.message);
    return null;
  }
}

/**
 * 从Cookie中提取token
 * @param {Request} request
 * @param {string} name - cookie名称
 * @returns {string|null}
 */
export function getCookie(request, name) {
  const cookie = request.headers.get("Cookie");
  if (!cookie) return null;

  const match = cookie.match(new RegExp(`${name}=([^;]+)`));
  return match ? match[1] : null;
}

/**
 * 生成设置Cookie的响应头
 * @param {string} name - cookie名称
 * @param {string} value - cookie值
 * @param {number} maxAge - 最大年龄(秒)
 * @param {boolean} secure - 是否仅HTTPS
 * @returns {string}
 */
export function createCookieHeader(name, value, maxAge = 86400, secure = false) {
  const parts = [
    `${name}=${value}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Strict',
    `Max-Age=${maxAge}`
  ];

  if (secure) {
    parts.push('Secure');
  }

  return parts.join('; ');
}