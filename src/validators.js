// 输入验证工具函数

import { ValidationError } from './errors.js';

/**
 * 验证域名格式
 */
export function validateDomain(domain) {
  if (!domain || typeof domain !== 'string') {
    throw new ValidationError('域名不能为空', 'domain');
  }

  domain = domain.trim().toLowerCase();

  if (domain.length === 0) {
    throw new ValidationError('域名不能为空', 'domain');
  }

  if (domain.length > 253) {
    throw new ValidationError('域名长度不能超过253字符', 'domain');
  }

  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

  if (!domainRegex.test(domain)) {
    throw new ValidationError('域名格式无效,请输入有效的域名(例如: example.com)', 'domain');
  }

  const parts = domain.split('.');
  if (parts.length < 2) {
    throw new ValidationError('域名必须包含至少一个点(例如: example.com)', 'domain');
  }

  for (const part of parts) {
    if (part.length === 0 || part.length > 63) {
      throw new ValidationError('域名各部分长度必须在1-63字符之间', 'domain');
    }
  }

  // 防止危险输入 (注意: 不包括斜杠,因为域名本身不应包含斜杠)
  if (/[<>\"\'\/\x00-\x1f\x7f]/.test(domain)) {
    throw new ValidationError('域名包含非法字符', 'domain');
  }

  // 防止路径遍历 (检查连续的点)
  if (/\.\./.test(domain)) {
    throw new ValidationError('域名包含非法字符(路径遍历尝试)', 'domain');
  }

  return domain;
}

/**
 * 验证API密钥格式
 */
export function validateApiKey(apiKey) {
  if (!apiKey || typeof apiKey !== 'string') {
    throw new ValidationError('API密钥不能为空', 'apiKey');
  }

  apiKey = apiKey.trim();

  if (apiKey.length < 20 || apiKey.length > 200) {
    throw new ValidationError('API密钥长度无效', 'apiKey');
  }

  if (/[\x00-\x1f\x7f<>\"\'\\]/.test(apiKey)) {
    throw new ValidationError('API密钥包含非法字符', 'apiKey');
  }

  return apiKey;
}

/**
 * 验证action参数
 */
export function validateAction(action, allowedActions) {
  if (!action || typeof action !== 'string') {
    throw new ValidationError('操作类型不能为空', 'action');
  }

  action = action.trim().toLowerCase();

  if (!allowedActions.includes(action)) {
    throw new ValidationError(
      `无效的操作类型。允许: ${allowedActions.join(', ')}`,
      'action'
    );
  }

  return action;
}