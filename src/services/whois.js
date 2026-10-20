// WHOIS 查询服务

import { CONFIG } from '../config.js';

export class WhoisService {
  constructor(proxyUrl, cacheManager, freeDomainManager) {
    this.proxyUrl = proxyUrl;
    this.cache = cacheManager;
    this.freeDomains = freeDomainManager;
  }

  async query(domain) {
    if (!domain) {
      throw new Error('域名不能为空');
    }

    console.log('查询域名: ' + domain);

    // 检查免费域名
    const freeInfo = this.freeDomains.getInfo(domain);
    if (freeInfo) {
      console.log('免费域名: ' + domain);
      return freeInfo;
    }

    // 检查缓存
    const cached = await this.cache.get(domain);
    if (cached) {
      console.log('缓存命中: ' + domain);
      return cached;
    }

    // WHOIS 查询
    if (!this.proxyUrl) {
      console.log('WHOIS代理未配置: ' + domain);
      return {
        registrar: 'N/A',
        registrationDate: 'N/A',
        expirationDate: 'N/A',
        whoisError: 'WHOIS proxy not configured'
      };
    }

    console.log('查询WHOIS: ' + domain);
    const result = await this.fetchWhoisWithRetry(domain);

    // 缓存结果（包括错误结果，避免重复查询）
    await this.cache.set(domain, result);

    return result;
  }

  async fetchWhoisWithRetry(domain) {
    let lastError;

    for (let attempt = 1; attempt <= CONFIG.MAX_RETRIES; attempt++) {
      try {
        console.log('第' + attempt + '次尝试: ' + domain);

        const response = await fetch(`${this.proxyUrl}/api/lookup?query=${domain}`, {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            'User-Agent': `DomainKeeper/${CONFIG.VERSION}`,
            'Cache-Control': 'no-cache'
          },
          signal: AbortSignal.timeout(CONFIG.TIMEOUT)
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log(`收到WHOIS响应: ${domain}`, data);

        if (data.error === true || data.status === 'error' || data.status === false) {
          throw new Error(data.message || data.error_message || '未知WHOIS错误');
        }

        const parsed = this.parseWhoisData(data);
        console.log(`WHOIS解析成功: ${domain}`, parsed);
        return parsed;

      } catch (error) {
        lastError = error;
        console.warn('第' + attempt + '次失败: ' + domain + ' - ' + error.message);

        if (attempt < CONFIG.MAX_RETRIES) {
          const delay = attempt * 1000;
          console.log('⏳ 等待' + delay + 'ms后重试...');
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    console.error('所有重试失败: ' + domain, lastError.message);
    return {
      registrar: 'Unknown',
      registrationDate: 'Unknown',
      expirationDate: 'Unknown',
      whoisError: this.formatError(lastError)
    };
  }

  parseWhoisData(data) {
    const source = data.result || data;

    const extractors = {
      registrar: ['registrar', 'registrarName', 'registrar_name', 'sponsoringRegistrar', 'sponsoring_registrar'],
      registrationDate: ['creationDate', 'created', 'registrationDate', 'registration_date', 'creation_date'],
      expirationDate: ['expirationDate', 'expires', 'expiry', 'expiration_date', 'registry_expiry_date']
    };

    const result = {};

    for (const [field, candidates] of Object.entries(extractors)) {
      let found = false;
      for (const candidate of candidates) {
        if (source[candidate] && !found) {
          if (field.includes('Date')) {
            result[field] = this.parseDate(source[candidate]);
          } else {
            result[field] = source[candidate].toString().trim();
          }
          found = true;
          console.log('提取' + field + ': ' + candidate + ' = ' + result[field]);
        }
      }
      if (!result[field]) {
        result[field] = 'Unknown';
      }
    }

    // 如果关键信息缺失，尝试从原始数据解析
    if (result.registrar === 'Unknown' && result.registrationDate === 'Unknown' && result.expirationDate === 'Unknown') {
      const rawContent = source.rawWhoisContent || source.rawData || source.raw_data;
      if (rawContent && typeof rawContent === 'string') {
        console.log('尝试从原始数据解析...');
        const rawParsed = this.parseRawWhoisData(rawContent);
        return { ...result, ...rawParsed };
      }
    }

    return result;
  }

  parseRawWhoisData(rawData) {
    if (!rawData || typeof rawData !== 'string') {
      return {};
    }

    console.log('解析原始WHOIS数据，长度: ' + rawData.length);

    const lines = rawData.split(/[\r\n]+/);
    const result = {};

    const patterns = {
      registrar: /^(?:registrar|sponsoring registrar|registrar name|registrant organization):\s*(.+)$/i,
      registrationDate: /^(?:creation date|created|registered|registration date|domain created):\s*(.+)$/i,
      expirationDate: /^(?:expiry date|expires|expiration date|registry expiry date|renewal date):\s*(.+)$/i
    };

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      for (const [field, pattern] of Object.entries(patterns)) {
        if (!result[field] || result[field] === 'Unknown') {
          const match = trimmed.match(pattern);
          if (match && match[1].trim()) {
            if (field.includes('Date')) {
              result[field] = this.parseDate(match[1].trim());
            } else {
              result[field] = match[1].trim();
            }
            console.log('从原始数据提取' + field + ': ' + result[field]);
          }
        }
      }
    }

    return result;
  }

  parseDate(dateString) {
    if (!dateString || dateString === 'Unknown' || dateString === 'N/A' || dateString === '') {
      return 'Unknown';
    }

    try {
      let cleanDate = dateString.toString().trim();

      // 清理时间戳格式
      cleanDate = cleanDate
        .replace(/\s+\(.+\)$/, '') // 移除括号
        .replace(/\s+[A-Z]{3,4}$/, '') // 移除时区
        .replace(/T\d{2}:\d{2}:\d{2}.*$/, '') // 移除时间
        .split(' ')[0]; // 只取日期部分

      let date = new Date(cleanDate);

      // 如果直接解析失败，尝试其他格式
      if (isNaN(date.getTime())) {
        // 处理 DD/MM/YYYY 或 MM/DD/YYYY
        if (cleanDate.includes('/')) {
          const parts = cleanDate.split('/');
          if (parts.length === 3) {
            date = new Date(`${parts[2]}-${parts[1].padStart(2, '0')}-${parts[0].padStart(2, '0')}`);
          }
        }
        // 处理 DD-MM-YYYY
        else if (cleanDate.includes('-') && cleanDate.split('-')[0].length === 2) {
          const parts = cleanDate.split('-');
          if (parts.length === 3) {
            date = new Date(`${parts[2]}-${parts[1]}-${parts[0]}`);
          }
        }
      }

      if (isNaN(date.getTime())) {
        console.warn('无效日期格式: ' + dateString);
        return 'Unknown';
      }

      const year = date.getFullYear();
      if (year < 1985 || year > 2050) {
        console.warn('日期年份异常: ' + year);
        return 'Unknown';
      }

      return date.toISOString().split('T')[0];
    } catch (error) {
      console.error('日期解析错误:', error);
      return 'Unknown';
    }
  }

  formatError(error) {
    if (error.name === 'AbortError') {
      return 'WHOIS 查询超时';
    } else if (error.message.includes('fetch') || error.message.includes('network')) {
      return '网络连接错误';
    } else if (error.message.includes('JSON')) {
      return 'API 响应格式错误';
    }
    return error.message;
  }
}