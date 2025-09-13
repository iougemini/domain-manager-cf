//第一部分：配置和基础函数（改进版）
// 版本和配置信息
const CONFIG = {
  VERSION: "3.0.0",
  TITLE: "NieGe Domain List", 
  WHOIS_PROXY: "https://who.nie.ge",
  CACHE_TTL: 7 * 24 * 60 * 60 * 1000, // 7天
  MAX_RETRIES: 3,
  BATCH_SIZE: 5,
  TIMEOUT: 30000
};

// 在这里设置你的多个 Cloudflare API Token
const CF_API_KEYS = [
  "Ux7irk0YSzDxqaUAWLvZIadXxAAv0dQf3Zh2eRVO",//love2wind
  "5FkecSbyeKzastl9BaYmjzhUi2EuUxPhG0f31Mme", //huayuworld
  "hnyx2PzbrWInwte95okZIYE8CMliGvIp6hu7Y5d0",//niege365
  "k9cPXN71eL5Jpkv376vfVEcyjQMadOuhB-Nx1cFe",//agreksandoval
  "vDGazU-v0sAr7Isze5Z84PB5f4emxgXKvnZfFUH_", //thiengiange468378@gmail.com
  "YXBKHWcCgoGKwnq3Vo_8_e45zbvCzM5Fe7ZOMyRe", //oraclevps520@gmail.com
  "GUgetujLEfprN1ChSqhhrVHgQEkA0YWAqWseBrYA", //iouvps@gmail.com
  "ojT_fRyd8QxjPSSZSlegM5G0cCSx5Xs7wM420T24", //17shua8
  "zqS2LvJWLnQCyAVUMfTSQ1GOGCuB16mqPVoTUE4M"//iouedumail
];

// 对应的用户名数组
const USERNAMES = [
  "love2wind",//love2wind
  "huayuworld", // username1
  "niege365",//niege365
  "agreksandoval",//agreksandoval
  "thiengiange", // username1
  "oraclevps", // username2
  "iouvps", //
  "17shua8",
  "iouedumail"
];

// 访问密码（可为空）
const ACCESS_PASSWORD = "lgd123456";

// 后台密码（不可为空）
const ADMIN_PASSWORD = "lgd123456";

// KV 命名空间绑定名称
const KV_NAMESPACE = DOMAIN_INFO;

// API Keys 管理类
class ApiKeyManager {
  constructor() {
    this.keys = CF_API_KEYS.map((key, index) => ({
      key,
      username: USERNAMES[index],
      active: true,
      lastUsed: null,
      errorCount: 0
    }));
    this.initialized = false;
  }

  async init() {
    if (!this.initialized) {
      await this.loadFromKV();
      this.initialized = true;
    }
  }

  getActiveKeys() {
    return this.keys.filter(k => k.active && k.errorCount < 3);
  }

  markError(key) {
    const keyObj = this.keys.find(k => k.key === key);
    if (keyObj) {
      keyObj.errorCount++;
      if (keyObj.errorCount >= 3) {
        keyObj.active = false;
        console.warn('API Key ' + key.slice(0, 10) + '... 已禁用，错误次数过多');
      }
    }
  }

  markSuccess(key) {
    const keyObj = this.keys.find(k => k.key === key);
    if (keyObj) {
      keyObj.lastUsed = Date.now();
      keyObj.errorCount = 0; // 重置错误计数
    }
  }

  async addApiKey(key, username) {
    // 测试API密钥是否有效
    const isValid = await testCloudflareApi(key, username);
    if (!isValid) {
      throw new Error('API密钥无效');
    }
    
    // 检查是否已存在
    const exists = this.keys.some(k => k.key === key);
    if (exists) {
      throw new Error('API密钥已存在');
    }
    
    this.keys.push({
      key,
      username,
      active: true,
      lastUsed: null,
      errorCount: 0
    });
    
    // 保存到KV存储
    await this.saveToKV();
    return true;
  }

  async removeApiKey(key) {
    const index = this.keys.findIndex(k => k.key === key);
    if (index === -1) {
      throw new Error('API密钥不存在');
    }
    
    this.keys.splice(index, 1);
    await this.saveToKV();
    return true;
  }

  async toggleApiKey(key) {
    const keyObj = this.keys.find(k => k.key === key);
    if (!keyObj) {
      throw new Error('API密钥不存在');
    }
    
    keyObj.active = !keyObj.active;
    if (keyObj.active) {
      keyObj.errorCount = 0; // 重新启用时重置错误计数
    }
    
    await this.saveToKV();
    return keyObj.active;
  }

  async saveToKV() {
    const apiKeysData = {
      keys: this.keys,
      lastUpdated: Date.now()
    };
    await KV_NAMESPACE.put('cf_api_keys', JSON.stringify(apiKeysData));
  }

  async loadFromKV() {
    try {
      const data = await KV_NAMESPACE.get('cf_api_keys');
      if (data) {
        const parsed = JSON.parse(data);
        this.keys = parsed.keys || this.keys;
      }
    } catch (error) {
      console.error('加载API密钥失败:', error);
    }
  }

  getAllKeys() {
    return this.keys.map(k => ({
      ...k,
      key: k.key.slice(0, 8) + '...' + k.key.slice(-8) // 隐藏密钥中间部分
    }));
  }
}

// 缓存管理类
class CacheManager {
  constructor(namespace) {
    this.kv = namespace;
  }

  async get(domain) {
    const key = `whois_${domain}`;
    const data = await this.kv.get(key);
    
    if (!data) return null;
    
    try {
      const parsed = JSON.parse(data);
      const { data: domainData, timestamp, version } = parsed;
      
      // 版本检查
      if (version && version !== CONFIG.VERSION) {
        console.log('版本不匹配，删除缓存: ' + domain + ' (' + version + ' -> ' + CONFIG.VERSION + ')');
        await this.delete(domain);
        return null;
      }
      
      // 过期检查
      if (Date.now() - timestamp > CONFIG.CACHE_TTL) {
        console.log('⏰ 缓存过期，删除: ' + domain);
        await this.delete(domain);
        return null;
      }

      // 免费域名强制刷新检查
      if (freeDomainManager.isFree(domain) && domainData.registrar === 'Unknown') {
        console.log('免费域名缓存异常，强制刷新: ' + domain);
        await this.delete(domain);
        return null;
      }

      return domainData;
    } catch (error) {
      console.error('缓存解析错误: ' + domain, error);
      await this.delete(domain);
      return null;
    }
  }

  async set(domain, data) {
    const key = `whois_${domain}`;
    const cacheData = {
      data,
      timestamp: Date.now(),
      version: CONFIG.VERSION
    };
    
    try {
      await this.kv.put(key, JSON.stringify(cacheData));
      console.log('缓存成功: ' + domain);
    } catch (error) {
      console.error('缓存失败: ' + domain, error);
    }
  }

  async delete(domain) {
    await this.kv.delete(`whois_${domain}`);
  }

  async clearAll() {
    const list = await this.kv.list({ prefix: 'whois_' });
    let deletedCount = 0;
    
    const batchSize = 50;
    for (let i = 0; i < list.keys.length; i += batchSize) {
      const batch = list.keys.slice(i, i + batchSize);
      
      await Promise.all(batch.map(async (key) => {
        try {
          await this.kv.delete(key.name);
          deletedCount++;
        } catch (error) {
          console.error('删除缓存失败: ' + key.name, error);
        }
      }));
      
      if (i + batchSize < list.keys.length) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    
    console.log('缓存清理完成，共删除 ' + deletedCount + ' 个缓存项');
    return deletedCount;
  }
}

// 免费域名管理类
class FreeDomainManager {
  constructor() {
    this.domains = new Map([
      ['eu.org', {
        registrar: 'NIC.EU.ORG',
        registrationDate: '1996-04-29',
        type: 'persistent',
        isPermanent: true,  // 标记为永久域名
        description: '欧洲免费域名服务'
      }],
      ['pp.ua', {
        registrar: 'NIC.UA',
        registrationDate: '2002-03-15', 
        expirationDate: 'Auto-Renewal',
        type: 'renewable',
        description: '乌克兰免费域名服务'
      }],
      ['qzz.io', {
        registrar: 'DIGITALPLAT.ORG',
        registrationDate: '2018-10-12',
        expirationDate: 'Auto-Renewal', 
        type: 'renewable',
        description: '免费IO子域名服务'
      }],
      ['us.kg', {
        registrar: 'DIGITALPLAT.ORG',
        registrationDate: '2020-05-20',
        expirationDate: 'Auto-Renewal',
        type: 'renewable', 
        description: '免费KG域名服务'
      }],
      ['xx.kg', {
        registrar: 'DIGITALPLAT.ORG',
        registrationDate: '2021-03-10',
        expirationDate: 'Auto-Renewal',
        type: 'renewable',
        description: '免费KG域名服务'
      }],
      ['dpdns.org', {
        registrar: 'DIGITALPLAT.ORG', 
        registrationDate: '2010-06-01',
        type: 'renewable',
        description: '免费DNS域名服务'
      }]
    ]);
  }

  isFree(domain) {
    if (!domain) return false;
    
    if (this.domains.has(domain)) return true;
    
    for (const freeDomain of this.domains.keys()) {
      if (domain.endsWith('.' + freeDomain)) return true;
    }
    
    return false;
  }

  getInfo(domain) {
    if (!domain) return null;

    // 直接匹配
    if (this.domains.has(domain)) {
      return {
        ...this.domains.get(domain),
        isFreeSubdomain: true,
        level: 'primary'
      };
    }

    // 子域名匹配
    for (const [freeDomain, info] of this.domains) {
      if (domain.endsWith('.' + freeDomain)) {
        return {
          registrar: info.registrar,
          registrationDate: 'N/A',
          expirationDate: info.expirationDate,
          isFreeSubdomain: true,
          level: 'subdomain',
          parent: freeDomain,
          description: `${info.description} - 子域名`
        };
      }
    }

    return null;
  }
}

// 非Cloudflare域名管理类
class CustomDomainManager {
  constructor() {
    this.domains = new Map();
  }

  async loadFromKV() {
    try {
      const data = await KV_NAMESPACE.get('custom_domains');
      if (data) {
        const parsed = JSON.parse(data);
        this.domains = new Map(parsed.domains || []);
      }
    } catch (error) {
      console.error('加载自定义域名失败:', error);
    }
  }

  async saveToKV() {
    const customDomainsData = {
      domains: Array.from(this.domains.entries()),
      lastUpdated: Date.now()
    };
    await KV_NAMESPACE.put('custom_domains', JSON.stringify(customDomainsData));
  }

  async addDomain(domain, info) {
    // 验证域名格式
    if (!domain || !this.isValidDomain(domain)) {
      throw new Error('域名格式无效');
    }

    // 检查是否已存在
    if (this.domains.has(domain)) {
      throw new Error('域名已存在');
    }

    const domainInfo = {
      registrar: info.registrar || 'Unknown',
      registrationDate: info.registrationDate || new Date().toISOString().split('T')[0],
      expirationDate: info.expirationDate || 'Unknown',
      nameServers: info.nameServers || [],
      status: info.status || 'Active',
      notes: info.notes || '',
      addedDate: new Date().toISOString(),
      isCustomDomain: true
    };

    this.domains.set(domain, domainInfo);
    await this.saveToKV();
    return true;
  }

  async removeDomain(domain) {
    if (!this.domains.has(domain)) {
      throw new Error('域名不存在');
    }
    
    this.domains.delete(domain);
    await this.saveToKV();
    return true;
  }

  async updateDomain(domain, info) {
    if (!this.domains.has(domain)) {
      throw new Error('域名不存在');
    }
    
    const existing = this.domains.get(domain);
    const updated = {
      ...existing,
      ...info,
      lastUpdated: new Date().toISOString()
    };
    
    this.domains.set(domain, updated);
    await this.saveToKV();
    return true;
  }

  getDomain(domain) {
    return this.domains.get(domain);
  }

  getAllDomains() {
    return Array.from(this.domains.entries()).map(([domain, info]) => ({
      domain,
      ...info
    }));
  }

  isValidDomain(domain) {
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
    return domainRegex.test(domain);
  }
}

// 全局实例
const apiKeyManager = new ApiKeyManager();
const cacheManager = new CacheManager(KV_NAMESPACE);
const freeDomainManager = new FreeDomainManager();
const customDomainManager = new CustomDomainManager();

// 清理 KV 中的错误数据（改进版）
async function cleanupKV() {
  console.log('开始清理KV错误数据...');
  
  try {
    const list = await KV_NAMESPACE.list({ prefix: 'whois_' });
    let cleanedCount = 0;
    
    for (const key of list.keys) {
      const value = await KV_NAMESPACE.get(key.name);
      if (value) {
        try {
          const parsed = JSON.parse(value);
          const { data } = parsed;
          
          // 清理有错误的缓存数据
          if (data && data.whoisError && data.whoisError.includes('网络连接错误')) {
            await KV_NAMESPACE.delete(key.name);
            cleanedCount++;
            console.log('清理错误缓存: ' + key.name);
          }
        } catch (error) {
          // 清理损坏的缓存数据
          await KV_NAMESPACE.delete(key.name);
          cleanedCount++;
          console.log('清理损坏缓存: ' + key.name);
        }
      }
    }
    
    if (cleanedCount > 0) {
      console.log('KV清理完成，清理了 ' + cleanedCount + ' 个错误项');
    } else {
      console.log('KV数据正常，无需清理');
    }
  } catch (error) {
    console.error('KV清理过程出错:', error);
  }
}

// footerHTML
const footerHTML = `
  <footer style="
    position: fixed;
    left: 0;
    bottom: 0;
    width: 100%;
    background-color: #f8f9fa;
    color: #6c757d;
    text-align: center;
    padding: 10px 0;
    font-size: 14px;
  ">
    Powered by DomainKeeper v${CONFIG.VERSION} <span style="margin: 0 10px;">|</span> © 2024 NieGe. All rights reserved.
  </footer>
`;

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
});

async function handleRequest(request) {
  // 清理KV中的错误数据
  await cleanupKV();

  const url = new URL(request.url);
  const path = url.pathname;

  try {
    if (path === "/api/manual-query") {
      return handleManualQuery(request);
    }

    // API密钥管理路由
    if (path === "/api/cf-keys") {
      return handleCfKeysApi(request);
    }

    // 自定义域名管理路由
    if (path === "/api/custom-domains") {
      return handleCustomDomainsApi(request);
    }

    if (path === "/") {
      return handleFrontend(request);
    } else if (path === "/admin") {
      return handleAdmin(request);
    } else if (path === "/api/update") {
      return handleApiUpdate(request);
    } else if (path === "/login") {
      return handleLogin(request);
    } else if (path === "/admin-login") {
      return handleAdminLogin(request);
    } else if (path.startsWith("/whois/")) {
      const domain = path.split("/")[2];
      return handleWhoisRequest(domain);
    } else {
      return new Response("Not Found", { status: 404 });
    }
  } catch (error) {
    console.error('请求处理异常:', error);
    return new Response(`Internal Server Error: ${error.message}`, { status: 500 });
  }
}
//第二部分：处理函数（改进版）
async function handleManualQuery(request) {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  try {
    const data = await request.json();
    const { domain, apiKey } = data;

    if (!domain) {
      return new Response(JSON.stringify({ error: '域名不能为空' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    console.log('手动查询域名: ' + domain);
    const whoisInfo = await whoisService.query(domain);
    
    return new Response(JSON.stringify(whoisInfo), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('手动查询异常:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Cloudflare API密钥管理API
async function handleCfKeysApi(request) {
  // 验证管理员权限
  const cookie = request.headers.get("Cookie");
  if (!cookie || !cookie.includes(`admin_token=${ADMIN_PASSWORD}`)) {
    return new Response(JSON.stringify({ error: '需要管理员权限' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    await apiKeyManager.init();
    
    if (request.method === 'GET') {
      // 获取所有API密钥
      const keys = apiKeyManager.getAllKeys();
      return new Response(JSON.stringify({ keys }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (request.method === 'POST') {
      const data = await request.json();
      const { action, key, username } = data;

      switch (action) {
        case 'add':
          await apiKeyManager.addApiKey(key, username);
          return new Response(JSON.stringify({ success: true, message: 'API密钥添加成功' }), {
            headers: { 'Content-Type': 'application/json' }
          });

        case 'remove':
          await apiKeyManager.removeApiKey(key);
          return new Response(JSON.stringify({ success: true, message: 'API密钥删除成功' }), {
            headers: { 'Content-Type': 'application/json' }
          });

        case 'toggle':
          const isActive = await apiKeyManager.toggleApiKey(key);
          return new Response(JSON.stringify({ 
            success: true, 
            message: `API密钥${isActive ? '启用' : '禁用'}成功`,
            active: isActive
          }), {
            headers: { 'Content-Type': 'application/json' }
          });

        default:
          return new Response(JSON.stringify({ error: '无效的操作' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
      }
    }

    return new Response('Method Not Allowed', { status: 405 });
  } catch (error) {
    console.error('API密钥管理错误:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// 自定义域名管理API
async function handleCustomDomainsApi(request) {
  // 验证管理员权限
  const cookie = request.headers.get("Cookie");
  if (!cookie || !cookie.includes(`admin_token=${ADMIN_PASSWORD}`)) {
    return new Response(JSON.stringify({ error: '需要管理员权限' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    await customDomainManager.loadFromKV();

    if (request.method === 'GET') {
      // 获取所有自定义域名
      const domains = customDomainManager.getAllDomains();
      return new Response(JSON.stringify({ domains }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (request.method === 'POST') {
      const data = await request.json();
      const { action, domain, info } = data;

      switch (action) {
        case 'add':
          await customDomainManager.addDomain(domain, info);
          return new Response(JSON.stringify({ success: true, message: '域名添加成功' }), {
            headers: { 'Content-Type': 'application/json' }
          });

        case 'update':
          // 检查域名是否存在于自定义域名管理器中
          const existingDomain = customDomainManager.getDomain(domain);
          
          if (existingDomain) {
            // 域名已存在，直接更新，并标记为手动编辑
            await customDomainManager.updateDomain(domain, {
              ...info,
              autoUpdateWhois: false, // 手动编辑后禁用自动WHOIS更新
              lastManualEdit: new Date().toISOString()
            });
          } else {
            // 域名不存在，创建新的自定义域名记录
            await customDomainManager.addDomain(domain, {
              ...info,
              status: info.status || 'Active',
              notes: info.notes || '手动添加的域名信息修正',
              autoUpdateWhois: false, // 手动编辑的域名不自动更新
              lastManualEdit: new Date().toISOString()
            });
          }
          
          return new Response(JSON.stringify({ success: true, message: '域名更新成功' }), {
            headers: { 'Content-Type': 'application/json' }
          });

        case 'remove':
          await customDomainManager.removeDomain(domain);
          return new Response(JSON.stringify({ success: true, message: '域名删除成功' }), {
            headers: { 'Content-Type': 'application/json' }
          });

        default:
          return new Response(JSON.stringify({ error: '无效的操作' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
      }
    }

    return new Response('Method Not Allowed', { status: 405 });
  } catch (error) {
    console.error('自定义域名管理错误:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleFrontend(request) {
  try {
    const cookie = request.headers.get("Cookie");
    if (ACCESS_PASSWORD && (!cookie || !cookie.includes(`access_token=${ACCESS_PASSWORD}`))) {
      return Response.redirect(`${new URL(request.url).origin}/login`, 302);
    }

    console.log("获取Cloudflare域名信息...");
    const domains = await fetchCloudflareDomainsInfo();
    console.log('获取到 ' + domains.length + ' 个Cloudflare域名');

    console.log("补充域名详细信息...");
    const domainsWithInfo = await fetchDomainInfo(domains);
    console.log('处理完成，共 ' + domainsWithInfo.length + ' 个域名');

    return new Response(generateHTML(domainsWithInfo, false), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  } catch (error) {
    console.error('前台页面异常:', error);
    return new Response(`页面加载失败: ${error.message}`, { status: 500 });
  }
}

async function handleAdmin(request) {
  try {
    const cookie = request.headers.get("Cookie");
    if (!cookie || !cookie.includes(`admin_token=${ADMIN_PASSWORD}`)) {
      return Response.redirect(`${new URL(request.url).origin}/admin-login`, 302);
    }

    console.log("管理员获取域名信息...");
    const domains = await fetchCloudflareDomainsInfo();
    const domainsWithInfo = await fetchDomainInfo(domains);
    
    return new Response(generateHTML(domainsWithInfo, true), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  } catch (error) {
    console.error('管理页面异常:', error);
    return new Response(`管理页面加载失败: ${error.message}`, { status: 500 });
  }
}

async function handleLogin(request) {
  try {
    if (request.method === "POST") {
      const formData = await request.formData();
      const password = formData.get("password");

      console.log("前台登录尝试");

      if (password === ACCESS_PASSWORD) {
        console.log("前台登录成功");
        return new Response("Login successful", {
          status: 302,
          headers: {
            "Location": "/",
            "Set-Cookie": `access_token=${ACCESS_PASSWORD}; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400`
          }
        });
      } else {
        console.log("前台登录失败：密码错误");
        return new Response(generateLoginHTML("前台登录", "/login", "密码错误，请重试。"), {
          headers: { "Content-Type": "text/html; charset=utf-8" },
          status: 401
        });
      }
    }
    
    return new Response(generateLoginHTML("前台登录", "/login"), {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  } catch (error) {
    console.error('登录处理异常:', error);
    return new Response(`登录处理失败: ${error.message}`, { status: 500 });
  }
}

async function handleAdminLogin(request) {
  try {
    console.log("处理管理员登录请求");

    if (request.method === "POST") {
      console.log("处理POST登录表单");
      const formData = await request.formData();
      const password = formData.get("password");
      
      console.log("验证管理员密码");

      if (password === ADMIN_PASSWORD) {
        console.log("管理员登录成功");
        return new Response("Admin login successful", {
          status: 302,
          headers: {
            "Location": "/admin",
            "Set-Cookie": `admin_token=${ADMIN_PASSWORD}; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400`
          }
        });
      } else {
        console.log("管理员登录失败：密码错误");
        return new Response(generateLoginHTML("后台登录", "/admin-login", "密码错误，请重试。"), {
          headers: { "Content-Type": "text/html; charset=utf-8" },
          status: 401
        });
      }
    }

    return new Response(generateLoginHTML("后台登录", "/admin-login"), {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  } catch (error) {
    console.error('管理员登录异常:', error);
    return new Response(`管理员登录处理失败: ${error.message}`, { status: 500 });
  }
}

async function handleWhoisRequest(domain) {
  try {
    console.log('处理WHOIS请求: ' + domain);

    if (!domain) {
      return new Response(JSON.stringify({
        error: true,
        message: '域名参数不能为空'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const whoisInfo = await whoisService.query(domain);
    
    // 如果是自定义域名且查询成功，仅在没有手动修改的情况下更新
    await customDomainManager.loadFromKV();
    const customDomain = customDomainManager.getDomain(domain);
    if (customDomain && whoisInfo && whoisInfo.registrar !== 'Unknown') {
      // 只有在原数据不完整或明确标记为可自动更新时才覆盖
      const shouldUpdate = customDomain.registrar === 'Unknown' || 
                          customDomain.registrationDate === 'Unknown' || 
                          !customDomain.registrationDate ||
                          customDomain.autoUpdateWhois !== false; // 默认允许自动更新，除非明确禁止
      
      if (shouldUpdate) {
        try {
          await customDomainManager.updateDomain(domain, {
            registrar: whoisInfo.registrar,
            registrationDate: whoisInfo.registrationDate,
            expirationDate: whoisInfo.expirationDate,
            lastWhoisUpdate: new Date().toISOString()
          });
          console.log('已更新自定义域名WHOIS信息: ' + domain);
        } catch (error) {
          console.warn('更新自定义域名WHOIS信息失败: ' + domain, error);
        }
      } else {
        console.log('域名 ' + domain + ' 已手动修改，跳过WHOIS自动更新');
      }
    }
    
    // 检查是否有原始数据
    let rawData = null;
    if (!freeDomainManager.isFree(domain) && CONFIG.WHOIS_PROXY) {
      try {
        const response = await fetch(`${CONFIG.WHOIS_PROXY}/api/lookup?query=${domain}`, {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            'User-Agent': `DomainKeeper/${CONFIG.VERSION}`,
          },
          signal: AbortSignal.timeout(CONFIG.TIMEOUT)
        });

        if (response.ok) {
          const data = await response.json();
          rawData = data.result?.rawWhoisContent || data.rawData || data.raw_data;
        }
      } catch (error) {
        console.warn('获取原始WHOIS数据失败: ' + domain, error.message);
      }
    }

    return new Response(JSON.stringify({
      error: false,
      data: whoisInfo,
      rawData: rawData
    }), {
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('WHOIS请求处理异常: ' + domain, error);
    return new Response(JSON.stringify({
      error: true,
      message: `获取WHOIS数据失败: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// WHOIS 服务类
class WhoisService {
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
      
      console.log('格式化日期: ' + cleanDate);
      
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
            // 尝试 DD/MM/YYYY 格式
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
      
      const result = date.toISOString().split('T')[0];
      console.log('日期解析成功: ' + dateString + ' -> ' + result);
      return result;
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

// 创建全局 WHOIS 服务实例
const whoisService = new WhoisService(CONFIG.WHOIS_PROXY, cacheManager, freeDomainManager);

//第三部分：API更新和Cloudflare集成（改进版）
async function handleApiUpdate(request) {
  try {
    console.log("处理API更新请求");

    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "只支持POST请求" }), {
        status: 405,
        headers: { "Content-Type": "application/json" }
      });
    }

    // 验证管理员权限
    const cookie = request.headers.get("Cookie");
    if (!cookie || !cookie.includes(`admin_token=${ADMIN_PASSWORD}`)) {
      return new Response(JSON.stringify({ error: "未授权访问" }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }

    const data = await request.json();
    const { action, domain, force } = data;

    if (!action) {
      return new Response(JSON.stringify({ error: "缺少action参数" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    let result = {};

    switch (action) {
      case "refresh":
        result = await handleRefreshAction(domain, force);
        break;
      case "clear-cache":
        result = await handleClearCacheAction(domain);
        break;
      case "test-apis":
        result = await handleTestApisAction();
        break;
      case "get-stats":
        result = await handleGetStatsAction();
        break;
      default:
        return new Response(JSON.stringify({ error: "不支持的action" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
    }

    return new Response(JSON.stringify(result), {
      headers: { "Content-Type": "application/json" }
    });

  } catch (error) {
    console.error("API更新处理异常:", error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}

async function handleRefreshAction(domain, force) {
  if (domain) {
    console.log('刷新单个域名: ' + domain + ' (强制: ' + force + ')');
    
    // 检查是否为免费域名且不是eu.org（永久域名）
    const isFreeDomain = freeDomainManager.isFree(domain);
    const isEuOrg = domain.includes('eu.org');
    
    // 如果是免费域名且不是eu.org，则执行续期操作
    if (isFreeDomain && !isEuOrg) {
      // 加载自定义域名信息
      await customDomainManager.loadFromKV();
      let customDomain = customDomainManager.getDomain(domain);
      
      // 如果自定义域名存在且有有效的过期日期，则进行续期
      if (customDomain && customDomain.expirationDate && customDomain.expirationDate !== 'Unknown') {
        try {
          const currentExpDate = new Date(customDomain.expirationDate);
          // 将过期日期延长一年
          currentExpDate.setFullYear(currentExpDate.getFullYear() + 1);
          
          // 更新自定义域名的过期日期
          await customDomainManager.updateDomain(domain, {
            ...customDomain,
            expirationDate: currentExpDate.toISOString().split('T')[0],
            lastUpdated: new Date().toISOString(),
            lastRenewal: new Date().toISOString() // 添加续期时间记录
          });
          
          console.log('免费域名续期成功: ' + domain);
          return {
            success: true,
            message: `免费域名 ${domain} 续期成功，过期日期已延长一年`,
            data: { ...customDomain, expirationDate: currentExpDate.toISOString().split('T')[0] }
          };
        } catch (error) {
          console.error('免费域名续期失败: ' + domain, error);
        }
      }
    }
    
    if (force) {
      await cacheManager.delete(domain);
      console.log('已清除缓存: ' + domain);
    }
    
    const info = await whoisService.query(domain);
    return {
      success: true,
      message: `域名 ${domain} 信息已更新`,
      data: info
    };
  } else {
    console.log("刷新所有域名");
    const domains = await fetchCloudflareDomainsInfo();
    
    if (force) {
      await cacheManager.clearAll();
      console.log("已清除所有缓存");
    }
    
    const updated = await fetchDomainInfo(domains);
    return {
      success: true,
      message: `已更新 ${updated.length} 个域名信息`,
      count: updated.length,
      force: force
    };
  }
}

async function handleClearCacheAction(domain) {
  if (domain) {
    await cacheManager.delete(domain);
    return {
      success: true,
      message: `域名 ${domain} 缓存已清除`
    };
  } else {
    const count = await cacheManager.clearAll();
    return {
      success: true,
      message: `所有缓存已清除，共 ${count} 个项目`
    };
  }
}

async function handleTestApisAction() {
  console.log("🧪 测试API密钥状态");
  const results = [];
  
  for (const keyInfo of apiKeyManager.keys) {
    const testResult = await testCloudflareApi(keyInfo.key, keyInfo.username);
    results.push({
      username: keyInfo.username,
      key: keyInfo.key.slice(0, 10) + '...',
      status: testResult.success ? '正常' : '异常',
      error: testResult.error || null,
      active: keyInfo.active,
      errorCount: keyInfo.errorCount
    });
  }
  
  return {
    success: true,
    message: "API密钥测试完成",
    results: results
  };
}

async function handleGetStatsAction() {
  console.log("获取系统统计信息");
  
  const domains = await fetchCloudflareDomainsInfo();
  const activeKeys = apiKeyManager.getActiveKeys();
  
  // 获取缓存统计
  const cacheList = await KV_NAMESPACE.list({ prefix: 'whois_' });
  
  return {
    success: true,
    stats: {
      totalDomains: domains.length,
      activeApiKeys: activeKeys.length,
      totalApiKeys: apiKeyManager.keys.length,
      cachedDomains: cacheList.keys.length,
      version: CONFIG.VERSION,
      lastUpdate: new Date().toISOString()
    }
  };
}

async function testCloudflareApi(api_key, username) {
  try {
    const response = await fetch("https://api.cloudflare.com/client/v4/zones?per_page=1", {
      headers: {
        "Authorization": `Bearer ${api_key}`,
        "Content-Type": "application/json"
      },
      signal: AbortSignal.timeout(10000)
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    
    if (data.success) {
      console.log('API测试成功: ' + username);
      return { success: true };
    } else {
      throw new Error(data.errors?.[0]?.message || "API响应错误");
    }
  } catch (error) {
    console.error('API测试失败: ' + username + ' - ' + error.message);
    return { success: false, error: error.message };
  }
}

// Cloudflare 域名信息获取器
class CloudflareFetcher {
  constructor(apiKeyManager) {
    this.apiManager = apiKeyManager;
  }

  async fetchAllDomains() {
    console.log("获取所有Cloudflare域名");
    const allDomains = new Map();
    let totalFetched = 0;
    
    const activeKeys = this.apiManager.getActiveKeys();
    if (activeKeys.length === 0) {
      throw new Error("没有可用的API密钥");
    }

    console.log('使用 ' + activeKeys.length + ' 个API密钥');

    for (const keyInfo of activeKeys) {
      try {
        console.log('使用密钥查询: ' + keyInfo.username);
        const domains = await this.fetchDomainsFromSingleApi(keyInfo.key, keyInfo.username);
        
        // 合并域名信息，避免重复
        for (const domain of domains) {
          if (!allDomains.has(domain.name)) {
            allDomains.set(domain.name, {
              ...domain,
              account: keyInfo.key,
              username: keyInfo.username,
              accountId: keyInfo.key.slice(0, 8) + '...' + keyInfo.key.slice(-4),
              isCloudflare: true
            });
            totalFetched++;
          }
        }
        
        this.apiManager.markSuccess(keyInfo.key);
        console.log(keyInfo.username + ': 获取' + domains.length + '个域名');
        
      } catch (error) {
        console.error(`${keyInfo.username}: ${error.message}`);
        this.apiManager.markError(keyInfo.key);
      }
    }

    const result = Array.from(allDomains.values());
    console.log('合并结果: 共' + result.length + '个唯一域名');
    
    return result;
  }

  async fetchDomainsFromSingleApi(api_key, username) {
    const domains = [];
    let page = 1;
    let totalPages = 1;

    do {
      try {
        console.log('📄 ' + username + ': 获取第' + page + '页');
        
        const response = await fetch(`https://api.cloudflare.com/client/v4/zones?page=${page}&per_page=50`, {
          headers: {
            "Authorization": `Bearer ${api_key}`,
            "Content-Type": "application/json"
          },
          signal: AbortSignal.timeout(30000)
        });

        if (!response.ok) {
          if (response.status === 403) {
            throw new Error("API密钥无效或权限不足");
          } else if (response.status === 429) {
            throw new Error("API请求频率限制");
          } else {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }
        }

        const data = await response.json();
        
        if (!data.success) {
          throw new Error(data.errors?.[0]?.message || "Cloudflare API返回错误");
        }

        if (data.result && data.result.length > 0) {
          for (const zone of data.result) {
            domains.push({
              name: zone.name,
              status: zone.status,
              id: zone.id,
              plan: zone.plan?.name || 'Unknown',
              created_on: zone.created_on,
              modified_on: zone.modified_on
            });
          }
        }

        totalPages = data.result_info?.total_pages || 1;
        page++;

        // 添加延时避免频率限制
        if (page <= totalPages) {
          await new Promise(resolve => setTimeout(resolve, 200));
        }

      } catch (error) {
        console.error('获取第' + page + '页失败: ' + error.message);
        throw error;
      }
    } while (page <= totalPages);

    return domains;
  }
}

// 创建全局 Cloudflare 获取器实例
const cloudflareFetcher = new CloudflareFetcher(apiKeyManager);

async function fetchCloudflareDomainsInfo() {
  try {
    return await cloudflareFetcher.fetchAllDomains();
  } catch (error) {
    console.error('获取Cloudflare域名失败:', error);
    return [];
  }
}

// 批量处理域名信息（支持分组）
async function fetchDomainInfo(domains) {
  if (!domains || domains.length === 0) {
    console.log("没有域名需要处理");
    return [];
  }

  console.log('开始处理' + domains.length + '个域名信息');
  
  // 加载自定义域名
  await customDomainManager.loadFromKV();
  const customDomains = customDomainManager.getAllDomains();
  
  // 合并Cloudflare域名和自定义域名 - 自定义域名优先用于覆盖修正
  const customDomainsMap = new Map(customDomains.map(d => [d.domain, d]));
  
  const allDomainsToProcess = [
    // 处理Cloudflare域名，如果有手动修正数据则标记
    ...domains.map(domain => {
      const customOverride = customDomainsMap.get(domain.name);
      if (customOverride) {
        return {
          ...domain,
          hasCustomOverride: true,
          customInfo: customOverride
        };
      }
      return domain;
    }),
    // 添加纯自定义域名（不在Cloudflare中的）
    ...customDomains
      .filter(domain => !domains.some(d => d.name === domain.domain))
      .map(domain => ({
        name: domain.domain,
        account: 'custom',
        username: '自定义域名',
        isCustomDomain: true,
        customInfo: domain
      }))
  ];
  
  console.log('域名统计: Cloudflare(' + domains.length + '), 自定义(' + customDomains.length + '), 总计(' + allDomainsToProcess.length + ')');
  
  const results = [];
  
  // 分批处理，避免并发过多
  const batchSize = CONFIG.BATCH_SIZE;
  
  for (let i = 0; i < allDomainsToProcess.length; i += batchSize) {
    const batch = allDomainsToProcess.slice(i, i + batchSize);
    console.log('📦 处理批次 ' + (Math.floor(i/batchSize) + 1) + '/' + Math.ceil(allDomainsToProcess.length/batchSize) + ': ' + batch.length + '个域名');
    
    const promises = batch.map(async (domain) => {
      try {
        let processedDomain;
        
        if (domain.isCustomDomain) {
          // 纯自定义域名：优先使用手动输入的信息
          processedDomain = {
            ...domain,
            registrar: domain.customInfo.registrar,
            registrationDate: domain.customInfo.registrationDate,
            expirationDate: domain.customInfo.expirationDate,
            nameServers: domain.customInfo.nameServers,
            status: domain.customInfo.status,
            notes: domain.customInfo.notes,
            serviceProvider: domain.customInfo.serviceProvider,
            isFree: freeDomainManager.isFree(domain.name),
            lastUpdated: domain.customInfo.lastUpdated || new Date().toISOString()
          };
        } else if (domain.hasCustomOverride) {
          // Cloudflare域名有手动修正：优先使用手动修正的数据
          processedDomain = {
            ...domain,
            registrar: domain.customInfo.registrar || 'Unknown',
            registrationDate: domain.customInfo.registrationDate || 'Unknown',
            expirationDate: domain.customInfo.expirationDate || 'Unknown',
            nameServers: domain.customInfo.nameServers || [],
            status: domain.customInfo.status || 'Active',
            notes: domain.customInfo.notes || '',
            serviceProvider: domain.customInfo.serviceProvider,
            isFree: freeDomainManager.isFree(domain.name),
            lastUpdated: domain.customInfo.lastUpdated || new Date().toISOString(),
            isManuallyEdited: true
          };
        } else {
          // Cloudflare域名查询WHOIS信息
          const whoisInfo = await whoisService.query(domain.name);
          
          // 检查是否是免费域名，如果是则优先使用免费域名的默认信息
          const freeInfo = freeDomainManager.getInfo(domain.name);
          if (freeInfo && !whoisInfo.whoisError) {
            processedDomain = {
              ...domain,
              registrar: freeInfo.registrar || whoisInfo.registrar || 'Unknown',
              registrationDate: freeInfo.registrationDate || whoisInfo.registrationDate || 'Unknown', 
              expirationDate: freeInfo.expirationDate || whoisInfo.expirationDate || 'Unknown',
              whoisError: null,
              isFree: true,
              lastUpdated: new Date().toISOString()
            };
          } else {
            processedDomain = {
              ...domain,
              registrar: whoisInfo.registrar || 'Unknown',
              registrationDate: whoisInfo.registrationDate || 'Unknown', 
              expirationDate: whoisInfo.expirationDate || 'Unknown',
              whoisError: whoisInfo.whoisError || null,
              isFree: freeDomainManager.isFree(domain.name),
              lastUpdated: new Date().toISOString()
            };
          }
        }
        
        return processedDomain;
      } catch (error) {
        console.error('处理域名失败: ' + domain.name, error);
        return {
          ...domain,
          registrar: domain.isCustomDomain ? domain.customInfo.registrar : 'Error',
          registrationDate: domain.isCustomDomain ? domain.customInfo.registrationDate : 'Error',
          expirationDate: domain.isCustomDomain ? domain.customInfo.expirationDate : 'Error', 
          whoisError: error.message,
          isFree: freeDomainManager.isFree(domain.name),
          lastUpdated: new Date().toISOString()
        };
      }
    });

    const batchResults = await Promise.allSettled(promises);
    
    for (const result of batchResults) {
      if (result.status === 'fulfilled') {
        results.push(result.value);
      } else {
        console.error('Promise处理失败:', result.reason);
      }
    }

    // 批次间延时
    if (i + batchSize < domains.length) {
      console.log("⏳ 批次间等待500ms...");
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }

  console.log('域名信息处理完成: ' + results.length + '/' + domains.length);
  return results;
}

// 域名状态分析器
class DomainAnalyzer {
  static analyze(domains) {
    if (!domains || domains.length === 0) {
      return {
        total: 0,
        active: 0,
        expired: 0,
        expiringSoon: 0,
        unknown: 0,
        free: 0,
        errors: 0
      };
    }

    let stats = {
      total: domains.length,
      active: 0,
      expired: 0,
      expiringSoon: 0,
      unknown: 0,
      free: 0,
      errors: 0
    };

    const now = new Date();
    const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

    for (const domain of domains) {
      if (domain.isFree) {
        stats.free++;
        continue;
      }

      if (domain.whoisError) {
        stats.errors++;
        continue;
      }

      if (domain.expirationDate === 'Unknown' || domain.registrationDate === 'Unknown') {
        stats.unknown++;
        continue;
      }

      try {
        const expDate = new Date(domain.expirationDate);
        
        if (expDate < now) {
          stats.expired++;
        } else if (expDate < thirtyDaysFromNow) {
          stats.expiringSoon++;
        } else {
          stats.active++;
        }
      } catch (error) {
        stats.unknown++;
      }
    }

    return stats;
  }

  static getExpiringDomains(domains, days = 30) {
    if (!domains || domains.length === 0) return [];

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() + days);

    return domains.filter(domain => {
      if (domain.isFree || domain.whoisError) return false;
      
      try {
        const expDate = new Date(domain.expirationDate);
        return expDate <= cutoffDate && expDate > new Date();
      } catch (error) {
        return false;
      }
    }).sort((a, b) => new Date(a.expirationDate) - new Date(b.expirationDate));
  }
}

//第四部分：页面生成和样式（改进版）
function generateHTML(domains, isAdmin) {
  try {
    console.log('生成' + (isAdmin ? '管理员' : '用户') + '页面 HTML，域名数量: ' + domains.length);
    
    const stats = DomainAnalyzer.analyze(domains);
    const expiringDomains = DomainAnalyzer.getExpiringDomains(domains, 30);
    
    console.log('域名统计:', stats);
    console.log('即将过期域名数量: ' + expiringDomains.length);

    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${isAdmin ? 'Domain Keeper - 管理面板' : 'Domain Keeper - 域名监控'}</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        ${generateCSS()}
    </style>
</head>
<body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark shadow-sm">
        <div class="container">
            <a class="navbar-brand d-flex align-items-center" href="#">
                <i class="fas fa-shield-alt me-2 text-primary"></i>
                <span class="fw-bold">Domain Keeper</span>
                <span class="badge bg-primary ms-2">${CONFIG.VERSION}</span>
            </a>
            
            <div class="d-flex align-items-center">
                ${isAdmin ? generateAdminNavButtons() : generateUserNavButtons()}
            </div>
        </div>
    </nav>

    <div class="container py-4">
        ${generateStatsCards(stats, isAdmin)}
        
        ${expiringDomains.length > 0 ? generateExpiringAlert(expiringDomains) : ''}
        
        <div class="row">
            <div class="col-12">
                <div class="card shadow-sm">
                    <div class="card-header bg-white border-bottom">
                        <div class="row align-items-center">
                            <div class="col-md-6">
                                <h5 class="mb-0 text-dark">
                                    <i class="fas fa-globe me-2"></i>域名列表
                                    <span class="badge bg-secondary ms-2">${domains.length}</span>
                                </h5>
                            </div>
                            <div class="col-md-6">
                                ${generateFilterControls()}
                            </div>
                        </div>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            ${generateDomainTable(domains, isAdmin)}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    ${isAdmin ? generateManualQueryModal() : ''}
    ${isAdmin ? generateApiKeyManagerModal() : ''}
    ${isAdmin ? generateAddCustomDomainModal() : ''}
    ${isAdmin ? generateEditDomainModal() : ''}
    ${generateWhoisModal()}
    ${generateToastContainer()}
    ${generateFooterHTML()}

    <!-- 回到顶部按钮 -->
    <button id="backToTop" class="btn btn-primary back-to-top" title="回到顶部">
        <i class="fas fa-arrow-up"></i>
    </button>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
` + generateJavaScript(isAdmin) + `
    </script>
    <style>.mb-3 {margin-bottom: 0rem !important;}.bg-euorg{background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);}</style>
</body>
</html>`;
  } catch (error) {
    console.error('HTML生成异常:', error);
    return `<html><body><h1>页面生成失败: ${error.message}</h1></body></html>`;
  }
}

function generateCSS() {
  return `
    :root {
        --primary-color: #0d6efd;
        --success-color: #198754;
        --warning-color: #ffc107;
        --danger-color: #dc3545;
        --info-color: #0dcaf0;
        --purple-color: #6f42c1;
        --orange-color: #fd7e14;
        --dark-color: #212529;
        --light-color: #f8f9fa;
    }
    
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        min-height: 100vh;
    }
    
    .navbar-brand {
        font-size: 1.5rem;
        font-weight: 700;
    }
    
    .stats-card {
        border-left: 4px solid var(--primary-color);
        transition: all 0.3s ease;
        height: 100%;
    }
    
    .stats-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    }
    
    .stats-card.success {
        border-left-color: var(--success-color);
    }
    
    .stats-card.warning {
        border-left-color: var(--warning-color);
    }
    
    .stats-card.danger {
        border-left-color: var(--danger-color);
    }
    
    .stats-card.info {
        border-left-color: var(--info-color);
    }
    
    .stats-card.purple {
        border-left-color: var(--purple-color);
    }
    
    .stats-card.orange {
        border-left-color: var(--orange-color);
    }
    
    .stats-number {
        font-size: 3rem;
        font-weight: 700;
        line-height: 1;
    }
    
    .stats-label {
        color: #6c757d;
        font-size: 1rem;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    /* 添加Bootstrap颜色类定义 */
    .text-purple {
        color: var(--purple-color) !important;
    }
    
    .bg-purple {
        background-color: var(--purple-color) !important;
    }
    
    .domain-table {
        font-size: 0.9rem;
        vertical-align: middle;
    }
    
    .domain-table th {
        border-bottom: 2px solid #dee2e6;
        font-weight: 600;
        color: var(--dark-color);
        white-space: nowrap;
        background: var(--light-color);
        vertical-align: middle;
    }
    
    .domain-table td {
        vertical-align: middle;
    }
    
    .domain-table tr {
        transition: background-color 0.2s ease;
    }
    
    .domain-table tr:hover {
        background-color: rgba(13, 110, 253, 0.05);
    }
    
    .status-badge {
        font-size: 0.88em;
        padding: 0.5em 1em;
        border-radius: 0.5rem;
        font-weight: 600;
    }

    .badge {
        font-size: 0.88em;
        padding: 0.5em 1em;
        border-radius: 0.5rem;
        font-weight: 600;
    }

    .expiry-soon {
        background: linear-gradient(45deg, #fff3cd, #ffeaa7);
        color: #856404;
        animation: pulse 2s infinite;
    }
    
    .expiry-expired {
        background: linear-gradient(45deg, #f8d7da, #fab1a0);
        color: #721c24;
    }
    
    .expiry-normal {
        background: linear-gradient(45deg, #d1e7dd, #a7f3d0);
        color: #0f5132;
    }
    
    .expiry-unknown {
        background: linear-gradient(45deg, #e2e3e5, #ddd6fe);
        color: #41464b;
    }
    
    .free-domain {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        font-weight: bold;
    }
    
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.7; }
        100% { opacity: 1; }
    }
    
    .btn-action {
        padding: 0.5rem 0.75rem;
        font-size: 0.875rem;
        border-radius: 0.375rem;
        transition: all 0.2s ease;
        display: inline-flex;
        align-items: center;
        justify-content: center;
    }
    
    .btn-action:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    
    .btn-primary.btn-action {
        background: linear-gradient(135deg, #0d6efd 0%, #0856d3 100%);
        border: none;
        color: white;
    }
    
    .btn-outline-info.btn-action {
        border: 1px solid #0dcaf0;
        color: #0dcaf0;
    }
    
    .btn-outline-primary.btn-action {
        border: 1px solid #0d6efd;
        color: #0d6efd;
    }
    
    .btn-outline-warning.btn-action {
        border: 1px solid #ffc107;
        color: #ffc107;
    }
    
    .btn-outline-danger.btn-action {
        border: 1px solid #dc3545;
        color: #dc3545;
    }
    
    .loading-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.5);
        display: none;
        justify-content: center;
        align-items: center;
        z-index: 9999;
    }
    
    .loading-content {
        background: white;
        padding: 2rem;
        border-radius: 0.5rem;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    }
    
    .spinner {
        width: 3rem;
        height: 3rem;
        margin-bottom: 1rem;
    }
    
    .filter-container {
        background: white;
        border-radius: 0.5rem;
        padding: 1rem;
        margin-bottom: 1rem;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    
    .search-input {
        border-radius: 2rem;
        border: 2px solid #e9ecef;
        padding: 0.5rem 1rem;
        transition: border-color 0.3s ease;
    }
    
    .search-input:focus {
        border-color: var(--primary-color);
        box-shadow: 0 0 0 0.2rem rgba(13, 110, 253, 0.25);
    }
    
    .alert-expiring {
        border-left: 4px solid var(--warning-color);
        background: linear-gradient(45deg, #fff3cd, #ffeaa7);
        border-color: transparent;
    }
    
    .card {
        border: none;
        border-radius: 0;
        overflow: hidden;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    
    .card-header {
        border-bottom: 1px solid #e9ecef;
        padding: 1.25rem;
        border-radius: 0 !important;
        background: white !important;
        color: #212529 !important;
    }
    
    .toast-container {
        position: fixed;
        top: 1rem;
        right: 1rem;
        z-index: 1050;
    }
    
    .table-actions {
        white-space: nowrap;
        width: 1%;
        text-align: center;
    }
    
    .domain-name {
        font-family: 'Courier New', monospace;
        font-weight: 600;
        color: var(--dark-color);
    }
    
    .text-truncate-custom {
        max-width: 200px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    
    @media (max-width: 768px) {
        .stats-number {
            font-size: 2rem;
        }
        
        .domain-table {
            font-size: 0.8rem;
        }
        
        .text-truncate-custom {
            max-width: 120px;
        }
        
        .btn-action {
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
        }
    }
    
    .whois-modal .modal-dialog {
        max-width: 90%;
    }
    
    .whois-content {
        font-family: 'Courier New', monospace;
        font-size: 0.875rem;
        line-height: 1.4;
        white-space: pre-wrap;
        word-wrap: break-word;
    }
    
    .copy-btn {
        position: absolute;
        top: 0.5rem;
        right: 0.5rem;
    }
    
    .position-relative .copy-btn {
        background: rgba(0,0,0,0.1);
        border: none;
        border-radius: 0.25rem;
        padding: 0.25rem 0.5rem;
        font-size: 0.75rem;
        transition: background-color 0.2s ease;
    }
    
    .position-relative .copy-btn:hover {
        background: rgba(0,0,0,0.2);
    }
    
    /* 进度条样式调整 */
    .progress {
        border-radius: 0;
        height: 24px !important;
        position: relative;
        overflow: visible;
    }
    
    .progress-bar {
        border-radius: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 12px;
        font-weight: bold;
        color: white;
        text-shadow: 0 1px 2px rgba(0,0,0,0.5);
    }
    
    .progress-bar.bg-warning {
        color: #000;
        text-shadow: none;
    }
    
    /* 容器宽度调整 */
    .container {
        max-width: 1400px;
    }
    
    /* 页脚样式调整 */
    footer {
        background: linear-gradient(135deg, #2c3e50 0%, #1a2a3a 100%);
        color: #fff;
        padding: 2rem 0;
        margin-top: 2rem;
    }
    
    footer a {
        color: #6fb3e0;
        text-decoration: none;
    }
    
    footer a:hover {
        color: #a3d4f5;
        text-decoration: underline;
    }
    
    /* 修改.text-muted颜色 */
    .text-muted {
        color: rgb(126 127 129 / 40%) !important;
    }
    
    /* 添加.row样式 */
    .row {
        flex-direction: row;
    }
    
    /* 回到顶部按钮样式 */
    .back-to-top {
        position: fixed;
        bottom: 20px;
        right: 20px;
        z-index: 9999;
        width: 50px;
        height: 50px;
        border-radius: 50%;
        display: none;
        align-items: center;
        justify-content: center;
        font-size: 1.2rem;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        transition: all 0.3s ease;
    }
    
    .back-to-top:hover {
        transform: translateY(-3px);
        box-shadow: 0 6px 16px rgba(0, 0, 0, 0.2);
    }
    
    .back-to-top.show {
        display: flex;
    }
  `;
}

function generateStatsCards(stats, isAdmin) {
  // 计算付费域名数量（总域名数 - 免费域名数）
  const paidDomains = stats.total - stats.free;
  
  const cards = [
    {
      title: '总域名数',
      value: stats.total,
      icon: 'fas fa-globe',
      color: 'primary'
    },
    {
      title: '正常域名',
      value: stats.active,
      icon: 'fas fa-check-circle',
      color: 'success'
    },
    {
      title: '临期域名',
      value: stats.expiringSoon,
      icon: 'fas fa-exclamation-triangle',
      color: 'warning'
    },
    {
      title: '过期域名',
      value: stats.expired,
      icon: 'fas fa-times-circle',
      color: 'danger'
    }
  ];

  // 只有管理员页面才显示付费域名、免费域名和查询错误
  if (isAdmin) {
    // 在正常域名后插入付费域名
    cards.splice(1, 0, {
      title: '付费域名',
      value: paidDomains,
      icon: 'fas fa-credit-card',
      color: 'purple'  // 改为紫色
    });
    
    // 在付费域名后插入免费域名
    cards.splice(2, 0, {
      title: '免费域名',
      value: stats.free,
      icon: 'fas fa-gift',
      color: 'info'
    });
    
    cards.push(
      {
        title: '查询错误',
        value: stats.errors,
        icon: 'fas fa-exclamation-circle',
        color: 'orange'  // 改为橙色
      }
    );
  }

  const cardsHtml = cards.map(card => `
    <div class="col-md mb-3">
        <div class="card stats-card ${card.color} h-100">
            <div class="card-body d-flex align-items-center">
                <div class="flex-grow-1">
                    <div class="stats-number text-${card.color}">${card.value}</div>
                    <div class="stats-label">${card.title}</div>
                </div>
                <div class="ms-3">
                    <i class="${card.icon} fa-2x text-${card.color} opacity-50"></i>
                </div>
            </div>
        </div>
    </div>
  `).join('');

  return `
    <div class="row mb-4">
        ${cardsHtml}
    </div>
  `;
}

function generateExpiringAlert(expiringDomains) {
  if (expiringDomains.length === 0) return '';

  const domainList = expiringDomains.slice(0, 5).map(domain => 
    `<span class="badge bg-warning text-dark me-1 mb-1">${domain.name} (${domain.expirationDate})</span>`
  ).join('');

  const moreCount = expiringDomains.length > 5 ? expiringDomains.length - 5 : 0;

  return `
    <div class="alert alert-expiring mb-4" role="alert">
        <div class="d-flex align-items-start">
            <i class="fas fa-exclamation-triangle text-warning me-3 mt-1"></i>
            <div class="flex-grow-1">
                <h6 class="alert-heading mb-2">⚠️ 域名即将过期警告</h6>
                <p class="mb-2">以下域名将在30天内过期，请及时续费：</p>
                <div class="mb-2">${domainList}</div>
                ${moreCount > 0 ? `<small class="text-muted">还有 ${moreCount} 个域名即将过期...</small>` : ''}
            </div>
        </div>
    </div>
  `;
}

function generateFilterControls() {
  return `
    <div class="d-flex gap-2 flex-wrap">
        <input type="text" 
               id="domainSearch" 
               class="form-control search-input" 
               placeholder="🔍 搜索域名..."
               style="max-width: 200px;">
        
        <select id="statusFilter" class="form-select" style="max-width: 150px;">
            <option value="">全部状态</option>
            <option value="normal">正常</option>
            <option value="expiring">即将过期</option>
            <option value="expired">过期</option>
            <option value="free">免费域名</option>
            <option value="unknown">状态未知</option>
            <option value="error">查询错误</option>
        </select>
        
        <button class="btn btn-outline-primary btn-sm" onclick="clearFilters()">
            <i class="fas fa-refresh"></i> 清除筛选
        </button>
    </div>
  `;
}

function generateAdminNavButtons() {
  return `
    <div class="btn-group me-3">
        <button class="btn btn-primary btn-sm" onclick="refreshAllDomains()">
            <i class="fas fa-sync-alt"></i> 刷新全部
        </button>
        <button class="btn btn-success btn-sm" onclick="showManualQuery()">
            <i class="fas fa-search"></i> 手动查询
        </button>
        <button class="btn btn-secondary btn-sm" onclick="showAddCustomDomain()">
            <i class="fas fa-plus"></i> 添加域名
        </button>
        <button class="btn btn-info btn-sm" onclick="showApiKeyManager()">
            <i class="fas fa-key"></i> API管理
        </button>
        <button class="btn btn-warning btn-sm" onclick="clearAllCache()">
            <i class="fas fa-trash"></i> 清除缓存
        </button>
    </div>
    <span class="text-light me-2">管理员</span>
  `;
}

function generateUserNavButtons() {
  return `
    <button class="btn btn-primary btn-sm me-2" onclick="location.reload()">
        <i class="fas fa-sync-alt"></i> 刷新页面
    </button>
    <span class="text-light">访客模式</span>
  `;
}

function generateDomainTable(domains, isAdmin) {
  if (!domains || domains.length === 0) {
    return `
      <div class="text-center py-5">
          <i class="fas fa-inbox fa-3x text-muted mb-3"></i>
          <h5 class="text-muted">暂无域名数据</h5>
          <p class="text-muted">请检查API配置或稍后重试</p>
      </div>
    `;
  }

  // 按账户分组域名
  const groupedDomains = {};
  domains.forEach(domain => {
    const groupKey = domain.isCustomDomain ? 'custom' : domain.username || 'unknown';
    if (!groupedDomains[groupKey]) {
      groupedDomains[groupKey] = [];
    }
    groupedDomains[groupKey].push(domain);
  });

  // 生成分组显示
    const groups = Object.keys(groupedDomains).map(groupKey => {
        const groupDomains = groupedDomains[groupKey];
        const isCustomGroup = groupKey === 'custom';
        const groupTitle = isCustomGroup ? '自定义域名' : `Cloudflare账户: ${groupKey}`;
        const groupIcon = isCustomGroup ? 'fas fa-user-cog' : 'fab fa-cloudflare';
        // 修改背景色：Cloudflare账户使用#2196f3，自定义域名使用#fb8c00
        const groupBgColor = isCustomGroup ? '' : '';
        const groupTextColor = isCustomGroup ? 'dark' : 'white';
        const groupBgStyle = isCustomGroup ? 'background-color: #fb8c00 !important;' : 'background-color: #2196f3 !important;';

        const tableBody = groupDomains.map(domain => {
      const statusInfo = getStatusInfo(domain);
      
      // 获取服务商信息
      const serviceProvider = domain.isCustomDomain ? 
        (domain.serviceProvider || 'Unknown DNS') : 
        (domain.plan ? `Cloudflare ${domain.plan}` : 'Cloudflare Free');
      
      return '<tr data-domain="' + domain.name + '" data-status="' + statusInfo.type + '">' +
        '<td class="text-center" title="' + statusInfo.tooltip + '">' +
            '<span class="badge ' + statusInfo.class + '">' + statusInfo.text + '</span>' +
        '</td>' +
        '<td class="domain-name text-center">' + domain.name + '</td>' +
        '<td class="text-center text-truncate-custom" title="' + domain.registrar + '">' +
            domain.registrar +
        '</td>' +
        '<td class="text-center">' + domain.registrationDate + '</td>' +
        '<td class="text-center">' + domain.expirationDate + '</td>' +
        '<td class="text-center" title="' + statusInfo.tooltip + '">' + statusInfo.progressBar + '</td>' +
        (isAdmin ? '<td class="text-center text-truncate-custom" title="' + serviceProvider + '">' + serviceProvider + '</td>' : '') +
        '<td class="table-actions text-center">' +
            '<div class="btn-group">' +
                '<button class="btn btn-outline-info btn-sm" ' +
                        'onclick="showWhoisInfo(\'' + domain.name + '\')" ' +
                        'title="WHOIS详情">' +
                    '<i class="fas fa-info-circle"></i>' +
                '</button>' +
                (isAdmin ? 
                '<button class="btn btn-outline-primary btn-sm" ' +
                        'onclick="editDomain(\'' + domain.name + '\', ' + (domain.isCustomDomain || false) + ')" ' +
                        'title="编辑域名">' +
                    '<i class="fas fa-edit"></i>' +
                '</button>' +
                (!domain.isCustomDomain ? 
                '<button class="btn btn-outline-warning btn-sm" ' +
                        'onclick="refreshSingleDomain(\'' + domain.name + '\')" ' +
                        'title="刷新此域名">' +
                    '<i class="fas fa-sync-alt"></i>' +
                '</button>' : '') +
                (domain.isCustomDomain ? 
                '<button class="btn btn-outline-danger btn-sm" ' +
                        'onclick="deleteCustomDomain(\'' + domain.name + '\')" ' +
                        'title="删除自定义域名">' +
                    '<i class="fas fa-trash"></i>' +
                '</button>' : '') : '') +
            '</div>' +
        '</td>' +
      '</tr>';
    }).join('');

    return '<div class="card mb-3">' +
        '<div class="card-header text-' + groupTextColor + ' d-flex justify-content-between align-items-center" style="' + groupBgStyle + '">' +
          '<h6 class="mb-0">' +
            '<i class="' + groupIcon + ' me-2"></i>' +
            groupTitle +
            '<span class="badge bg-light text-dark ms-2">' + groupDomains.length + '</span>' +
          '</h6>' +
          '<button class="btn btn-sm btn-outline-light" type="button" ' +
                  'onclick="toggleGroup(\'' + groupKey + '\')" ' +
                  'id="toggle-' + groupKey + '">' +
            '<i class="fas fa-chevron-up"></i>' +
          '</button>' +
        '</div>' +
        '<div class="card-body p-0" id="group-' + groupKey + '">' +
          '<div class="table-responsive">' +
            '<table class="table table-hover domain-table mb-0">' +
                '<thead class="table-light">' +
                    '<tr>' +
                        '<th class="text-center" style="width: 10%;">状态</th>' +
                        '<th class="text-center" style="width: 18%;">域名</th>' +
                        '<th class="text-center" style="width: 16%;">注册商</th>' +
                        '<th class="text-center" style="width: 10%;">注册日期</th>' +
                        '<th class="text-center" style="width: 10%;">过期日期</th>' +
                        '<th class="text-center" style="width: 12%;">剩余天数</th>' +
                        (isAdmin ? '<th class="text-center" style="width: 14%;">服务商</th>' : '') +
                        '<th class="text-center" style="width: 10%;">操作</th>' +
                    '</tr>' +
                '</thead>' +
                '<tbody>' +
                    tableBody +
                '</tbody>' +
            '</table>' +
          '</div>' +
        '</div>' +
      '</div>';
  }).join('');

  return groups;
}

function getStatusInfo(domain) {
  // 检查是否为免费域名
  if (domain.isFree) {
    // 特殊处理：eu.org是永久域名
    if (domain.name && domain.name.includes('eu.org')) {
      return {
        text: '永久',
        daysRemaining: '∞',
        class: 'bg-euorg text-white',  // 添加class属性
        progressBar: '<div class="progress" style="height: 20px; position: relative;"><div class="progress-bar bg-success" role="progressbar" style="width: 100%; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);" title="这是一个永久域名"></div><span style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: bold; color: white;">永久域名</span></div>',
        tooltip: '这是一个永久域名，无需续期'
      };
    }
    
    // 其他免费域名：如果没有手动设置过期日期，显示需要设置
    if (!domain.expirationDate || 
        domain.expirationDate === 'Auto-Renewal' || 
        domain.expirationDate === 'Unknown') {
      return {
        text: '需要设置',
        daysRemaining: 'N/A',
        progressBar: '<div class="progress" style="height: 20px; position: relative;"><div class="progress-bar bg-warning" role="progressbar" style="width: 100%;" title="需要手动设置过期日期"></div><span style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: bold; color: black;">需设置</span></div>',
        tooltip: '请手动设置此免费域名的过期日期'
      };
    }
    
    // 免费域名有手动设置的过期日期，按正常逻辑计算
    // 继续执行后面的正常计算逻辑
  }

  if (domain.whoisError) {
    return {
      type: 'error',
      class: 'bg-danger text-white',
      text: '查询错误',
      daysRemaining: 'N/A',
      progressBar: '<div class="progress" style="height: 20px; position: relative;"><div class="progress-bar bg-danger" role="progressbar" style="width: 100%;" title="' + domain.whoisError + '"></div><span style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: bold; color: white;">N/A</span></div>',
      tooltip: domain.whoisError
    };
  }

  if (domain.expirationDate === 'Unknown' || domain.registrationDate === 'Unknown') {
    return {
      type: 'unknown',
      class: 'bg-secondary text-white',
      text: '状态未知',
      daysRemaining: 'N/A',
      progressBar: '<div class="progress" style="height: 20px; position: relative;"><div class="progress-bar bg-secondary" role="progressbar" style="width: 100%;" title="无法获取域名信息"></div><span style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: bold; color: white;">N/A</span></div>',
      tooltip: '无法获取域名信息'
    };
  }

  try {
    // 检查是否为Auto-Renewal类型的过期日期
    if (domain.expirationDate === 'Auto-Renewal') {
      return {
        type: 'free',
        class: 'bg-info text-white',
        text: '自动续期',
        daysRemaining: '∞',
        progressBar: '<div class="progress" style="height: 20px; position: relative;"><div class="progress-bar bg-info" role="progressbar" style="width: 100%;" title="自动续期域名"></div><span style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: bold; color: white;">∞</span></div>',
        tooltip: '自动续期域名'
      };
    }
    
    const expDate = new Date(domain.expirationDate);
    const now = new Date();
    const daysUntilExpiry = Math.ceil((expDate - now) / (1000 * 60 * 60 * 24));

    if (daysUntilExpiry <= 0) {
      return {
        type: 'expired',
        class: 'bg-danger text-white',
        text: '过期',
        daysRemaining: daysUntilExpiry + '天',
        progressBar: '<div class="progress" style="height: 20px; position: relative;"><div class="progress-bar bg-danger" role="progressbar" style="width: 100%;" title="过期 ' + Math.abs(daysUntilExpiry) + ' 天"></div><span style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: bold; color: white;">' + daysUntilExpiry + '天</span></div>',
        tooltip: `过期 ${Math.abs(daysUntilExpiry)} 天`
      };
    } else if (daysUntilExpiry <= 30) {
      const percentage = Math.max((daysUntilExpiry / 30) * 100, 5); // 至少显示5%宽度
      return {
        type: 'expiring',
        class: 'bg-warning text-dark',
        text: '临期',
        daysRemaining: daysUntilExpiry + '天',
        progressBar: '<div class="progress" style="height: 20px; position: relative;"><div class="progress-bar bg-warning" role="progressbar" style="width: ' + percentage + '%;" title="将在 ' + daysUntilExpiry + ' 天后过期"></div><span style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: bold; color: black;">' + daysUntilExpiry + '天</span></div>',
        tooltip: `将在 ${daysUntilExpiry} 天后过期`
      };
    } else {
      const maxDays = 365; // 以一年为100%
      const percentage = Math.min((daysUntilExpiry / maxDays) * 100, 100);
      return {
        type: 'normal',
        class: 'bg-success text-white',
        text: '正常',
        daysRemaining: daysUntilExpiry + '天',
        progressBar: '<div class="progress" style="height: 20px; position: relative;"><div class="progress-bar bg-success" role="progressbar" style="width: ' + percentage + '%;" title="' + daysUntilExpiry + ' 天后过期"></div><span style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: bold; color: white;">' + daysUntilExpiry + '天</span></div>',
        tooltip: `${daysUntilExpiry} 天后过期`
      };
    }
  } catch (error) {
    return {
      type: 'unknown',
      class: 'bg-secondary text-white',
      text: '日期错误',
      daysRemaining: 'N/A',
      progressBar: '<div class="progress" style="height: 20px; position: relative;"><div class="progress-bar bg-secondary" role="progressbar" style="width: 100%;" title="日期格式错误"></div><span style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: bold; color: white;">N/A</span></div>',
      tooltip: '日期格式错误'
    };
  }
}

//第五部分A：JavaScript交互和模态框（修复版）
function generateManualQueryModal() {
  return `
    <div class="modal fade" id="manualQueryModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-search me-2"></i>手动WHOIS查询
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="manualQueryForm">
                        <div class="mb-3">
                            <label for="queryDomain" class="form-label">域名</label>
                            <input type="text" 
                                   class="form-control" 
                                   id="queryDomain" 
                                   placeholder="例如：example.com"
                                   required>
                            <div class="form-text">请输入要查询的域名（不含协议）</div>
                        </div>
                        
                        <div class="mb-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="forceRefresh">
                                <label class="form-check-label" for="forceRefresh">
                                    强制刷新（忽略缓存）
                                </label>
                            </div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-primary" onclick="executeManualQuery()">
                        <i class="fas fa-search"></i> 查询
                    </button>
                </div>
            </div>
        </div>
    </div>
  `;
}

function generateWhoisModal() {
  return `
    <div class="modal fade whois-modal" id="whoisModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-info-circle me-2"></i>
                        WHOIS信息：<span id="whoisDomainName" class="text-primary"></span>
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="whoisLoading" class="text-center py-4">
                        <div class="spinner-border text-primary" role="status">
                            <span class="visually-hidden">加载中...</span>
                        </div>
                        <p class="mt-2 text-muted">正在获取WHOIS信息...</p>
                    </div>
                    
                    <div id="whoisContent" style="display: none;">
                        <ul class="nav nav-tabs" id="whoisTabs">
                            <li class="nav-item">
                                <a class="nav-link active" id="basic-tab" data-bs-toggle="tab" href="#basic">
                                    <i class="fas fa-list-ul"></i> 基本信息
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" id="raw-tab" data-bs-toggle="tab" href="#raw">
                                    <i class="fas fa-code"></i> 原始数据
                                </a>
                            </li>
                        </ul>
                        
                        <div class="tab-content mt-3" id="whoisTabContent">
                            <div class="tab-pane fade show active" id="basic">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label fw-bold">注册商</label>
                                        <div class="form-control-plaintext bg-light p-2 rounded" id="whoisRegistrar">-</div>
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label fw-bold">注册日期</label>
                                        <div class="form-control-plaintext bg-light p-2 rounded" id="whoisCreated">-</div>
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label fw-bold">过期日期</label>
                                        <div class="form-control-plaintext bg-light p-2 rounded" id="whoisExpires">-</div>
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label fw-bold">状态</label>
                                        <div class="form-control-plaintext bg-light p-2 rounded" id="whoisStatus">-</div>
                                    </div>
                                </div>
                                
                                <div id="whoisError" class="alert alert-danger" style="display: none;">
                                    <i class="fas fa-exclamation-triangle"></i>
                                    <strong>查询失败：</strong>
                                    <span id="whoisErrorMessage"></span>
                                </div>
                            </div>
                            
                            <div class="tab-pane fade" id="raw">
                                <div class="position-relative">
                                    <button class="copy-btn btn btn-sm btn-outline-secondary" onclick="copyRawData()">
                                        <i class="fas fa-copy"></i> 复制
                                    </button>
                                    <pre class="whois-content bg-light p-3 rounded" id="whoisRawData">暂无原始数据</pre>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                    <button type="button" class="btn btn-primary" onclick="refreshWhoisInfo()">
                        <i class="fas fa-sync-alt"></i> 刷新
                    </button>
                </div>
            </div>
        </div>
    </div>
  `;
}

function generateApiKeyManagerModal() {
  return `
    <div class="modal fade" id="apiKeyManagerModal" tabindex="-1">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-key me-2"></i>Cloudflare API密钥管理
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="row mb-3">
                        <div class="col-md-8">
                            <input type="text" class="form-control" id="newApiKey" placeholder="输入Cloudflare API Token">
                        </div>
                        <div class="col-md-4">
                            <input type="text" class="form-control" id="newApiUsername" placeholder="用户名标识">
                        </div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-12">
                            <button class="btn btn-success" onclick="addApiKey()">
                                <i class="fas fa-plus"></i> 添加API密钥
                            </button>
                        </div>
                    </div>
                    
                    <div class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>用户名</th>
                                    <th>API密钥</th>
                                    <th>状态</th>
                                    <th>错误次数</th>
                                    <th>最后使用</th>
                                    <th>操作</th>
                                </tr>
                            </thead>
                            <tbody id="apiKeyTableBody">
                                <tr><td colspan="6" class="text-center">加载中...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                    <button type="button" class="btn btn-primary" onclick="refreshApiKeys()">
                        <i class="fas fa-sync-alt"></i> 刷新
                    </button>
                </div>
            </div>
        </div>
    </div>
  `;
}

function generateAddCustomDomainModal() {
  return `
    <div class="modal fade" id="addCustomDomainModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-plus me-2"></i>添加自定义域名
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="addCustomDomainForm">
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="customDomainName" class="form-label">域名 *</label>
                                <input type="text" class="form-control" id="customDomainName" required placeholder="example.com">
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="customDomainRegistrar" class="form-label">注册商</label>
                                <input type="text" class="form-control" id="customDomainRegistrar" placeholder="GoDaddy">
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-12 mb-3">
                                <label for="customDomainServiceProvider" class="form-label">服务商</label>
                                <input type="text" class="form-control" id="customDomainServiceProvider" placeholder="阿里云DNS, Cloudflare, Route53等">
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="customDomainRegDate" class="form-label">注册日期</label>
                                <input type="date" class="form-control" id="customDomainRegDate">
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="customDomainExpDate" class="form-label">过期日期</label>
                                <input type="date" class="form-control" id="customDomainExpDate">
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="customDomainStatus" class="form-label">状态</label>
                                <select class="form-select" id="customDomainStatus">
                                    <option value="Active">活跃</option>
                                    <option value="Inactive">不活跃</option>
                                    <option value="Pending">待处理</option>
                                    <option value="Suspended">暂停</option>
                                </select>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="customDomainNS" class="form-label">名称服务器</label>
                                <input type="text" class="form-control" id="customDomainNS" placeholder="ns1.example.com,ns2.example.com">
                            </div>
                        </div>
                        <div class="mb-3">
                            <label for="customDomainNotes" class="form-label">备注</label>
                            <textarea class="form-control" id="customDomainNotes" rows="3" placeholder="域名相关备注信息"></textarea>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-primary" onclick="saveCustomDomain()">
                        <i class="fas fa-save"></i> 保存
                    </button>
                </div>
            </div>
        </div>
    </div>
  `;
}

function generateEditDomainModal() {
  return `
    <div class="modal fade" id="editDomainModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-edit me-2"></i>编辑域名信息
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="editDomainForm">
                        <input type="hidden" id="editDomainOriginalName">
                        <input type="hidden" id="editDomainIsCustom">
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="editDomainName" class="form-label">域名</label>
                                <input type="text" class="form-control" id="editDomainName" readonly>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="editDomainRegistrar" class="form-label">注册商</label>
                                <input type="text" class="form-control" id="editDomainRegistrar">
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-12 mb-3">
                                <label for="editDomainServiceProvider" class="form-label">服务商</label>
                                <input type="text" class="form-control" id="editDomainServiceProvider" placeholder="例如: Cloudflare Free, 阿里云DNS">
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="editDomainRegDate" class="form-label">注册日期</label>
                                <input type="date" class="form-control" id="editDomainRegDate">
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="editDomainExpDate" class="form-label">过期日期</label>
                                <input type="date" class="form-control" id="editDomainExpDate">
                            </div>
                        </div>
                        <div class="row" id="customDomainFields" style="display: none;">
                            <div class="col-md-6 mb-3">
                                <label for="editDomainStatus" class="form-label">状态</label>
                                <select class="form-select" id="editDomainStatus">
                                    <option value="Active">活跃</option>
                                    <option value="Inactive">不活跃</option>
                                    <option value="Pending">待处理</option>
                                    <option value="Suspended">暂停</option>
                                </select>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="editDomainNS" class="form-label">名称服务器</label>
                                <input type="text" class="form-control" id="editDomainNS">
                            </div>
                        </div>
                        <div class="mb-3" id="notesField" style="display: none;">
                            <label for="editDomainNotes" class="form-label">备注</label>
                            <textarea class="form-control" id="editDomainNotes" rows="3"></textarea>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-primary" onclick="saveEditedDomain()">
                        <i class="fas fa-save"></i> 保存更改
                    </button>
                </div>
            </div>
        </div>
    </div>
  `;
}

function generateToastContainer() {
  return `
    <div class="toast-container position-fixed top-0 end-0 p-3" style="z-index: 1050;">
        <div id="successToast" class="toast align-items-center text-white bg-success border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body">
                    <i class="fas fa-check-circle me-2"></i>
                    <span id="successMessage">操作成功</span>
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
        
        <div id="errorToast" class="toast align-items-center text-white bg-danger border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body">
                    <i class="fas fa-exclamation-circle me-2"></i>
                    <span id="errorMessage">操作失败</span>
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
        
        <div id="warningToast" class="toast align-items-center text-white bg-warning border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    <span id="warningMessage">警告信息</span>
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
        
        <div id="infoToast" class="toast align-items-center text-white bg-info border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body">
                    <i class="fas fa-info-circle me-2"></i>
                    <span id="infoMessage">提示信息</span>
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    </div>
    
    <div class="loading-overlay" id="loadingOverlay">
        <div class="loading-content">
            <div class="spinner-border text-primary spinner" role="status">
                <span class="visually-hidden">加载中...</span>
            </div>
            <h5>处理中...</h5>
            <p class="text-muted mb-0" id="loadingMessage">请稍候</p>
        </div>
    </div>
  `;
}

// 修复：使用函数返回footer内容，避免重复声明
function generateFooterHTML() {
  return `
    <footer class="mt-5 py-4 bg-dark text-light">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-6">
                    <p class="mb-0">
                        <i class="fas fa-shield-alt me-2"></i>
                        <strong>Domain Keeper</strong> ${CONFIG.VERSION}
                    </p>
                    <small class="text-muted">专业的域名监控和管理工具</small>
                </div>
                <div class="col-md-6 text-md-end">
                    <small class="text-muted">
                        &copy; 2025 NieGe. All rights reserved.
                    </small>
                    <br>
                    <small class="text-muted">
                        最后更新：<span id="lastUpdateTime">${new Date().toLocaleString('zh-CN')}</span>
                    </small>
                </div>
            </div>
        </div>
    </footer>
  `;
}

function generateJavaScript(isAdmin) {
  return `
    // 全局变量
    let currentWhoisDomain = '';
    let filterTimeout = null;
    
    // 页面加载完成后初始化
    document.addEventListener('DOMContentLoaded', function() {
        console.log('🚀 Domain Keeper 3.0.0 初始化');
        console.log('Bootstrap状态:', typeof bootstrap !== 'undefined' ? '已加载' : '未加载');
        
        // 测试基本函数
        window.testBasicFunctions = function() {
            console.log('Testing basic functions...');
            console.log('showApiKeyManager:', typeof showApiKeyManager);
            console.log('showAddCustomDomain:', typeof showAddCustomDomain);
            console.log('editDomain:', typeof editDomain);
        };
        
        initializeFilters();
        bindEventListeners();
        
        // 添加键盘快捷键
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey || e.metaKey) {
                switch(e.key) {
                    case 'f':
                        e.preventDefault();
                        document.getElementById('domainSearch').focus();
                        break;
                    case 'r':
                        e.preventDefault();
                        location.reload();
                        break;
                }
            }
        });
        
        // 初始化回到顶部按钮
        initBackToTop();
        
        showToast('success', '页面加载完成');
    });
    
    // 初始化筛选器
    function initializeFilters() {
        const searchInput = document.getElementById('domainSearch');
        const statusFilter = document.getElementById('statusFilter');
        
        if (searchInput) {
            searchInput.addEventListener('input', debounce(filterDomains, 300));
        }
        
        if (statusFilter) {
            statusFilter.addEventListener('change', filterDomains);
        }
    }
    
    // 绑定事件监听器
    function bindEventListeners() {
        // 表格行点击高亮
        document.querySelectorAll('.domain-table tbody tr').forEach(row => {
            row.addEventListener('click', function(e) {
                if (!e.target.closest('button')) {
                    document.querySelectorAll('.domain-table tbody tr').forEach(r => r.classList.remove('table-active'));
                    this.classList.add('table-active');
                }
            });
        });
    }
    
    // 防抖函数
    function debounce(func, wait) {
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(filterTimeout);
                func(...args);
            };
            clearTimeout(filterTimeout);
            filterTimeout = setTimeout(later, wait);
        };
    }
    
    // 域名筛选功能
    function filterDomains() {
        const searchTerm = document.getElementById('domainSearch').value.toLowerCase();
        const statusFilter = document.getElementById('statusFilter').value;
        const rows = document.querySelectorAll('.domain-table tbody tr');
        let visibleCount = 0;
        
        rows.forEach(row => {
            const domain = row.getAttribute('data-domain').toLowerCase();
            const status = row.getAttribute('data-status');
            
            const matchesSearch = domain.includes(searchTerm);
            const matchesStatus = !statusFilter || status === statusFilter;
            
            const shouldShow = matchesSearch && matchesStatus;
            row.style.display = shouldShow ? '' : 'none';
            
            if (shouldShow) visibleCount++;
        });
        
        // 更新结果统计
        updateFilterStats(visibleCount, rows.length);
    }
    
    // 更新筛选统计
    function updateFilterStats(visible, total) {
        let statsElement = document.getElementById('filterStats');
        if (!statsElement) {
            const tableContainer = document.querySelector('.card-header .row .col-md-6:first-child');
            if (tableContainer) {
                statsElement = document.createElement('small');
                statsElement.id = 'filterStats';
                statsElement.className = 'text-muted ms-2';
                tableContainer.appendChild(statsElement);
            }
        }
        
        if (statsElement) {
            if (visible === total) {
                statsElement.innerHTML = '';
            } else {
                statsElement.innerHTML = \`(显示 \${visible}/\${total})\`;
            }
        }
    }
    
    // 清除筛选器
    function clearFilters() {
        document.getElementById('domainSearch').value = '';
        document.getElementById('statusFilter').value = '';
        filterDomains();
        showToast('info', '筛选条件已清除');
    }
    
    // Toast 通知系统
    function showToast(type, message, duration = 3000) {
        const toastElement = document.getElementById(\`\${type}Toast\`);
        const messageElement = document.getElementById(\`\${type}Message\`);
        
        if (toastElement && messageElement) {
            messageElement.textContent = message;
            const toast = new bootstrap.Toast(toastElement, { delay: duration });
            toast.show();
        }
    }
    
    // 显示/隐藏加载遮罩
    function showLoading(message = '处理中...') {
        const overlay = document.getElementById('loadingOverlay');
        const messageEl = document.getElementById('loadingMessage');
        
        if (overlay && messageEl) {
            messageEl.textContent = message;
            overlay.style.display = 'flex';
        }
    }
    
    function hideLoading() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.style.display = 'none';
        }
    }
    
    // 回到顶部按钮功能
    function initBackToTop() {
        const backToTopButton = document.getElementById('backToTop');
        
        if (!backToTopButton) return;
        
        // 监听滚动事件
        window.addEventListener('scroll', function() {
            if (window.pageYOffset > window.innerHeight) {
                backToTopButton.classList.add('show');
            } else {
                backToTopButton.classList.remove('show');
            }
        });
        
        // 点击回到顶部
        backToTopButton.addEventListener('click', function() {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }
    
    ${isAdmin ? generateAdminJavaScript() : ''}
    ${generateWhoisJavaScript()}
  `;
}
//第五部分B：JavaScript交互和登录页面（完结版）
function generateWhoisJavaScript() {
  return `
    // WHOIS 信息显示
    async function showWhoisInfo(domain) {
        currentWhoisDomain = domain;
        
        // 显示模态框
        const modal = new bootstrap.Modal(document.getElementById('whoisModal'));
        document.getElementById('whoisDomainName').textContent = domain;
        document.getElementById('whoisLoading').style.display = 'block';
        document.getElementById('whoisContent').style.display = 'none';
        modal.show();
        
        try {
            console.log(\`获取WHOIS信息: \${domain}\`);
            const response = await fetch(\`/whois/\${encodeURIComponent(domain)}\`);
            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.message || '获取WHOIS信息失败');
            }
            
            displayWhoisData(data.data, data.rawData);
            
        } catch (error) {
            console.error('WHOIS查询失败:', error);
            displayWhoisError(error.message);
        }
    }
    
    // 显示WHOIS数据
    function displayWhoisData(whoisData, rawData) {
        document.getElementById('whoisLoading').style.display = 'none';
        document.getElementById('whoisContent').style.display = 'block';
        
        // 填充基本信息
        document.getElementById('whoisRegistrar').textContent = whoisData.registrar || 'Unknown';
        document.getElementById('whoisCreated').textContent = whoisData.registrationDate || 'Unknown';
        document.getElementById('whoisExpires').textContent = whoisData.expirationDate || 'Unknown';
        
        // 计算状态
        const status = calculateDomainStatus(whoisData.expirationDate);
        const statusEl = document.getElementById('whoisStatus');
        statusEl.textContent = status.text;
        statusEl.className = 'form-control-plaintext p-2 rounded ' + status.class;
        
        // 显示错误信息（如果有）
        const errorEl = document.getElementById('whoisError');
        if (whoisData.whoisError) {
            document.getElementById('whoisErrorMessage').textContent = whoisData.whoisError;
            errorEl.style.display = 'block';
        } else {
            errorEl.style.display = 'none';
        }
        
        // 填充原始数据
        const rawDataEl = document.getElementById('whoisRawData');
        if (rawData && rawData.trim()) {
            rawDataEl.textContent = rawData;
        } else {
            rawDataEl.textContent = '暂无原始WHOIS数据或数据获取失败';
        }
    }
    
    // 显示WHOIS错误
    function displayWhoisError(errorMessage) {
        document.getElementById('whoisLoading').style.display = 'none';
        document.getElementById('whoisContent').style.display = 'block';
        
        // 清空基本信息
        document.getElementById('whoisRegistrar').textContent = 'Error';
        document.getElementById('whoisCreated').textContent = 'Error';
        document.getElementById('whoisExpires').textContent = 'Error';
        document.getElementById('whoisStatus').textContent = 'Error';
        
        // 显示错误信息
        document.getElementById('whoisErrorMessage').textContent = errorMessage;
        document.getElementById('whoisError').style.display = 'block';
        
        // 清空原始数据
        document.getElementById('whoisRawData').textContent = \`查询失败：\${errorMessage}\`;
    }
    
    // 计算域名状态
    function calculateDomainStatus(expirationDate) {
        if (!expirationDate || expirationDate === 'Unknown') {
            return { text: '状态未知', class: 'bg-secondary text-white' };
        }
        
        try {
            const expDate = new Date(expirationDate);
            const now = new Date();
            const daysUntilExpiry = Math.ceil((expDate - now) / (1000 * 60 * 60 * 24));
            
            if (daysUntilExpiry < 0) {
                return { text: \`过期 \${Math.abs(daysUntilExpiry)} 天\`, class: 'bg-danger text-white' };
            } else if (daysUntilExpiry <= 30) {
                return { text: \`\${daysUntilExpiry} 天后过期\`, class: 'bg-warning text-dark' };
            } else {
                return { text: \`正常 (\${daysUntilExpiry} 天后过期)\`, class: 'bg-success text-white' };
            }
        } catch (error) {
            return { text: '日期解析错误', class: 'bg-secondary text-white' };
        }
    }
    
    // 刷新WHOIS信息
    function refreshWhoisInfo() {
        if (currentWhoisDomain) {
            showWhoisInfo(currentWhoisDomain);
        }
    }
    
    // 复制原始数据
    function copyRawData() {
        const rawDataEl = document.getElementById('whoisRawData');
        const text = rawDataEl.textContent;
        
        navigator.clipboard.writeText(text).then(() => {
            showToast('success', '原始数据已复制到剪贴板');
        }).catch(err => {
            console.error('复制失败:', err);
            showToast('error', '复制失败');
        });
    }
  `;
}

function generateAdminJavaScript() {
  return `
    // 管理员功能
    
    // 刷新所有域名
    async function refreshAllDomains() {
        if (!confirm('确定要刷新所有域名信息吗？这可能需要几分钟时间。')) {
            return;
        }
        
        showLoading('正在刷新所有域名信息...');
        
        try {
            const response = await fetch('/api/update', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'refresh', force: true })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showToast('success', data.message);
                setTimeout(() => location.reload(), 2000);
            } else {
                throw new Error(data.error || '刷新失败');
            }
            
        } catch (error) {
            console.error('刷新失败:', error);
            showToast('error', '刷新失败: ' + error.message);
        } finally {
            hideLoading();
        }
    }
    
    // 刷新单个域名
    async function refreshSingleDomain(domain) {
        showLoading('正在刷新域名: ' + domain);
        
        try {
            const response = await fetch('/api/update', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'refresh', domain: domain, force: true })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showToast('success', data.message);
                
                // 检查是否为免费域名续期操作
                if (data.message && data.message.includes('续期成功')) {
                    // 更新表格中的域名信息而不刷新页面
                    if (data.data && data.data.expirationDate) {
                        await updateDomainRow(domain, data.data);
                    }
                } else {
                    // 普通刷新操作，延迟刷新页面
                    setTimeout(() => location.reload(), 1500);
                }
            } else {
                throw new Error(data.error || '刷新失败');
            }
            
        } catch (error) {
            console.error('刷新域名失败: ' + domain, error);
            showToast('error', '刷新失败: ' + error.message);
        } finally {
            hideLoading();
        }
    }
    
    // 显示手动查询模态框
    function showManualQuery() {
        const modal = new bootstrap.Modal(document.getElementById('manualQueryModal'));
        modal.show();
        document.getElementById('queryDomain').focus();
    }
    
    // 执行手动查询
    async function executeManualQuery() {
        const domain = document.getElementById('queryDomain').value.trim();
        const forceRefresh = document.getElementById('forceRefresh').checked;
        
        if (!domain) {
            showToast('warning', '请输入域名');
            return;
        }
        
        // 关闭模态框
        const modal = bootstrap?.Modal?.getInstance(document.getElementById('manualQueryModal'));
        if (modal) modal.hide();
        
        showLoading('正在查询域名: ' + domain);
        
        try {
            const response = await fetch('/api/manual-query', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ domain: domain, force: forceRefresh })
            });
            
            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.error);
            }
            
            // 显示查询结果
            showWhoisResult(domain, data);
            
        } catch (error) {
            console.error('手动查询失败: ' + domain, error);
            showToast('error', '查询失败: ' + error.message);
        } finally {
            hideLoading();
        }
    }
    
    // 显示手动查询结果
    function showWhoisResult(domain, data) {
        currentWhoisDomain = domain;
        
        const modal = new bootstrap.Modal(document.getElementById('whoisModal'));
        document.getElementById('whoisDomainName').textContent = domain;
        document.getElementById('whoisLoading').style.display = 'none';
        document.getElementById('whoisContent').style.display = 'block';
        
        displayWhoisData(data, null);
        modal.show();
        
        showToast('success', \`域名 \${domain} 查询完成\`);
    }
    
    // 测试所有API密钥
    async function testAllApis() {
        showLoading('正在测试API密钥...');
        
        try {
            const response = await fetch('/api/update', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'test-apis' })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showApiTestResults(data.results);
                showToast('success', 'API测试完成');
            } else {
                throw new Error(data.error || 'API测试失败');
            }
            
        } catch (error) {
            console.error('API测试失败:', error);
            showToast('error', 'API测试失败: ' + error.message);
        } finally {
            hideLoading();
        }
    }
    
    // 显示API测试结果
    function showApiTestResults(results) {
        let message = 'API密钥测试结果:\\n\\n';
        
        results.forEach(result => {
            message += \`用户: \${result.username}\\n\`;
            message += \`状态: \${result.status}\\n\`;
            message += \`密钥: \${result.key}\\n\`;
            if (result.error) {
                message += \`错误: \${result.error}\\n\`;
            }
            message += \`错误次数: \${result.errorCount}\\n\\n\`;
        });
        
        alert(message);
    }
    
    // 清除所有缓存
    async function clearAllCache() {
        if (!confirm('确定要清除所有WHOIS缓存吗？这将导致下次查询需要重新获取数据。')) {
            return;
        }
        
        showLoading('正在清除缓存...');
        
        try {
            const response = await fetch('/api/update', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'clear-cache' })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showToast('success', data.message);
            } else {
                throw new Error(data.error || '清除缓存失败');
            }
            
        } catch (error) {
            console.error('清除缓存失败:', error);
            showToast('error', '清除缓存失败: ' + error.message);
        } finally {
            hideLoading();
        }
    }
    
    // API密钥管理功能
    function showApiKeyManager() {
        if (typeof bootstrap === 'undefined') {
            alert('Bootstrap未加载，请刷新页面重试');
            return;
        }
        const modal = new bootstrap.Modal(document.getElementById('apiKeyManagerModal'));
        refreshApiKeys();
        modal.show();
    }
    
    async function refreshApiKeys() {
        const tbody = document.getElementById('apiKeyTableBody');
        tbody.innerHTML = '<tr><td colspan="6" class="text-center">加载中...</td></tr>';
        
        try {
            const response = await fetch('/api/cf-keys');
            const data = await response.json();
            
            if (data.keys && data.keys.length > 0) {
                tbody.innerHTML = data.keys.map((key, index) => 
                    '<tr>' +
                        '<td>' + key.username + '</td>' +
                        '<td><code>' + key.key + '</code></td>' +
                        '<td>' +
                            '<span class="badge bg-' + (key.active ? 'success' : 'danger') + '">' +
                                (key.active ? '启用' : '禁用') +
                            '</span>' +
                        '</td>' +
                        '<td>' + key.errorCount + '</td>' +
                        '<td>' + (key.lastUsed ? new Date(key.lastUsed).toLocaleString() : '未使用') + '</td>' +
                        '<td>' +
                            '<div class="btn-group">' +
                                '<button class="btn btn-sm btn-outline-' + (key.active ? 'warning' : 'success') + '" ' +
                                        'data-key="' + key.key + '" onclick="toggleApiKeyByData(this)">' +
                                    (key.active ? '禁用' : '启用') +
                                '</button>' +
                                '<button class="btn btn-sm btn-outline-danger" ' +
                                        'data-key="' + key.key + '" onclick="removeApiKeyByData(this)">' +
                                    '删除' +
                                '</button>' +
                            '</div>' +
                        '</td>' +
                    '</tr>'
                ).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">暂无API密钥</td></tr>';
            }
        } catch (error) {
            console.error('加载API密钥失败:', error);
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-danger">加载失败</td></tr>';
        }
    }
    
    async function addApiKey() {
        const keyInput = document.getElementById('newApiKey');
        const usernameInput = document.getElementById('newApiUsername');
        
        const key = keyInput.value.trim();
        const username = usernameInput.value.trim();
        
        if (!key || !username) {
            showToast('error', '请填写API密钥和用户名');
            return;
        }
        
        try {
            const response = await fetch('/api/cf-keys', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'add', key, username })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showToast('success', data.message);
                keyInput.value = '';
                usernameInput.value = '';
                refreshApiKeys();
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            console.error('添加API密钥失败:', error);
            showToast('error', '添加失败: ' + error.message);
        }
    }
    
    async function toggleApiKey(key) {
        try {
            const response = await fetch('/api/cf-keys', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'toggle', key })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showToast('success', data.message);
                refreshApiKeys();
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            console.error('切换API密钥状态失败:', error);
            showToast('error', '操作失败: ' + error.message);
        }
    }
    
    async function removeApiKey(key) {
        if (!confirm('确定要删除这个API密钥吗？')) {
            return;
        }
        
        try {
            const response = await fetch('/api/cf-keys', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'remove', key })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showToast('success', data.message);
                refreshApiKeys();
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            console.error('删除API密钥失败:', error);
            showToast('error', '删除失败: ' + error.message);
        }
    }
    
    // Helper functions for data attribute approach
    function toggleApiKeyByData(button) {
        const key = button.getAttribute('data-key');
        toggleApiKey(key);
    }
    
    function removeApiKeyByData(button) {
        const key = button.getAttribute('data-key');
        removeApiKey(key);
    }
    
    // 自定义域名管理功能
    function showAddCustomDomain() {
        if (typeof bootstrap === 'undefined') {
            alert('Bootstrap未加载，请刷新页面重试');
            return;
        }
        const modal = new bootstrap.Modal(document.getElementById('addCustomDomainModal'));
        // 清空表单
        document.getElementById('addCustomDomainForm').reset();
        modal.show();
    }
    
    async function saveCustomDomain() {
        const form = document.getElementById('addCustomDomainForm');
        const formData = new FormData(form);
        
        const domain = document.getElementById('customDomainName').value.trim();
        if (!domain) {
            showToast('error', '请输入域名');
            return;
        }
        
        const info = {
            registrar: document.getElementById('customDomainRegistrar').value || 'Unknown',
            registrationDate: document.getElementById('customDomainRegDate').value || new Date().toISOString().split('T')[0],
            expirationDate: document.getElementById('customDomainExpDate').value || 'Unknown',
            status: document.getElementById('customDomainStatus').value,
            nameServers: document.getElementById('customDomainNS').value.split(',').map(ns => ns.trim()).filter(ns => ns),
            notes: document.getElementById('customDomainNotes').value,
            serviceProvider: document.getElementById('customDomainServiceProvider').value || 'Unknown DNS'
        };
        
        try {
            const response = await fetch('/api/custom-domains', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'add', domain, info })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showToast('success', data.message);
                const modal = bootstrap?.Modal?.getInstance(document.getElementById('addCustomDomainModal'));
                if (modal) modal.hide();
                setTimeout(() => location.reload(), 1000);
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            console.error('添加自定义域名失败:', error);
            showToast('error', '添加失败: ' + error.message);
        }
    }
    
    // 域名编辑功能
    function editDomain(domain, isCustom) {
        if (typeof bootstrap === 'undefined') {
            alert('Bootstrap未加载，请刷新页面重试');
            return;
        }
        const modal = new bootstrap.Modal(document.getElementById('editDomainModal'));
        
        // 设置基础信息
        document.getElementById('editDomainOriginalName').value = domain;
        document.getElementById('editDomainName').value = domain;
        document.getElementById('editDomainIsCustom').value = isCustom;
        
        // 显示/隐藏自定义域名特有字段
        const customFields = document.getElementById('customDomainFields');
        const notesField = document.getElementById('notesField');
        
        if (isCustom) {
            customFields.style.display = 'flex';
            notesField.style.display = 'block';
        } else {
            customFields.style.display = 'none';
            notesField.style.display = 'none';
        }
        
        // 加载现有数据 - 从DOM中获取
        const row = document.querySelector('tr[data-domain="' + domain + '"]');
        if (row) {
            const cells = row.querySelectorAll('td');
            // 新的列顺序：状态(0), 域名(1), 注册商(2), 注册日期(3), 过期日期(4), 剩余天数(5), 服务商(6), 操作(7)
            document.getElementById('editDomainRegistrar').value = cells[2].textContent.trim();
            
            // 设置服务商字段 (如果是管理员并且有这个字段)
            if (cells.length > 6) {
                document.getElementById('editDomainServiceProvider').value = cells[6].textContent.trim();
            }
            
            // 尝试解析日期
            const regDate = cells[3].textContent.trim();
            const expDate = cells[4].textContent.trim();
            
            if (regDate !== 'Unknown' && regDate !== 'Error' && regDate !== '-') {
                try {
                    const date = new Date(regDate);
                    if (!isNaN(date.getTime())) {
                        document.getElementById('editDomainRegDate').value = date.toISOString().split('T')[0];
                    }
                } catch (e) {}
            }
            
            if (expDate !== 'Unknown' && expDate !== 'Error' && expDate !== '-' && expDate !== 'Auto-Renewal') {
                try {
                    const date = new Date(expDate);
                    if (!isNaN(date.getTime())) {
                        document.getElementById('editDomainExpDate').value = date.toISOString().split('T')[0];
                    }
                } catch (e) {}
            }
        }
        
        modal.show();
    }
    
    async function saveEditedDomain() {
        const domain = document.getElementById('editDomainOriginalName').value;
        const isCustom = document.getElementById('editDomainIsCustom').value === 'true';
        
        const info = {
            registrar: document.getElementById('editDomainRegistrar').value,
            registrationDate: document.getElementById('editDomainRegDate').value,
            expirationDate: document.getElementById('editDomainExpDate').value,
            serviceProvider: document.getElementById('editDomainServiceProvider').value
        };
        
        // 检查是否为免费域名且注册日期被修改
        const freeDomains = ['eu.org', 'pp.ua', 'qzz.io', 'us.kg', 'xx.kg', 'dpdns.org'];
        const isFreedomainEdited = freeDomains.some(freeDomain => 
            domain === freeDomain || domain.endsWith('.' + freeDomain)
        );
        
        // 免费域名现在完全依赖手动填写的过期日期，不再自动计算
        
        if (isCustom) {
            info.status = document.getElementById('editDomainStatus').value;
            info.nameServers = document.getElementById('editDomainNS').value.split(',').map(ns => ns.trim()).filter(ns => ns);
            info.notes = document.getElementById('editDomainNotes').value;
        }
        
        try {
            const response = await fetch('/api/custom-domains', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'update', domain, info })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showToast('success', data.message);
                const modal = bootstrap?.Modal?.getInstance(document.getElementById('editDomainModal'));
                if (modal) modal.hide();
                
                // 更新表格中的域名信息而不刷新页面
                await updateDomainRow(domain, info);
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            console.error('更新域名失败:', error);
            showToast('error', '更新失败: ' + error.message);
        }
    }
    
    // 更新表格中特定域名的行信息
    async function updateDomainRow(domain, updatedInfo) {
        try {
            // 找到对应的表格行
            const rows = document.querySelectorAll('.domain-table tbody tr');
            let targetRow = null;
            
            for (const row of rows) {
                const domainCell = row.cells[1]; // 域名在第2列（索引1）
                if (domainCell && domainCell.textContent.trim() === domain) {
                    targetRow = row;
                    break;
                }
            }
            
            if (!targetRow) {
                console.warn('未找到域名行:', domain);
                return;
            }
            
            // 更新注册商（第3列，索引2）
            if (updatedInfo.registrar) {
                targetRow.cells[2].textContent = updatedInfo.registrar;
            }
            
            // 更新注册日期（第4列，索引3）
            if (updatedInfo.registrationDate) {
                const regDate = new Date(updatedInfo.registrationDate);
                targetRow.cells[3].textContent = regDate.toLocaleDateString('zh-CN');
            }
            
            // 更新过期日期（第5列，索引4）
            if (updatedInfo.expirationDate) {
                const expDate = new Date(updatedInfo.expirationDate);
                targetRow.cells[4].textContent = expDate.toLocaleDateString('zh-CN');
            }
            
            // 重新计算并更新剩余天数（第6列，索引5）
            if (updatedInfo.expirationDate) {
                try {
                    // 检查是否为Auto-Renewal类型
                    if (updatedInfo.expirationDate === 'Auto-Renewal') {
                        targetRow.cells[5].innerHTML = '<div class="progress" style="height: 20px; position: relative;"><div class="progress-bar bg-info" role="progressbar" style="width: 100%;" title="自动续期域名"></div><span style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: bold; color: white;">∞</span></div>';
                        return;
                    }
                    
                    const expDate = new Date(updatedInfo.expirationDate);
                    const now = new Date();
                    const daysUntilExpiry = Math.ceil((expDate - now) / (1000 * 60 * 60 * 24));
                    
                    let statusInfo;
                    if (daysUntilExpiry <= 0) {
                        statusInfo = {
                            progressBar: '<div class="progress" style="height: 20px; position: relative;"><div class="progress-bar bg-danger" role="progressbar" style="width: 100%;" title="过期 ' + Math.abs(daysUntilExpiry) + ' 天"></div><span style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: bold; color: white;">' + daysUntilExpiry + '天</span></div>'
                        };
                    } else if (daysUntilExpiry <= 30) {
                        const percentage = Math.max((daysUntilExpiry / 30) * 100, 5);
                        statusInfo = {
                            progressBar: '<div class="progress" style="height: 20px; position: relative;"><div class="progress-bar bg-warning" role="progressbar" style="width: ' + percentage + '%;" title="将在 ' + daysUntilExpiry + ' 天后过期"></div><span style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: bold; color: black;">' + daysUntilExpiry + '天</span></div>'
                        };
                    } else {
                        const maxDays = 365;
                        const percentage = Math.min((daysUntilExpiry / maxDays) * 100, 100);
                        statusInfo = {
                            progressBar: '<div class="progress" style="height: 20px; position: relative;"><div class="progress-bar bg-success" role="progressbar" style="width: ' + percentage + '%;" title="' + daysUntilExpiry + ' 天后过期"></div><span style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: bold; color: white;">' + daysUntilExpiry + '天</span></div>'
                        };
                    }
                    
                    targetRow.cells[5].innerHTML = statusInfo.progressBar;
                } catch (error) {
                    console.error('日期计算错误:', error);
                    targetRow.cells[5].innerHTML = '<div class="progress" style="height: 20px; position: relative;"><div class="progress-bar bg-secondary" role="progressbar" style="width: 100%;" title="日期格式错误"></div><span style="position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: bold; color: white;">N/A</span></div>';
                }
            }
            
            // 更新服务商（第7列，索引6）
            if (updatedInfo.serviceProvider && targetRow.cells[6]) {
                targetRow.cells[6].textContent = updatedInfo.serviceProvider;
            }
            
            console.log('域名行更新成功:', domain);
        } catch (error) {
            console.error('更新域名行失败:', error);
            // 如果更新失败，回退到刷新页面
            setTimeout(() => location.reload(), 1000);
        }
    }
    
    async function deleteCustomDomain(domain) {
        if (!confirm('确定要删除自定义域名 ' + domain + ' 吗？')) {
            return;
        }
        
        try {
            const response = await fetch('/api/custom-domains', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'remove', domain })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showToast('success', data.message);
                setTimeout(() => location.reload(), 1000);
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            console.error('删除域名失败:', error);
            showToast('error', '删除失败: ' + error.message);
        }
    }
    
    // 分组折叠功能
    function toggleGroup(groupKey) {
        const content = document.getElementById('group-' + groupKey);
        const button = document.getElementById('toggle-' + groupKey);
        const icon = button.querySelector('i');
        
        if (content.style.display === 'none') {
            content.style.display = 'block';
            icon.className = 'fas fa-chevron-up';
        } else {
            content.style.display = 'none';
            icon.className = 'fas fa-chevron-down';
        }
    }
  `;
}

function generateLoginHTML(title, action, errorMessage = "") {
  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title} - Domain Keeper</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            position: relative;
            overflow: hidden;
        }
        
        /* 动画背景 */
        body::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 1px, transparent 1px);
            background-size: 30px 30px;
            animation: backgroundMove 20s ease-in-out infinite alternate;
            z-index: 0;
        }
        
        @keyframes backgroundMove {
            0% { transform: translate(0, 0) rotate(0deg); }
            100% { transform: translate(-20px, -20px) rotate(5deg); }
        }
        
        .container {
            position: relative;
            z-index: 1;
        }
        
        .login-container {
            max-width: 420px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .login-card {
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.3), 0 8px 24px rgba(0,0,0,0.1);
            border: none;
            backdrop-filter: blur(20px);
            background: rgba(255,255,255,0.98);
            overflow: hidden;
            transform: translateY(0);
            transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
        }
        
        .login-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 25px 50px rgba(0,0,0,0.35), 0 12px 30px rgba(0,0,0,0.15);
        }
        
        .login-header {
            background: linear-gradient(135deg, #0d6efd 0%, #0856d3 50%, #6f42c1 100%);
            color: white;
            padding: 3rem 2rem 2.5rem;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        
        .login-header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 1px, transparent 1px);
            background-size: 20px 20px;
            animation: headerFloat 15s ease-in-out infinite;
        }
        
        @keyframes headerFloat {
            0%, 100% { transform: translate(0, 0) rotate(0deg); }
            50% { transform: translate(-10px, -10px) rotate(2deg); }
        }
        
        .logo-icon {
            font-size: 3.5rem;
            margin-bottom: 1rem;
            position: relative;
            z-index: 2;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
            animation: logoGlow 3s ease-in-out infinite alternate;
        }
        
        @keyframes logoGlow {
            0% { text-shadow: 0 2px 4px rgba(0,0,0,0.3), 0 0 20px rgba(255,255,255,0.1); }
            100% { text-shadow: 0 2px 4px rgba(0,0,0,0.3), 0 0 30px rgba(255,255,255,0.3); }
        }
        
        .login-header h4 {
            position: relative;
            z-index: 2;
            text-shadow: 0 2px 4px rgba(0,0,0,0.2);
            letter-spacing: 0.5px;
        }
        
        .login-header p {
            position: relative;
            z-index: 2;
            opacity: 0.9;
        }
        
        .login-body {
            padding: 2.5rem;
            background: white;
        }
        
        .form-label {
            color: #2c3e50;
            font-weight: 600;
            margin-bottom: 0.75rem;
            font-size: 0.95rem;
        }
        
        .form-control {
            border-radius: 12px;
            border: 2px solid #e8ecf0;
            padding: 0.875rem 1rem;
            transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
            font-size: 1rem;
            background: #fafbfc;
        }
        
        .form-control:focus {
            border-color: #0d6efd;
            box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.15);
            background: white;
            transform: translateY(-1px);
        }
        
        .input-group {
            border-radius: 12px;
            overflow: hidden;
        }
        
        .input-group .form-control {
            border-left: none;
            border-radius: 0 12px 12px 0;
        }
        
        .input-group-text {
            background: linear-gradient(135deg, #0d6efd, #0856d3);
            color: white;
            border: 2px solid #0d6efd;
            border-right: none;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .btn-login {
            border-radius: 12px;
            padding: 1rem 2rem;
            font-weight: 600;
            font-size: 1.05rem;
            background: linear-gradient(135deg, #0d6efd 0%, #0856d3 50%, #6f42c1 100%) !important;
            border: none !important;
            color: white !important;
            transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
            text-transform: none;
            letter-spacing: 0.5px;
            box-shadow: 0 4px 15px rgba(13, 110, 253, 0.3);
            position: relative;
            overflow: hidden;
        }
        
        .btn-login::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }
        
        .btn-login:hover {
            transform: translateY(-3px) !important;
            box-shadow: 0 8px 25px rgba(13, 110, 253, 0.4) !important;
            background: linear-gradient(135deg, #0856d3 0%, #6f42c1 50%, #0d6efd 100%) !important;
        }
        
        .btn-login:hover::before {
            left: 100%;
        }
        
        .btn-login:active {
            transform: translateY(-1px) !important;
        }
        
        .btn-login:disabled {
            opacity: 0.7;
            transform: none !important;
        }
        
        .alert {
            border-radius: 12px;
            border: none;
            padding: 1rem 1.25rem;
            background: rgba(220, 53, 69, 0.1);
            color: #721c24;
            border-left: 4px solid #dc3545;
        }
        
        .footer-links {
            text-align: center;
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid #e8ecf0;
        }
        
        .footer-links small {
            color: #6c757d;
            font-size: 0.875rem;
        }
        
        .footer-links a {
            color: #0d6efd;
            text-decoration: none;
            margin: 0 0.5rem;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        
        .footer-links a:hover {
            color: #0856d3;
            text-decoration: underline;
        }
        
        /* 响应式设计 */
        @media (max-width: 576px) {
            .login-container {
                max-width: 95%;
                padding: 15px;
            }
            
            .login-header {
                padding: 2rem 1.5rem;
            }
            
            .login-body {
                padding: 2rem 1.5rem;
            }
            
            .logo-icon {
                font-size: 2.5rem;
            }
        }
        
        /* 加载动画 */
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translate3d(0, 40px, 0);
            }
            to {
                opacity: 1;
                transform: translate3d(0, 0, 0);
            }
        }
        
        .login-card {
            animation: fadeInUp 0.8s ease-out;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-container">
            <div class="card login-card">
                <div class="login-header">
                    <div class="logo-icon">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <h4 class="mb-0 fw-bold">Domain Keeper</h4>
                    <p class="mb-0">${title}</p>
                </div>
                <div class="login-body">
                    ${errorMessage ? `
                    <div class="alert alert-danger border-danger" role="alert">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        ${errorMessage}
                    </div>
                    ` : ''}
                    
                    <form method="POST" action="${action}">
                        <div class="mb-4">
                            <label for="password" class="form-label">
                                <i class="fas fa-lock me-2"></i>访问密码
                            </label>
                            <div class="input-group">
                                <span class="input-group-text">
                                    <i class="fas fa-key"></i>
                                </span>
                                <input type="password" 
                                       class="form-control" 
                                       id="password" 
                                       name="password" 
                                       placeholder="请输入访问密码"
                                       required 
                                       autocomplete="current-password">
                                <button class="btn btn-outline-secondary" 
                                        type="button" 
                                        onclick="togglePassword()"
                                        title="显示/隐藏密码"
                                        style="border-color: #e8ecf0; color: #6c757d; border-radius: 0 12px 12px 0;">
                                    <i class="fas fa-eye" id="passwordToggleIcon"></i>
                                </button>
                            </div>
                            <div class="form-text mt-2">
                                <i class="fas fa-info-circle me-1"></i>
                                <small class="text-muted">请输入您的管理员密码以访问域名管理面板</small>
                            </div>
                        </div>
                        
                        <div class="d-grid">
                            <button type="submit" class="btn btn-primary btn-login">
                                <i class="fas fa-sign-in-alt me-2"></i>
                                登录
                            </button>
                        </div>
                    </form>
                    
                    <div class="footer-links">
                        <small class="text-muted">
                            <i class="fas fa-info-circle me-1"></i>
                            Domain Keeper ${CONFIG.VERSION}
                        </small>
                        <br>
                        <small class="text-muted mt-2 d-block">
                            专业的域名监控和管理工具
                        </small>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 密码显示/隐藏功能
        function togglePassword() {
            const passwordField = document.getElementById('password');
            const toggleIcon = document.getElementById('passwordToggleIcon');
            const toggleBtn = toggleIcon.parentElement;
            
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                toggleIcon.classList.remove('fa-eye');
                toggleIcon.classList.add('fa-eye-slash');
                toggleBtn.setAttribute('title', '隐藏密码');
            } else {
                passwordField.type = 'password';
                toggleIcon.classList.remove('fa-eye-slash');
                toggleIcon.classList.add('fa-eye');
                toggleBtn.setAttribute('title', '显示密码');
            }
        }
        
        // 登录表单增强
        document.addEventListener('DOMContentLoaded', function() {
            console.log('🚀 Domain Keeper 登录页面初始化');
            
            const form = document.querySelector('form');
            const submitBtn = form.querySelector('button[type="submit"]');
            const passwordField = document.getElementById('password');
            const originalBtnText = submitBtn.innerHTML;
            
            // 表单提交处理
            form.addEventListener('submit', function(e) {
                if (submitBtn.disabled) return;
                
                const password = passwordField.value.trim();
                if (!password) {
                    e.preventDefault();
                    passwordField.focus();
                    passwordField.classList.add('is-invalid');
                    setTimeout(() => passwordField.classList.remove('is-invalid'), 3000);
                    return;
                }
                
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>验证中...';
                submitBtn.style.transform = 'translateY(0)';
            });
            
            // 密码输入框事件
            passwordField.addEventListener('input', function() {
                this.classList.remove('is-invalid');
            });
            
            passwordField.addEventListener('focus', function() {
                this.parentElement.parentElement.classList.add('focused');
            });
            
            passwordField.addEventListener('blur', function() {
                this.parentElement.parentElement.classList.remove('focused');
            });
            
            // 自动聚焦到密码输入框
            setTimeout(() => {
                passwordField.focus();
            }, 300);
            
            // 回车键支持
            passwordField.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    form.requestSubmit();
                }
            });
            
            // 添加输入验证样式
            const style = document.createElement('style');
            style.textContent = 
                '.form-control.is-invalid {' +
                '    border-color: #dc3545 !important;' +
                '    box-shadow: 0 0 0 0.25rem rgba(220, 53, 69, 0.15) !important;' +
                '    animation: shake 0.5s ease-in-out;' +
                '}' +
                '' +
                '.focused .input-group-text {' +
                '    background: linear-gradient(135deg, #0856d3, #6f42c1) !important;' +
                '    transform: scale(1.05);' +
                '}' +
                '' +
                '@keyframes shake {' +
                '    0%, 100% { transform: translateX(0); }' +
                '    25% { transform: translateX(-5px); }' +
                '    75% { transform: translateX(5px); }' +
                '}';
            document.head.appendChild(style);
        });
    </script>
    <style>.mb-3 {margin-bottom: 0rem !important;}.bg-euorg{background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);}</style>
</body>
</html>`;
}

