// KV 配置通用读写层
//
// 背景：这一版把原先散落在环境变量里的东西（Cloudflare 账户、访问密码、
// WHOIS 代理、查询节奏、通知渠道）全部搬到了 KV，让用户能在页面上直接改。
// 每个领域各写一遍「读 KV → 解析 JSON → 内存缓存 → 写回」既啰嗦又容易写错，
// 所以抽成这一层。
//
// 三个必须遵守的约束：
// 1. **读不抛异常**。配置坏了、KV 没绑定，都要退回默认值，不能把页面拖挂。
// 2. **写后立即失效缓存**。否则同一个 isolate 里刚保存完，下一个请求还读旧值，
//    用户会以为没保存成功。
// 3. **增删改必须读最新值再写**。KV 没有事务，读-改-写至少能避免把自己刚加的
//    条目覆盖掉（并发写仍可能丢，但概率远低于直接用内存里的旧数组）。

export const MEM_TTL = 60000;

/** @type {Map<string, {at: number, value: any}>} */
const cache = new Map();

/** 清掉某个 key 的缓存（写入后调用） */
export function invalidateConfig(key) {
  cache.delete(key);
}

/** 清掉全部缓存（测试用） */
export function __resetConfigCache() {
  cache.clear();
}

function fresh(key) {
  const hit = cache.get(key);
  if (!hit) return undefined;
  if (Date.now() - hit.at >= MEM_TTL) {
    cache.delete(key);
    return undefined;
  }
  return hit.value;
}

function remember(key, value) {
  cache.set(key, { at: Date.now(), value });
  return value;
}

/**
 * 读取并解析 JSON 配置。
 * @param {KVNamespace|null} kv
 * @param {string} key
 * @param {*} [fallback] 读不到或解析失败时返回它
 * @returns {Promise<*>}
 */
export async function readConfig(kv, key, fallback = null) {
  const hit = fresh(key);
  if (hit !== undefined) return hit;

  if (!kv) return fallback;

  try {
    const raw = await kv.get(key);
    if (raw === null || raw === undefined || raw === '') {
      // 空值也要缓存，避免每次请求都打一次 KV 去确认"确实没有"
      return remember(key, fallback);
    }
    const parsed = JSON.parse(raw);
    return remember(key, parsed);
  } catch (e) {
    // 解析失败不缓存：下次可能就被修好了
    return fallback;
  }
}

/**
 * 覆盖写入。
 * @param {KVNamespace} kv
 * @param {string} key
 * @param {*} value
 */
export async function writeConfig(kv, key, value) {
  if (!kv) throw new Error('KV 未绑定，无法保存配置');
  await kv.put(key, JSON.stringify(value));
  remember(key, value);
  return value;
}

/**
 * 读最新值（绕过缓存）后修改并写回。
 * @param {KVNamespace} kv
 * @param {string} key
 * @param {*} fallback
 * @param {(current: *) => *} mutator
 */
export async function mutateConfig(kv, key, fallback, mutator) {
  if (!kv) throw new Error('KV 未绑定，无法保存配置');

  let current = fallback;
  try {
    const raw = await kv.get(key);
    if (raw !== null && raw !== undefined && raw !== '') {
      current = JSON.parse(raw);
    }
  } catch (e) {
    current = fallback;
  }

  return writeConfig(kv, key, mutator(current));
}

/** 生成短 ID（8 位十六进制），用于账户/渠道条目标识 */
export function makeId(prefix = '') {
  const bytes = new Uint8Array(4);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return prefix ? prefix + '_' + hex : hex;
}

/**
 * 掩码：只露出首尾，避免把完整密钥回传到前端。
 *
 * URL 单独处理：机器人地址的 token 藏在路径末段，直接取前 6 位只会得到
 * `https:` 这种毫无信息量的前缀。这里保留 origin 与路径前缀、只遮蔽末段，
 * 用户既能看出"这是哪个平台哪个机器人"，又拿不到凭证。
 */
export function maskSecret(value, head = 6, tail = 4) {
  const text = String(value || '');
  if (!text) return '';

  if (/^https?:\/\//i.test(text)) {
    const cut = text.lastIndexOf('/');
    // 没有路径（https://host）就没有可遮的部分
    if (cut > text.indexOf('://') + 2) {
      const prefix = text.slice(0, cut + 1);
      const last = text.slice(cut + 1);
      if (!last) return text;
      const keep = last.length > tail ? last.slice(-tail) : '';
      return prefix + '••••••••' + keep;
    }
  }

  if (text.length <= head + tail + 2) return text.slice(0, 2) + '••••';
  return text.slice(0, head) + '••••••••' + text.slice(-tail);
}
