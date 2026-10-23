// 测试用的 KV 桩：只实现业务代码真正用到的 get / put / delete / list。
// 放在 test/_ 前缀下，不会被 node --test 的 glob 当成用例文件。
//
// get 必须支持 { type: 'json' }：真实 KV 会按这个选项把值解析成对象，桩如果不实现，
// 调用方拿到的就是字符串，`typeof raw === 'object'` 恒为 false，读缓存永远"没命中"。
// 这类假通过不会报错，只会让被测功能静默失效——之前审计日志与限流器就这么被漏掉过。
export function fakeKV(initial = {}) {
  const store = new Map(Object.entries(initial));

  return {
    store,
    async get(key, options) {
      if (!store.has(key)) return null;
      const raw = store.get(key);
      if (options && options.type === 'json') {
        try {
          return JSON.parse(raw);
        } catch {
          return null;
        }
      }
      return raw;
    },
    async put(key, value, options = {}) {
      store.set(key, String(value));
      // TTL 在桩里只记录不生效，供断言"写入时确实带了过期时间"
      if (options && options.expirationTtl) {
        store.set(`__ttl:${key}`, String(options.expirationTtl));
      }
    },
    async delete(key) {
      store.delete(key);
    },
    async list(options = {}) {
      const prefix = options.prefix || '';
      return {
        keys: Array.from(store.keys())
          .filter(name => name.startsWith(prefix))
          .map(name => ({ name }))
      };
    }
  };
}

/** 读回某个 key 的 JSON，方便断言 */
export function readJSON(kv, key) {
  const raw = kv.store.get(key);
  return raw === undefined ? null : JSON.parse(raw);
}
