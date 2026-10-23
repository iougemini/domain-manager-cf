// `cloudflare:sockets` 的 Node 桩：只在冒烟测试里用来顶替 Workers 专有模块。
// 真机上这个模块由运行时提供；Node 里没有，所以打包时把它 alias 到这里。
// connect 一旦被调用说明测试路径走错了，直接抛错暴露出来。
export function connect() {
  throw new Error('cloudflare:sockets 在 Node 冒烟测试中不可用');
}
