// 表单模板：客户端克隆到 <dialog> 中，避免在 JS 字符串里拼 HTML
import { icon } from './icons.js';

function closeBtn() {
  return '<button type="button" class="icon-btn" data-action="close-modal" aria-label="关闭">' + icon('x', 16) + '</button>';
}

export function formsHtml() {
  return `
<template id="tpl-add-domain">
  <form data-form="add-domain" class="modal-panel">
    <div class="m-head"><h3>添加域名</h3>${closeBtn()}</div>
    <div class="m-body">
      <label class="frow"><span>域名</span><input class="input" name="domain" placeholder="example.com" required autocomplete="off" spellcheck="false"></label>
      <label class="frow"><span>备注</span><textarea class="input" name="notes" rows="3" placeholder="续费渠道、预算、客户信息…（可选）"></textarea></label>
      <p class="hint">添加后会立即查询一次 WHOIS：查到注册商与到期日就直接写入；查不到才会让你补填。</p>
      <p class="err-text" data-error hidden></p>
    </div>
    <div class="m-foot">
      <button type="button" class="btn ghost" data-action="close-modal">取消</button>
      <button class="btn primary" type="submit">添加并查询</button>
    </div>
  </form>
</template>

<template id="tpl-edit-domain">
  <form data-form="edit-domain" class="modal-panel">
    <div class="m-head"><h3>编辑域名</h3>${closeBtn()}</div>
    <div class="m-body">
      <div class="callout warn" data-notice hidden style="margin-bottom:14px"></div>
      <div class="frow"><span>域名</span><div class="mono" data-field="name" style="font-size:13px;padding:8px 0"></div></div>
      <div class="grid2">
        <label class="frow"><span>注册商</span><input class="input" name="registrar" placeholder="Unknown"></label>
        <label class="frow"><span>DNS 服务商</span><input class="input" name="serviceProvider" placeholder="外部 DNS"></label>
      </div>
      <div class="grid2">
        <label class="frow"><span>注册日期</span><input class="input" name="registrationDate" type="date"></label>
        <label class="frow"><span>到期日期</span><input class="input" name="expirationDate" type="date"></label>
      </div>
      <label class="frow"><span>备注</span><textarea class="input" name="notes" rows="3"></textarea></label>
      <p class="hint">改了注册商或日期，就以你填的为准并停止 WHOIS 自动更新；只改备注不受影响。</p>
      <p class="err-text" data-error hidden></p>
    </div>
    <div class="m-foot">
      <button type="button" class="btn ghost" data-action="close-modal">取消</button>
      <button class="btn primary" type="submit">保存修改</button>
    </div>
  </form>
</template>

<template id="tpl-manual-query">
  <form data-form="manual-query" class="modal-panel">
    <div class="m-head"><h3>手动 WHOIS 查询</h3>${closeBtn()}</div>
    <div class="m-body">
      <label class="frow"><span>域名</span><input class="input" name="domain" placeholder="example.com" required autocomplete="off"></label>
      <label class="frow" style="grid-template-columns:auto 1fr;align-items:center;gap:8px;display:flex">
        <input type="checkbox" name="force"> <span>忽略缓存，强制重新查询</span>
      </label>
      <div data-result hidden><div class="result" data-result-body></div></div>
      <p class="err-text" data-error hidden></p>
    </div>
    <div class="m-foot">
      <button type="button" class="btn ghost" data-action="close-modal">关闭</button>
      <button class="btn primary" type="submit">查询</button>
    </div>
  </form>
</template>

<template id="tpl-account">
  <form data-form="account" class="modal-panel">
    <div class="m-head"><h3 data-field="mode">添加 Cloudflare 账户</h3>${closeBtn()}</div>
    <div class="m-body">
      <div class="grid2">
        <label class="frow"><span>显示名称</span><input class="input" name="label" placeholder="例如：主账户" autocomplete="off"></label>
        <label class="frow"><span>账户标识 <em class="req">*</em></span><input class="input" name="username" placeholder="域名列表里的分组名" required autocomplete="off"></label>
      </div>
      <label class="frow"><span>API Token <em class="req" data-token-req>*</em></span>
        <input class="input" name="token" placeholder="粘贴 Cloudflare API Token" autocomplete="off">
        <span class="hint" data-token-hint>需要 Zone:Read 权限。保存前会先验证 Token 是否真的能读 Zone 列表。</span></label>
      <label class="frow"><span>备注</span><input class="input" name="note" placeholder="可选，例如：客户 A / 备用账户"></label>
      <p class="err-text" data-error hidden></p>
    </div>
    <div class="m-foot">
      <button type="button" class="btn ghost" data-action="close-modal">取消</button>
      <button class="btn primary" type="submit">保存</button>
    </div>
  </form>
</template>

<template id="tpl-dnshe">
  <form data-form="dnshe" class="modal-panel">
    <div class="m-head"><h3 data-field="mode">添加 DNSHE 凭证</h3>${closeBtn()}</div>
    <div class="m-body">
      <label class="frow"><span>名称（可选）</span><input class="input" name="label" placeholder="例如：DNSHE 主账户" autocomplete="off"></label>
      <label class="frow"><span>API Key <em class="req">*</em></span>
        <input class="input" name="key" placeholder="cfsd_xxxxxxxxxx" autocomplete="off" required></label>
      <label class="frow"><span>API Secret <em class="req" data-secret-req>*</em></span>
        <input class="input" name="secret" type="password" placeholder="创建密钥时给出的 Secret" autocomplete="new-password">
        <span class="hint" data-secret-hint>在 DNSHE 客户区 → 我的域名管理 → API 管理 里创建。</span></label>
      <p class="err-text" data-error hidden></p>
    </div>
    <div class="m-foot">
      <button type="button" class="btn ghost" data-action="close-modal">取消</button>
      <button class="btn primary" type="submit">保存</button>
    </div>
  </form>
</template>

<template id="tpl-channel">
  <form data-form="channel" class="modal-panel">
    <div class="m-head"><h3 data-field="mode">添加通知渠道</h3>${closeBtn()}</div>
    <div class="m-body">
      <label class="frow"><span>渠道类型 <em class="req">*</em></span>
        <select class="input" name="type" data-channel-type></select></label>
      <label class="frow"><span>名称（可选）</span><input class="input" name="label" placeholder="例如：运维群"></label>
      <div data-channel-fields style="display:grid;gap:12px"></div>
      <p class="hint" data-channel-desc></p>
      <label class="inline-check"><input type="checkbox" name="enabled" checked><span>启用这个渠道</span></label>
      <p class="err-text" data-error hidden></p>
    </div>
    <div class="m-foot">
      <button type="button" class="btn ghost" data-action="close-modal">取消</button>
      <button class="btn primary" type="submit">保存</button>
    </div>
  </form>
</template>

<template id="tpl-free-domain">
  <form data-form="free-domain" class="modal-panel">
    <div class="m-head"><h3 data-field="mode">添加免费域名后缀</h3>${closeBtn()}</div>
    <div class="m-body">
      <label class="frow"><span>后缀</span><input class="input" name="suffix" placeholder="is-a.dev" required autocomplete="off"></label>
      <div class="grid2">
        <label class="frow"><span>类型</span><select class="input" name="category">
          <option value="free">免费注册</option>
          <option value="public">公益 / 永久</option>
        </select></label>
        <label class="frow"><span>续期模式</span><select class="input" name="renew">
          <option value="auto">自动续期</option>
          <option value="permanent">永久</option>
          <option value="manual">人工维护</option>
        </select></label>
      </div>
      <div class="grid2">
        <label class="frow"><span>注册商</span><input class="input" name="registrar" placeholder="NIC.UA"></label>
        <label class="frow"><span>服务商</span><input class="input" name="provider" placeholder="pp.ua"></label>
      </div>
      <div class="grid2">
        <label class="frow"><span>查询方式</span><select class="input" name="lookupType">
          <option value="">仅用元数据</option>
          <option value="rdap">RDAP</option>
          <option value="dnshe">DNSHE API</option>
          <option value="whois">WHOIS / TCP</option>
        </select></label>
        <label class="frow" data-endpoint-row hidden><span>查询端点</span><input class="input" name="endpoint" placeholder="whois.pp.ua:43"></label>
      </div>
      <p class="hint" data-endpoint-hint></p>
      <label class="frow"><span>说明</span><input class="input" name="note" placeholder="例如：社区公益域名"></label>
      <p class="hint">命中后缀的域名不再查询 WHOIS，直接按注册表规则处理。公益类按永久处理，不参与到期告警。</p>
      <p class="err-text" data-error hidden></p>
    </div>
    <div class="m-foot">
      <button type="button" class="btn ghost" data-action="close-modal">取消</button>
      <button class="btn primary" type="submit">保存</button>
    </div>
  </form>
</template>

<template id="tpl-confirm">
  <div class="modal-panel">
    <div class="m-head"><h3 data-confirm-title>确认操作</h3>${closeBtn()}</div>
    <div class="m-body"><p class="hint" data-confirm-text style="font-size:13px;color:var(--text-2)"></p></div>
    <div class="m-foot">
      <button type="button" class="btn ghost" data-action="close-modal">取消</button>
      <button class="btn primary" data-confirm-ok>确认</button>
    </div>
  </div>
</template>`;
}
