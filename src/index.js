const SESSION_COOKIE = "edgetunnel_admin";
const SESSION_TTL = 60 * 60 * 8;
const WHITELIST_KEY = "subscription-domain-whitelist";

/** @typedef {{ PASSWORD: string, WHITELIST: KVNamespace }} Env */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const securityHeaders = {
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "same-origin",
      "Cache-Control": "no-store",
    };

    if (url.pathname === "/") return nginxWelcome();
    if (url.pathname === "/favicon.ico") return new Response(null, { status: 204 });
    if (url.pathname === "/admin") return adminPage(request, env, securityHeaders);
    if (url.pathname === "/admin/login" && request.method === "POST") return login(request, env, securityHeaders);
    if (url.pathname === "/admin/logout" && request.method === "POST") return logout(securityHeaders);
    if (url.pathname === "/admin/api/whitelist") return whitelistApi(request, env, securityHeaders);

    return fetchSubscription(request, url, env, securityHeaders);
  },
};

function html(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=UTF-8", ...headers },
  });
}

function nginxWelcome() {
  return html(`<!doctype html><html><head><meta charset="utf-8"><title>Welcome to nginx!</title><style>body{width:35em;margin:4em auto;font-family:Tahoma,Arial,sans-serif;color:#333}h1{font-weight:normal}a{color:#157878}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p><p>For online documentation and support please refer to <a href="https://nginx.org/">nginx.org</a>.<br/>Commercial support is available at <a href="https://www.nginx.com/">nginx.com</a>.</p><p><em>Thank you for using nginx.</em></p></body></html>`);
}

async function adminPage(request, env, headers) {
  if (!isConfigured(env)) return html(errorPage("未配置 PASSWORD", "请先在 Cloudflare Workers 的 Settings → Variables and Secrets 中添加文本变量 PASSWORD。"), 503, headers);
  if (!hasValidSession(request, env)) return html(loginView(), 200, headers);
  if (!env.WHITELIST) return html(errorPage("未绑定 KV", "请创建 KV 命名空间，并以 WHITELIST 绑定到该 Worker。"), 503, headers);
  const domains = await getWhitelist(env);
  return html(adminView(domains), 200, headers);
}

async function login(request, env, headers) {
  if (!isConfigured(env)) return json({ error: "PASSWORD 未配置" }, 503, headers);
  const form = await request.formData();
  const username = String(form.get("username") || "");
  const password = String(form.get("password") || "");
  if (username !== "admin" || !safeEqual(password, env.PASSWORD)) return html(loginView("账号或密码错误。"), 401, headers);
  const token = await makeSessionToken(env);
  return new Response(null, {
    status: 303,
    headers: { ...headers, Location: "/admin", "Set-Cookie": `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL}` },
  });
}

function logout(headers) {
  return new Response(null, { status: 303, headers: { ...headers, Location: "/admin", "Set-Cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0` } });
}

async function whitelistApi(request, env, headers) {
  if (!hasValidSession(request, env)) return json({ error: "未登录" }, 401, headers);
  if (!env.WHITELIST) return json({ error: "未绑定 WHITELIST KV" }, 503, headers);
  if (request.method === "GET") return json({ domains: await getWhitelist(env) }, 200, headers);
  if (request.method !== "POST" && request.method !== "DELETE") return json({ error: "方法不允许" }, 405, headers);

  let data;
  try { data = await request.json(); } catch { return json({ error: "请求格式无效" }, 400, headers); }
  const domain = normalizeDomain(data.domain);
  if (!domain) return json({ error: "请输入有效域名，例如 example.com" }, 400, headers);
  const domains = await getWhitelist(env);
  const updated = request.method === "POST" ? [...new Set([...domains, domain])].sort() : domains.filter((item) => item !== domain);
  await env.WHITELIST.put(WHITELIST_KEY, JSON.stringify(updated));
  return json({ domains: updated }, 200, headers);
}

async function fetchSubscription(request, url, env, headers) {
  if (request.method !== "GET" && request.method !== "HEAD") return new Response("Method Not Allowed", { status: 405, headers });
  if (!env.WHITELIST) return new Response("Service unavailable: WHITELIST KV binding is missing.", { status: 503, headers });
  const domains = await getWhitelist(env);
  if (domains.length === 0) return new Response("Forbidden: subscription whitelist is empty.", { status: 403, headers });

  // 路径本身即目标完整 URL：/https://subscription.example.com/path
  const rawTarget = decodeURIComponent(url.pathname.slice(1)) + url.search;
  let target;
  try { target = new URL(rawTarget); } catch { return new Response("Not Found", { status: 404, headers }); }
  if (target.protocol !== "https:") return new Response("Bad Request: only HTTPS subscription URLs are allowed.", { status: 400, headers });
  if (!domainAllowed(target.hostname, domains)) return new Response("Forbidden: target domain is not in the whitelist.", { status: 403, headers });

  const upstreamHeaders = new Headers();
  for (const name of ["Accept", "Accept-Encoding", "User-Agent"]) {
    const value = request.headers.get(name);
    if (value) upstreamHeaders.set(name, value);
  }
  let upstream;
  try {
    // 手动处理重定向，避免白名单域名将请求导向任意第三方主机。
    let current = target;
    for (let redirects = 0; redirects <= 5; redirects++) {
      upstream = await fetch(current.toString(), { method: request.method, headers: upstreamHeaders, redirect: "manual" });
      if (![301, 302, 303, 307, 308].includes(upstream.status)) break;
      const location = upstream.headers.get("Location");
      if (!location) break;
      const next = new URL(location, current);
      if (next.protocol !== "https:" || !domainAllowed(next.hostname, domains)) return new Response("Forbidden: redirect target is not in the whitelist.", { status: 403, headers });
      if (redirects === 5) return new Response("Bad Gateway: too many redirects.", { status: 502, headers });
      current = next;
    }
  } catch {
    return new Response("Bad Gateway: unable to retrieve subscription.", { status: 502, headers });
  }

  const responseHeaders = new Headers(upstream.headers);
  for (const [name, value] of Object.entries(headers)) responseHeaders.set(name, value);
  responseHeaders.delete("Set-Cookie");
  responseHeaders.set("X-EdgeTunnel-Target", target.hostname);
  return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: responseHeaders });
}

async function getWhitelist(env) {
  try {
    const raw = await env.WHITELIST.get(WHITELIST_KEY);
    const values = raw ? JSON.parse(raw) : [];
    return Array.isArray(values) ? values.filter((item) => typeof item === "string" && normalizeDomain(item)).map(normalizeDomain) : [];
  } catch { return []; }
}

function normalizeDomain(input) {
  if (typeof input !== "string") return null;
  let domain = input.trim().toLowerCase().replace(/\.$/, "");
  if (domain.startsWith("https://") || domain.startsWith("http://")) { try { domain = new URL(domain).hostname; } catch { return null; } }
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) return null;
  return domain;
}

function domainAllowed(hostname, domains) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return domains.some((domain) => host === domain || host.endsWith(`.${domain}`));
}

function cookies(request) {
  return Object.fromEntries((request.headers.get("Cookie") || "").split(";").map((part) => { const i = part.indexOf("="); return i < 0 ? ["", ""] : [part.slice(0, i).trim(), part.slice(i + 1).trim()]; }));
}

async function makeSessionToken(env) {
  const expiry = Math.floor(Date.now() / 1000) + SESSION_TTL;
  const payload = `admin.${expiry}`;
  return `${payload}.${await sign(payload, env.PASSWORD)}`;
}

async function hasValidSession(request, env) {
  if (!isConfigured(env)) return false;
  const token = cookies(request)[SESSION_COOKIE];
  const parts = token?.split(".");
  if (!parts || parts.length !== 3 || parts[0] !== "admin" || Number(parts[1]) < Math.floor(Date.now() / 1000)) return false;
  return safeEqual(parts[2], await sign(`${parts[0]}.${parts[1]}`, env.PASSWORD));
}

async function sign(value, password) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(signature))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let result = 0; for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i); return result === 0;
}
function isConfigured(env) { return typeof env.PASSWORD === "string" && env.PASSWORD.length > 0; }
function json(data, status, headers) { return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=UTF-8", ...headers } }); }

function layout(title, content) { return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#0b1220"><title>${title}</title><style>:root{color-scheme:dark;--bg:#0b1220;--panel:#111c31e8;--line:#273753;--text:#f3f7ff;--muted:#9baac3;--blue:#5ba7ff;--cyan:#54e2d0;--red:#ff7784}*{box-sizing:border-box}body{min-height:100vh;margin:0;background:radial-gradient(900px 500px at 10% -10%,#1e5684 0%,transparent 65%),radial-gradient(750px 450px at 100% 10%,#243878 0%,transparent 68%),var(--bg);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}.shell{width:min(960px,calc(100% - 32px));margin:0 auto;padding:58px 0 44px}.brand{display:flex;gap:13px;align-items:center;margin-bottom:26px;color:#dce9ff;font-weight:700;letter-spacing:.02em}.brand-mark{display:grid;place-items:center;width:34px;height:34px;border-radius:11px;background:linear-gradient(135deg,var(--blue),var(--cyan));color:#07111d;font-size:18px;box-shadow:0 8px 24px #2584df55}.card{overflow:hidden;border:1px solid #ffffff18;border-radius:20px;background:var(--panel);box-shadow:0 24px 70px #00000045;backdrop-filter:blur(16px)}.card-head{padding:30px 32px 23px;border-bottom:1px solid var(--line)}.eyebrow{margin:0 0 8px;color:var(--cyan);font-size:12px;font-weight:700;letter-spacing:.11em;text-transform:uppercase}.card h1{margin:0;font-size:27px;line-height:1.25;letter-spacing:-.035em}.subtext,.muted{color:var(--muted)}.subtext{max-width:660px;margin:9px 0 0}.card-body{padding:28px 32px}.login-card{width:min(470px,100%);margin:10vh auto 0}.login-card .card-body{padding-top:25px}label{display:block;margin:0 0 7px;color:#dce6f7;font-size:13px;font-weight:650}input{width:100%;height:45px;margin:0 0 18px;padding:0 13px;outline:0;border:1px solid #344868;border-radius:10px;background:#091323aa;color:var(--text);font:inherit;transition:.18s}input::placeholder{color:#70819d}input:focus{border-color:var(--blue);box-shadow:0 0 0 4px #5ba7ff20}button{display:inline-flex;min-height:40px;align-items:center;justify-content:center;gap:7px;cursor:pointer;padding:0 14px;border:1px solid transparent;border-radius:10px;background:linear-gradient(135deg,#3d91f5,#5aaefc);color:#07111d;font:700 13px inherit;transition:transform .16s,filter .16s}button:hover{filter:brightness(1.09);transform:translateY(-1px)}button:active{transform:none}.danger{border-color:#ff778440;background:#ff778412;color:#ffabb3}.outline{border-color:#394d6d;background:transparent;color:#dbe7fa}.error{margin:0 0 20px;padding:11px 13px;border:1px solid #ff778447;border-radius:10px;background:#ff778412;color:#ffb1b8}.toolbar{display:flex;gap:12px;align-items:center;justify-content:space-between;margin-bottom:22px}.status{display:inline-flex;gap:8px;align-items:center;padding:6px 10px;border:1px solid #54e2d040;border-radius:99px;background:#54e2d010;color:#9ff9ec;font-size:12px;font-weight:650}.dot{width:7px;height:7px;border-radius:50%;background:var(--cyan);box-shadow:0 0 11px var(--cyan)}.add-form{display:grid;grid-template-columns:1fr auto;gap:10px;padding:16px;border:1px solid var(--line);border-radius:14px;background:#0a1425a6}.add-form input{margin:0}.list-title{display:flex;align-items:center;justify-content:space-between;margin:27px 0 10px;font-weight:700}.count{padding:2px 8px;border-radius:99px;background:#243754;color:#bed8ff;font-size:12px}ul{margin:0;padding:0;list-style:none}.domain-item{display:flex;min-height:58px;align-items:center;justify-content:space-between;gap:18px;padding:9px 12px 9px 16px;border:1px solid var(--line);border-bottom:0;background:#0b1526aa}.domain-item:first-child{border-radius:12px 12px 0 0}.domain-item:last-child{border-bottom:1px solid var(--line);border-radius:0 0 12px 12px}.domain-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#e9f2ff;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px}.empty{display:flex;flex-direction:column;align-items:center;padding:34px 15px;border:1px dashed #3c5272;border-radius:12px;color:var(--muted);text-align:center}.empty-icon{margin-bottom:8px;color:#f7c66e;font-size:25px}.help{display:grid;grid-template-columns:1fr auto;gap:18px;align-items:center;margin-top:25px;padding:17px;border:1px solid #31557a;border-radius:13px;background:#12325b3d}.help-title{margin-bottom:5px;font-weight:700}.help code{display:block;overflow:auto;padding:7px 9px;border:1px solid #355275;border-radius:7px;background:#081222;color:#a7d3ff;font-size:12px}.footer-actions{display:flex;justify-content:flex-end;margin-top:20px}@media(max-width:600px){.shell{width:min(100% - 22px,960px);padding-top:26px}.card-head,.card-body{padding-left:20px;padding-right:20px}.card h1{font-size:23px}.toolbar,.help{align-items:flex-start;flex-direction:column}.add-form{grid-template-columns:1fr}.add-form button{width:100%}.domain-item{padding-left:12px}.footer-actions{justify-content:stretch}.footer-actions button{width:100%}}</style></head><body><div class="shell"><div class="brand"><span class="brand-mark">↗</span><span>EDGETUNNEL <small style="color:#7f90aa;font-weight:600">NETWORK TOOL</small></span></div>${content}</div></body></html>`; }
function loginView(error = "") { return layout("EdgeTunnel 管理中心", `<section class="card login-card"><header class="card-head"><p class="eyebrow">管理员访问</p><h1>欢迎回来</h1><p class="subtext">登录后可管理允许更新的订阅域名。</p></header><div class="card-body">${error ? `<p class="error">${error}</p>` : ""}<form method="post" action="/admin/login"><label for="username">账号</label><input id="username" name="username" value="admin" required autocomplete="username"><label for="password">密码</label><input id="password" name="password" type="password" required autocomplete="current-password" autofocus><button style="width:100%" type="submit">进入管理中心 <span>→</span></button></form><p class="muted" style="margin:20px 0 0;font-size:12px">账号固定为 <code>admin</code>，密码取自 Worker 的 <code>PASSWORD</code> 变量。</p></div></section>`); }
function adminView(domains) { return layout("白名单管理", `<section class="card"><header class="card-head"><div class="toolbar"><div><p class="eyebrow">访问控制</p><h1>订阅域名白名单</h1></div><span class="status"><i class="dot"></i>防护已启用</span></div><p class="subtext">仅白名单中的域名可通过此 Worker 拉取订阅；空白名单会拒绝全部请求（403）。</p></header><div class="card-body"><form id="add" class="add-form"><input id="domain" aria-label="订阅域名" placeholder="输入域名，例如 sub.example.com" required><button type="submit">＋ 添加域名</button></form><div class="list-title"><span>已允许的域名</span><span class="count">${domains.length} 个</span></div><ul id="list">${domains.length ? domains.map((d) => `<li class="domain-item"><span class="domain-name">${d}</span><button class="danger" data-domain="${d}" type="button">删除</button></li>`).join("") : `<li class="empty"><span class="empty-icon">⚠</span><strong>白名单仍为空</strong><span>当前所有订阅请求都会返回 403 Forbidden。</span></li>`}</ul><aside class="help"><div><div class="help-title">订阅调用格式</div><span class="muted">将完整的订阅链接拼接在你的 Worker 域名后：</span></div><code>https://你的域名/https://订阅链接</code></aside><div class="footer-actions"><form method="post" action="/admin/logout"><button class="outline" type="submit">退出登录</button></form></div></div></section><script>const api='/admin/api/whitelist';async function update(method,domain){const r=await fetch(api,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify({domain})});const d=await r.json();if(!r.ok)return alert(d.error);location.reload()}document.querySelector('#add').onsubmit=e=>{e.preventDefault();update('POST',document.querySelector('#domain').value)};document.querySelectorAll('[data-domain]').forEach(b=>b.onclick=()=>update('DELETE',b.dataset.domain));</script>`); }
function errorPage(title, detail) { return layout(title, `<section class="card login-card"><header class="card-head"><p class="eyebrow">配置错误</p><h1>${title}</h1></header><div class="card-body"><p class="subtext">${detail}</p></div></section>`); }
