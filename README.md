# EdgeTunnel 网络优化工具（Cloudflare Workers）

通过将订阅请求发送至已部署在 Cloudflare 边缘网络的 Worker，改善 EdgeTunnel 等订阅更新时的网络可达性。它**只会拉取管理者白名单允许的 HTTPS 域名**：不会充当任意 URL 的开放代理。

## 使用格式

```text
https://你的-Worker-域名/https://你的订阅链接
```

例如，白名单中加入 `subscription.example.com` 后：

```text
https://edge.example.com/https://subscription.example.com/api/v1/client/subscribe?token=abc
```

可将 Worker 绑定到一个已优选/可访问性良好的 Cloudflare 自定义域名，访问链路为：**用户 → 已优选域名 → Cloudflare Worker → 已白名单订阅站**。

> 根路径 `/` 固定显示 nginx 默认欢迎页；管理入口仅为 `/admin`。

## 部署

### 1. 安装依赖并登录

```bash
npm install
npx wrangler login
```

### 2. 创建 KV 白名单存储

```bash
npx wrangler kv namespace create WHITELIST
```

把命令输出的 id 填入 [`wrangler.toml`](./wrangler.toml)：

```toml
[[kv_namespaces]]
binding = "WHITELIST"
id = "你的 KV namespace id"
```

### 3. 设置管理密码

在 Cloudflare Dashboard 中打开该 Worker：

**Settings → Variables and Secrets → Add → Text**

新增变量：

- 名称：`PASSWORD`
- 值：你自定义的强密码

`PASSWORD` 按需求采用 **Text** 变量；生产环境也可改用 Secret，功能相同。

也可以本地通过 Wrangler 设置：

```bash
npx wrangler secret put PASSWORD
```

### 4. 发布

```bash
npm run deploy
```

如使用自定义域名，请在 Worker 的 **Settings → Domains & Routes** 中绑定该域名。请确保域名已由 Cloudflare 代理（橙云）并按你的网络测试结果使用合适的优选域名。

## 管理中心与白名单

1. 打开 `https://你的域名/admin`。
2. 账号固定为 `admin`，密码为 `PASSWORD` 变量的值。
3. 添加订阅站的域名，例如 `subscription.example.com`。
4. 使用前述 URL 格式更新订阅。

白名单最初为空；此时每一个订阅请求均返回 **403 Forbidden**。域名加入后，该域名及其子域名可被请求。例如添加 `example.com` 会允许 `a.example.com`；若需最小授权，请添加订阅链接的精确主机名。

## 行为与安全限制

- 仅支持 `GET`、`HEAD` 和 HTTPS 目标地址。
- 未在白名单中的域名返回 403。
- `/admin` 使用带 `HttpOnly`、`Secure`、`SameSite=Strict` 属性的会话 Cookie；会话有效期为 8 小时。
- Worker 会跟随上游重定向，但初始请求地址必须通过白名单检查。
- 根路径 `/` 不是转发入口，固定返回 nginx 默认欢迎页面，以避免访问部署域名时出现 404。
- 请只加入你有权使用的订阅服务域名，并遵守服务条款与当地法律。

## 本地调试

本地需要配置 KV 和 `PASSWORD`。可以创建 `.dev.vars`（不要提交真实密码）：

```text
PASSWORD=your-local-password
```

随后执行：

```bash
npm run dev
```
