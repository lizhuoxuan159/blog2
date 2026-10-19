# blog2

基于 Cloudflare Pages + Pages Functions + D1 的个人博客系统，包含文章、评论、犇犇广场（公共聊天）、私信、放逐投票、用户管理等功能。

## 目录结构

```
blog2/
├── public/                  # 静态站点（Pages 构建输出目录）
│   ├── *.html               # 各页面（多页应用，无前端构建步骤）
│   ├── css/style.css
│   └── _headers / _redirects  # Pages 响应头与重定向规则（必须位于此目录，放仓库根目录不生效）
├── functions/api/           # Pages Functions 后端 API
│   ├── user.js              # 登录/注册/2FA/用户管理（路由 /api/user）
│   ├── post.js              # 文章/评论
│   ├── chat.js              # 犇犇广场/私信
│   ├── ban.js               # 放逐投票
│   ├── config.js            # 公开配置接口（/api/config，如 hCaptcha sitekey）
│   ├── githubCallback.js    # GitHub OAuth 回调（/api/githubCallback）
│   ├── codeforcesCallback.js# Codeforces OAuth 回调（/api/codeforcesCallback）
│   └── init/[[path]].js     # 管理员初始化（/api/init/）
├── init.sql                 # D1 数据库 Schema（新环境初始化用）
├── wrangler.toml            # Cloudflare 配置（D1 绑定等）
└── .github/workflows/       # CI/CD（可选，见下文）
```

> **路由注意事项**：Pages Functions 按文件路径路由——`functions/api/user.js` 只能收到
> `/api/user` 的请求。因此每个独立路由（如 OAuth 回调）必须有自己独立的文件，
> 写在其他文件里判断 `path` 是无效的（请求根本不会到达，会被静态资源兜底）。

## 部署

项目为纯静态 + Functions，**无 npm 构建步骤**，两种部署方式二选一：

### 方式 A：Cloudflare Dashboard Git 集成（推荐）

Pages 项目 → 设置 → 连接 Git 仓库，构建输出目录选 `public`。之后每次 push 自动部署，无需配置任何 secret。

> 若采用方式 A，请删除 `.github/workflows/deploy.yml`，避免重复部署。

### 方式 B：GitHub Actions 自动部署

1. 在仓库 Settings → Secrets 添加：
   - `CF_API_TOKEN`：Cloudflare API Token（需 Pages 编辑权限）
   - `CF_ACCOUNT_ID`：Cloudflare 账户 ID
2. push 到 main 即触发 `.github/workflows/deploy.yml`。

## 运行所需的环境变量 / Secrets

在 Cloudflare Pages 项目设置中配置（wrangler.toml 的 `[vars]` 仅存放非敏感项）：

| 名称 | 用途 | 敏感度 |
|------|------|--------|
| `SESSION_HMAC_SECRET` | 会话签名密钥（**必改**，勿用默认值） | secret |
| `INIT_SECRET` | 初始化接口重置密码口令（可选，配置后 `/api/init/` 才允许重置已初始化的站长密码） | secret |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth 客户端密钥 | secret |
| `CF_CLIENT_SECRET` | Codeforces OAuth 客户端密钥 | secret |
| `HCAPTCHA_SECRET_KEY` | hCaptcha 服务端密钥（不配置则跳过人机验证） | secret |
| `HCAPTCHA_SITE_KEY` | hCaptcha 站点密钥（兼容变量名 `HCAPTCHA`），前端经 `/api/config` 自动获取 | secret |
| `RESEND_API_KEY` | Resend 邮件服务密钥（不配置则邮件功能不可用） | secret |
| `GITHUB_CLIENT_ID` / `CF_CLIENT_ID` | OAuth 客户端 ID | 普通 |
| `SITE_ORIGIN` | 站点完整地址（OAuth 回调用） | 普通 |

D1 数据库绑定名 `DB` 已在 wrangler.toml 中配置；新环境可用 `init.sql` 初始化表结构。

## 第三方登录（OAuth）

| 平台 | 授权端点 | 回调地址（需在对应平台填写） |
|------|----------|------------------------------|
| GitHub | `https://github.com/login/oauth/authorize` | `https://<你的域名>/api/githubCallback` |
| Codeforces | `https://codeforces.com/oauth/authorize` | `https://<你的域名>/api/codeforcesCallback` |

- GitHub OAuth App：<https://github.com/settings/developers>，Authorization callback URL 填上表地址
- Codeforces OAuth 应用：登录 Codeforces 后打开 <https://codeforces.com/settings/api>，
  创建应用时 API key/secret 即为 `CF_CLIENT_ID` / `CF_CLIENT_SECRET`，Redirect URI 填上表地址
- 登录成功后自动以平台账号创建站内用户（`gh_*` / `cf_*` 前缀），无需额外绑定流程

## 管理员初始化（`/api/init/`）

部署后首先调用初始化接口创建站长账号（接口会自动幂等建表）：

```bash
curl -X POST https://<你的域名>/api/init/ \
  -H "Content-Type: application/json" \
  -d '{"adminname":"admin","adminpassword":"your_password"}'
```

- `adminname`：仅限字母/数字/`_`/`-`，长度 2-32
- `adminpassword`：长度至少 6 位
- `GET /api/init/` 可查询当前初始化状态
- 安全策略：数据库中**不存在 owner 时**允许自助初始化；已初始化后拒绝执行，
  需额外携带 `initSecret`（对应环境变量 `INIT_SECRET`，用 `wrangler secret put` 配置）
  才可重置站长密码

## 人机验证（hCaptcha）

服务端配置 `HCAPTCHA_SECRET_KEY`（密钥类型），前端站点密钥配置为 `HCAPTCHA_SITE_KEY`
（兼容变量名 `HCAPTCHA`；两者在 Cloudflare 控制台以"密钥"类型添加即可，Functions 运行时均可读取）。

页面加载时通过 `GET /api/config` 自动获取站点密钥：已配置则渲染验证码，未配置则不渲染、
服务端同步跳过验证——无需改动任何前端代码。

## 本地开发

```bash
npx wrangler pages dev public --d1 DB=<database_id> --binding SESSION_HMAC_SECRET=dev-secret
```
