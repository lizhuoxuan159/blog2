// ============================================================
// GitHub OAuth 回调（独立路由文件）
//
// 重要说明：Cloudflare Pages Functions 按文件路径路由，
// functions/api/user.js 只能接收到 /api/user 的请求，
// 写在 user.js 内部的 `path === "/api/githubCallback"` 判断是死代码，
// 永远不会被执行——请求会落空并被静态资源/重定向规则兜底（表现为跳转到首页）。
// 因此 OAuth 回调必须使用本独立文件。
//
// 路由：GET /api/githubCallback?code=...
// ============================================================

// ========== 原生WebCrypto工具，零Node依赖 ==========
async function hmacSha256(secret, content) {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(content));
    return Array.from(new Uint8Array(sig))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

async function secureHashPassword(rawStr, hmacSecret) {
    return await hmacSha256(hmacSecret, String(rawStr).trim());
}

function jsonResp(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json; charset=utf-8" }
    });
}
function success(data = null, msg = "操作成功") {
    return jsonResp({ code: 0, msg, data });
}
function fail(msg = "操作失败", code = 400) {
    return jsonResp({ code, msg, data: null }, code);
}

export async function onRequest({ request, env }) {
    try {
        const url = new URL(request.url);
        const code = new URLSearchParams(url.search).get("code");
        if (!code) return fail("GitHub登录回调缺少授权码，请重新登录", 400);

        const DB = env.DB;
        const SECRET = env.SESSION_HMAC_SECRET;
        const ORIGIN = env.SITE_ORIGIN;
        if (!DB || !SECRET || !ORIGIN) return fail("服务端配置不完整（DB / SESSION_HMAC_SECRET / SITE_ORIGIN）", 500);

        // 1) 用授权码换取 access_token
        const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
            body: new URLSearchParams({
                client_id: env.GITHUB_CLIENT_ID,
                client_secret: env.GITHUB_CLIENT_SECRET,
                code
            })
        });
        const tokenData = await tokenRes.json();
        if (!tokenData?.access_token) {
            return fail("GitHub登录授权失败，请重试", 401);
        }

        // 2) 获取 GitHub 用户信息
        const userRes = await fetch("https://api.github.com/user", {
            headers: { Authorization: `token ${tokenData.access_token}` }
        });
        const ghUser = await userRes.json();
        const ghId = ghUser?.id ? String(ghUser.id) : null;
        if (!ghId) {
            return fail("无法获取GitHub账号信息，请重试", 401);
        }
        const email = ghUser.email || `${ghUser.login}@github.local`;

        // 3) 查找或创建站内用户
        let dbUser = await DB.prepare(`SELECT * FROM users WHERE github_id = ?`).bind(ghId).first();
        if (!dbUser) {
            const randPwd = Math.random().toString(36).slice(2);
            const hash = await secureHashPassword(randPwd, SECRET);
            await DB.prepare(`INSERT INTO users (username,email,password,github_id,role,totp_secret) VALUES (?,?,?,?,'guest',null)`)
                .bind(`gh_${ghUser.login}`, email, hash, ghId).run();
            dbUser = await DB.prepare(`SELECT * FROM users WHERE github_id = ?`).bind(ghId).first();
        }

        // 4) 签发会话 Cookie 并跳转首页
        // 注意：Response.redirect() 的 headers 是不可变的（immutable guard），
        // 不能再用 .headers.set() 设置 Cookie，必须用 new Response 手动构造。
        const sign = await hmacSha256(SECRET, String(dbUser.id));
        const sid = `${dbUser.id}.${sign}`;
        return new Response(null, {
            status: 302,
            headers: {
                Location: `${ORIGIN}/index.html`,
                "Set-Cookie": `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`
            }
        });
    } catch (err) {
        console.error("GitHub回调异常：", err);
        return fail("GitHub登录处理异常，请重试", 500);
    }
}
