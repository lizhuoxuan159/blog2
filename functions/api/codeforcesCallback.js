// ============================================================
// Codeforces OAuth 回调（OpenID Connect，独立路由文件）
//
// 重要说明：Cloudflare Pages Functions 按文件路径路由，
// functions/api/user.js 只能接收到 /api/user 的请求，
// 写在 user.js 内部的 `path === "/api/codeforcesCallback"` 判断是死代码，
// 永远不会被执行——请求会落空并被静态资源/重定向规则兜底（表现为跳转到首页）。
// 因此 OAuth 回调必须使用本独立文件。
//
// 路由：GET /api/codeforcesCallback?code=...
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

// 零依赖 JWT payload 解析（Codeforces id_token 为 HS256 JWT）
function parseJwtPayload(jwt) {
    try {
        const parts = String(jwt).split(".");
        if (parts.length !== 3) return null;
        let b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
        b64 += "=".repeat((4 - (b64.length % 4)) % 4);
        return JSON.parse(atob(b64));
    } catch (e) {
        console.error("JWT payload 解析失败：", e);
        return null;
    }
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
        if (!code) return fail("Codeforces登录回调缺少授权码，请重新登录", 400);

        const DB = env.DB;
        const SECRET = env.SESSION_HMAC_SECRET;
        const ORIGIN = env.SITE_ORIGIN;
        if (!DB || !SECRET || !ORIGIN) return fail("服务端配置不完整（DB / SESSION_HMAC_SECRET / SITE_ORIGIN）", 500);

        // 1) 用授权码换取 token（client_secret_post 方式，凭据放在 body）
        const tokenRes = await fetch("https://codeforces.com/oauth/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
            body: new URLSearchParams({
                grant_type: "authorization_code",
                code,
                client_id: env.CF_CLIENT_ID,
                client_secret: env.CF_CLIENT_SECRET,
                redirect_uri: `${ORIGIN}/api/codeforcesCallback`
            })
        });
        const tokenData = await tokenRes.json();
        if (!tokenData?.id_token) {
            return fail("Codeforces登录授权失败，请重试", 401);
        }

        // 2) 解析 id_token，payload 中含 handle / avatar / rating（官方 OIDC 声明）
        const payload = parseJwtPayload(tokenData.id_token);
        const cfHandle = payload?.handle;
        if (!cfHandle) {
            return fail("无法获取Codeforces账号信息，请重试", 401);
        }

        // 3) 查找或创建站内用户（数据库未迁移时给出明确提示）
        let dbUser = null;
        try {
            dbUser = await DB.prepare(`SELECT * FROM users WHERE codeforces_id = ?`).bind(cfHandle).first();
        } catch (dbErr) {
            if (String(dbErr?.message || "").includes("no such column")) {
                return fail("数据库尚未迁移，请先调用 /api/init/ 完成升级", 500);
            }
            throw dbErr;
        }
        if (!dbUser) {
            const randPwd = Math.random().toString(36).slice(2);
            const hash = await secureHashPassword(randPwd, SECRET);
            try {
                await DB.prepare(`INSERT INTO users (username,email,password,codeforces_id,role,totp_secret) VALUES (?,?,?,?,'guest',null)`)
                    .bind(`cf_${cfHandle}`, `${cfHandle}@codeforces.local`, hash, cfHandle).run();
            } catch (dbErr) {
                if (String(dbErr?.message || "").includes("no such column")) {
                    return fail("数据库尚未迁移，请先调用 /api/init/ 完成升级", 500);
                }
                throw dbErr;
            }
            dbUser = await DB.prepare(`SELECT * FROM users WHERE codeforces_id = ?`).bind(cfHandle).first();
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
        console.error("Codeforces回调异常：", err);
        return fail("Codeforces登录处理异常，请重试", 500);
    }
}
