// ========== 原生WebCrypto工具，零Node依赖 ==========
async function hmacSha256(secret, content) {
    const encoder = new TextEncoder();
    const secretBytes = encoder.encode(secret);
    const contentBytes = encoder.encode(content);

    const key = await crypto.subtle.importKey(
        "raw",
        secretBytes,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
    );

    const signatureBuffer = await crypto.subtle.sign("HMAC", key, contentBytes);
    const uint8Arr = new Uint8Array(signatureBuffer);
    return Array.from(uint8Arr)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

async function secureHashPassword(rawStr, hmacSecret) {
    return await hmacSha256(hmacSecret, rawStr.trim());
}

async function verifySessionToken(token, secret) {
    const splitArr = token.split(".");
    if (splitArr.length !== 2) return null;
    const [uidStr, clientSign] = splitArr;
    const serverSign = await hmacSha256(secret, uidStr);
    return serverSign === clientSign ? Number(uidStr) : null;
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

function toUTC8Time(utcTime) {
    if (!utcTime) return null;
    const date = new Date(utcTime);
    date.setHours(date.getHours() + 8);
    const pad = n => n.toString().padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth())}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function getSessionCookie(request) {
    const cookieRaw = request.headers.get("cookie") || "";
    const cookieObj = Object.fromEntries(
        cookieRaw.split("; ").map(item => item.split("="))
    );
    return cookieObj.sid || null;
}

async function getLoginUser(request, secret, db) {
    const sid = getSessionCookie(request);
    if (!sid) return null;
    const loginUid = await verifySessionToken(sid, secret);
    if (!loginUid) return null;
    const user = await db.prepare(`
    SELECT id, username, password, role, ban_until, microsoft_id, github_id, email, totp_secret
    FROM users WHERE id = ?
  `).bind(loginUid).first();
    return user;
}

function handleOptions() {
    return new Response(null, {
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type,Cookie",
            "Access-Control-Max-Age": "86400"
        }
    });
}

async function sendEmail(resendKey, to, subject, html) {
    return await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${resendKey}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            from: "<notify>@lizhuoxuan.zh.kg",
            to,
            subject,
            html
        })
    });
}

// ===================== TOTP 2FA 工具 =====================
const BASE32_CHAR = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function generateTOTPSecret() {
    let secret = "";
    const rand = new Uint32Array(16);
    crypto.getRandomValues(rand);
    for (let i = 0; i < 16; i++) {
        secret += BASE32_CHAR[rand[i] % 32];
    }
    return secret;
}
function base32ToBytes(s) {
    s = s.toUpperCase().replace(/=+$/, "");
    let bits = "";
    for (const c of s) bits += BASE32_CHAR.indexOf(c).toString(2).padStart(5, "0");
    const buf = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) buf.push(parseInt(bits.slice(i, i + 8), 2));
    return new Uint8Array(buf);
}
function getTOTPStep() {
    return Math.floor(Date.now() / 30000);
}
async function verifyTOTP(secret32, code) {
    if (!secret32 || secret32.length < 16) return false;
    const keyBuf = base32ToBytes(secret32);
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", keyBuf, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    const steps = [getTOTPStep() - 1, getTOTPStep(), getTOTPStep() + 1];
    for (const step of steps) {
        const stepBuf = new Uint8Array(8);
        let v = BigInt(step);
        for (let i = 7; i >= 0; i--) {
            stepBuf[i] = Number(v & 0xFFn);
            v >>= 8n;
        }
        const mac = await crypto.subtle.sign("HMAC", key, stepBuf);
        const arr = new Uint8Array(mac);
        const offset = arr[arr.length - 1] & 0x0F;
        const bin = (arr[offset] << 24) | (arr[offset + 1] << 16) | (arr[offset + 2] << 8) | arr[offset + 3];
        const num = bin & 0x7FFFFFFF;
        const nowCode = (num % 1000000).toString().padStart(6, "0");
        if (nowCode === code) return true;
    }
    return false;
}

// ===================== Cloudflare Turnstile CF人机验证 =====================
/**
 * 校验Turnstile token
 * @param {string} token 前端获取的cf-turnstile-response
 * @param {string} secretKey wrangler环境变量 TURNSTILE_SECRET
 * @returns {Promise<boolean>}
 */
async function verifyTurnstile(token, secretKey) {
    if (!token || !secretKey) return false;
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            secret: secretKey,
            response: token
        })
    });
    const data = await res.json();
    return data.success === true;
}


export async function onRequest({ request, env }) {
    try {
        if (request.method === "OPTIONS") return handleOptions();
        const url = new URL(request.url);
        const path = url.pathname;
        const action = url.searchParams.get("action");
        const method = request.method;
        const DB = env.DB;
        const SECRET = env.SESSION_HMAC_SECRET;
        const ORIGIN = env.SITE_ORIGIN;

        // ===================== 独立OAuth回调（固定路径，禁止带?action） =====================
        // 微软登录回调（Azure校验redirect_uri必须完全匹配静态路径）
        if (path === "/api/microsoftCallback") {
            const { code } = new URLSearchParams(url.search);
            const tokenRes = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({
                    client_id: env.MS_CLIENT_ID,
                    client_secret: env.MS_CLIENT_SECRET,
                    grant_type: "authorization_code",
                    code,
                    redirect_uri: `${ORIGIN}/api/microsoftCallback`
                })
            });
            const tokenData = await tokenRes.json();
            // 修复Graph接口版本错误，强制v1.0
            const userRes = await fetch("https://graph.microsoft.com/v1.0/me", {
                headers: { Authorization: `Bearer ${tokenData.access_token}` }
            });
            const msUser = await userRes.json();
            const msId = msUser.id;
            const email = msUser.mail || msUser.userPrincipalName;
            let dbUser = await DB.prepare(`SELECT * FROM users WHERE microsoft_id = ?`).bind(msId).first();
            if (!dbUser) {
                const randPwd = Math.random().toString(36).slice(2);
                const hash = await secureHashPassword(randPwd, SECRET);
                await DB.prepare(`INSERT INTO users (username,email,password,microsoft_id,role,totp_secret) VALUES (?,?,?,?,0,null)`)
                    .bind(`ms_${msId.slice(0, 8)}`, email, hash, msId).run();
                dbUser = await DB.prepare(`SELECT * FROM users WHERE microsoft_id = ?`).bind(msId).first();
            }
            const sign = await hmacSha256(SECRET, String(dbUser.id));
            const sid = `${dbUser.id}.${sign}`;
            const redirect = Response.redirect(`${ORIGIN}/index.html`, 302);
            redirect.headers.set("Set-Cookie", `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
            return redirect;
        }

        // GitHub登录回调（静态路径，OAuth白名单固定）
        if (path === "/api/githubCallback") {
            const { code } = new URLSearchParams(url.search);
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
            const userRes = await fetch("https://api.github.com/user", {
                headers: { Authorization: `token ${tokenData.access_token}` }
            });
            const ghUser = await userRes.json();
            const ghId = String(ghUser.id);
            const email = ghUser.email || `${ghUser.login}@github.local`;
            let dbUser = await DB.prepare(`SELECT * FROM users WHERE github_id = ?`).bind(ghId).first();
            if (!dbUser) {
                const randPwd = Math.random().toString(36).slice(2);
                const hash = await secureHashPassword(randPwd, SECRET);
                await DB.prepare(`INSERT INTO users (username,email,password,github_id,role,totp_secret) VALUES (?,?,?,?,0,null)`)
                    .bind(`gh_${ghUser.login}`, email, hash, ghId).run();
                dbUser = await DB.prepare(`SELECT * FROM users WHERE github_id = ?`).bind(ghId).first();
            }
            const sign = await hmacSha256(SECRET, String(dbUser.id));
            const sid = `${dbUser.id}.${sign}`;
            const redirect = Response.redirect(`${ORIGIN}/index.html`, 302);
            redirect.headers.set("Set-Cookie", `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
            return redirect;
        }

        // ===================== 主接口：/api/user 全部走 action 参数 =====================
        if (path !== "/api/user") return fail("接口不存在", 404);

        // OAuth跳转入口（GET，拼接静态回调路径）
        if (action === "githubLogin") {
            const authUrl = `https://github.com/login/oauth/authorize?client_id=${env.GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(`${ORIGIN}/api/githubCallback`)}`;
            return Response.redirect(authUrl, 302);
        }
        if (action === "microsoftLogin") {
            const redirectUri = encodeURIComponent(`${ORIGIN}/api/microsoftCallback`);
            const msUrl = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=${env.MS_CLIENT_ID}&response_type=code&scope=openid email profile&redirect_uri=${redirectUri}`;
            return Response.redirect(msUrl, 302);
        }

        // 账号密码登录
        if (action === "login" && method === "POST") {
            const { username, password, totpCode, cfToken } = await request.json();
            // CF人机验证
            const cfOk = await verifyTurnstile(cfToken, env.TURNSTILE_SECRET);
            if (!cfOk) return fail("人机验证失败，请完成验证后重试");
            const user = await DB.prepare(`SELECT * FROM users WHERE username = ?`).bind(username).first();
            if (!user) return fail("账号不存在");
            const hashPwd = await secureHashPassword(password, SECRET);
            if (hashPwd !== user.password) return fail("密码错误");
            if (user.totp_secret && !totpCode) return success({ need2fa: true, uid: user.id }, "请输入6位二次验证码");
            if (user.totp_secret) {
                const ok = await verifyTOTP(user.totpCode, totpCode);
                if (!ok) return fail("验证码错误或过期");
            }
            const sign = await hmacSha256(SECRET, String(user.id));
            const sid = `${user.id}.${sign}`;
            const ip = request.headers.get("cf-connecting-ip") || "未知IP";
            await sendEmail(env.RESEND_API_KEY, user.email, "账号登录提醒", `<p>登录IP：${ip}</p>`);
            const res = success({ uid: user.id, username: user.username, role: user.role }, "登录成功");
            res.headers.set("Set-Cookie", `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
            return res;
        }

        // 注册
        if (action === "register" && method === "POST") {
            const { username, email, password, cfToken } = await request.json();
            // CF人机验证
            const cfOk = await verifyTurnstile(cfToken, env.TURNSTILE_SECRET);
            if (!cfOk) return fail("人机验证失败，请刷新组件重试");
            const exist = await DB.prepare(`SELECT id FROM users WHERE username = ? OR email = ?`).bind(username, email).first();
            if (exist) return fail("用户名/邮箱已注册");
            const hash = await secureHashPassword(password, SECRET);
            await DB.prepare(`INSERT INTO users (username,email,password,role,totp_secret) VALUES (?,?,?,0,null)`).bind(username, email, hash).run();
            return success(null, "注册完成");
        }


        // 退出登录
        if (action === "logout") {
            const resp = success(null, "已退出");
            resp.headers.set("Set-Cookie", "sid=; Path=/; HttpOnly; Max-Age=0");
            return resp;
        }

        // 修改密码
        if (action === "changePwd" && method === "POST") {
            const user = await getLoginUser(request, SECRET, DB);
            if (!user) return fail("请登录", 401);
            const { oldPwd, newPwd } = await request.json();
            const oldHash = await secureHashPassword(oldPwd, SECRET);
            if (oldHash !== user.password) return fail("原密码错误");
            const newHash = await secureHashPassword(newPwd, SECRET);
            await DB.prepare(`UPDATE users SET password = ? WHERE id = ?`).bind(newHash, user.id).run();
            const resp = success(null, "密码修改成功，请重新登录");
            resp.headers.set("Set-Cookie", "sid=; Path=/; Max-Age=0");
            return resp;
        }

        if (action === "sendCode" && method === "POST") {
            const { email, type, cfToken } = await request.json();
            // CF人机验证
            const cfOk = await verifyTurnstile(cfToken, env.TURNSTILE_SECRET);
            if (!cfOk) return fail("人机验证失败");
            const user = await DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
            if (!user) return fail("邮箱未注册");
            const token = await hmacSha256(SECRET, `${user.id}-${Date.now()}`);
            const expire = new Date(Date.now() + 3600 * 1000).toISOString();
            await DB.prepare(`INSERT INTO email_verifications (uid,code,action,expire_at) VALUES (?,?,?,?)`).bind(user.id, token, type, expire).run();
            const resetUrl = `${ORIGIN}/reset.html?token=${token}`;
            await sendEmail(env.RESEND_API_KEY, email, "密码重置", `<a href="${resetUrl}">重置链接</a>`);
            return success(null, "邮件已发送");
        }


        // 重置密码
        if (action === "resetPwd" && method === "POST") {
            const { email, code, newPwd } = await request.json();
            const rec = await DB.prepare(`SELECT uid FROM email_verifications WHERE email=? AND code=? AND expire_at > ?`).bind(email, code, new Date().toISOString()).first();
            if (!rec) return fail("验证码失效");
            const hash = await secureHashPassword(newPwd, SECRET);
            await DB.prepare(`UPDATE users SET password = ? WHERE id = ?`).bind(hash, rec.uid).run();
            return success(null, "重置完成");
        }

        // 检测登录状态
        if (action === "check") {
            const user = await getLoginUser(request, SECRET, DB);
            if (!user) return success({ login: false }, "未登录");
            return success({
                login: true,
                uid: user.id,
                username: user.username,
                role: user.role,
                microsoft_id: user.microsoft_id,
                github_id: user.github_id
            });
        }

        // 管理员：用户列表
        if (action === "adminList") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!["admin", "owner"].includes(u?.role)) return fail("无管理员权限", 403);
            const list = await DB.prepare(`SELECT id,username,email,role,ban_until,totp_secret FROM users`).all();
            return success(list.results);
        }

        // 管理员新建用户
        if (action === "adminAdd" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!["admin", "owner"].includes(u?.role)) return fail("无管理员权限", 403);
            const { username, email, password, role } = await request.json();
            const ex = await DB.prepare(`SELECT id FROM users WHERE username=? OR email=?`).bind(username, email).first();
            if (ex) return fail("账号已存在");
            const hash = await secureHashPassword(password, SECRET);
            await DB.prepare(`INSERT INTO users (username,email,password,role,totp_secret) VALUES (?,?,?,?,null)`).bind(username, email, hash, role).run();
            return success(null, "创建成功");
        }

        // 修改角色
        if (action === "setRole" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!["admin", "owner"].includes(u?.role)) return fail("无管理员权限", 403);
            const { targetUid, newRole } = await request.json();
            await DB.prepare(`UPDATE users SET role = ? WHERE id = ?`).bind(newRole, targetUid).run();
            return success(null, "修改完成");
        }

        // 封禁用户
        if (action === "banUser" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!["admin", "owner"].includes(u?.role)) return fail("无管理员权限");
            const { targetUid, banDays } = await request.json();
            const end = new Date(Date.now() + banDays * 86400 * 1000).toISOString();
            await DB.prepare(`UPDATE users SET ban_until = ? WHERE id = ?`).bind(end, targetUid).run();
            return success(null, "封禁成功");
        }

        // 删除用户
        if (action === "delUser" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!["admin", "owner"].includes(u?.role)) return fail("无管理员权限");
            const { targetUid } = await request.json();
            await DB.prepare(`DELETE FROM users WHERE id = ?`).bind(targetUid).run();
            return success(null, "删除完成");
        }

        // 解绑微软
        if (action === "unbindMs" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!u) return fail("未登录", 401);
            await DB.prepare(`UPDATE users SET microsoft_id = null WHERE id = ?`).bind(u.id).run();
            return success(null, "解绑微软账号成功");
        }

        // 解绑GitHub
        if (action === "unbindGh" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!u) return fail("未登录", 401);
            await DB.prepare(`UPDATE users SET github_id = null WHERE id = ?`).bind(u.id).run();
            return success(null, "解绑GitHub账号成功");
        }

        // 2FA：生成密钥
        if (action === "totpGen" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!u) return fail("未登录", 401);
            if (u.totp_secret) return fail("已绑定二次验证");
            const secret = generateTOTPSecret();
            const issuer = "blog.lizhuoxuan.dpdns.org";
            const label = encodeURIComponent(`${issuer}:${u.email}`);
            const qrUrl = `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;
            return success({ secret, qrUrl });
        }

        // 2FA绑定
        if (action === "totpBind" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!u) return fail("未登录", 401);
            if (u.totp_secret) return fail("已绑定");
            const { secret, code } = await request.json();
            const valid = await verifyTOTP(secret, code);
            if (!valid) return fail("验证码错误");
            await DB.prepare(`UPDATE users SET totp_secret = ? WHERE id = ?`).bind(secret, u.id).run();
            return success(null, "2FA绑定成功");
        }

        // 2FA解绑
        if (action === "totpUnbind" && method === "POST") {
            const u = await getLoginUser(request, SECRET);
            if (!u) return fail("未登录", 401);
            if (!u.totp_secret) return fail("未开启");
            const { password } = await request.json();
            const hash = await secureHashPassword(password, SECRET);
            if (hash !== u.password) return fail("密码错误");
            await DB.prepare(`UPDATE users SET totp_secret = null WHERE id = ?`).bind(u.id).run();
            return success(null, "2FA已解绑");
        }

        // 获取2FA状态
        if (action === "totpStatus") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!u) return fail("未登录", 401);
            return success({ enabled: !!u.totp_secret });
        }

        return fail("无效action参数", 404);
    } catch (err)
    console.error("全局捕获异常：", err);
    return fail(`服务器异常：${err.message}`, 500);
}
}
