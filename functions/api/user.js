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
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
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
    SELECT id, username, password, role, ban_until, github_id, email, totp_secret
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
            from: "notify@lizhuoxuan.com",
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

// ===================== hCaptcha 人机验证 =====================
// 注意：未配置 HCAPTCHA_SECRET_KEY 时跳过验证（降级），
// 配置后自动启用。生产环境务必配置该 secret。
async function verifyHCaptcha(token, secretKey) {
    if (!secretKey) {
        console.warn("未配置 HCAPTCHA_SECRET_KEY，跳过人机验证");
        return true;
    }
    if (!token) return false;
    const res = await fetch("https://api.hcaptcha.com/siteverify", {
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

// ===================== JWT 工具（解析 Codeforces id_token，零依赖） =====================
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

        // ===================== 独立OAuth回调 =====================
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
            if (!tokenData?.access_token) {
                return fail("GitHub登录授权失败，请重试", 401);
            }
            const userRes = await fetch("https://api.github.com/user", {
                headers: { Authorization: `token ${tokenData.access_token}` }
            });
            const ghUser = await userRes.json();
            const ghId = ghUser?.id ? String(ghUser.id) : null;
            if (!ghId) {
                return fail("无法获取GitHub账号信息，请重试", 401);
            }
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

        // ===================== 独立OAuth回调：Codeforces（OpenID Connect） =====================
        if (path === "/api/codeforcesCallback") {
            const { code } = new URLSearchParams(url.search);
            if (!code) return fail("Codeforces登录回调缺少授权码", 400);
            // 用授权码换取 token（client_secret_post 方式，凭据放在 body）
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
            // id_token 的 payload 中含 handle / avatar / rating（官方 OIDC 声明）
            const payload = parseJwtPayload(tokenData.id_token);
            const cfHandle = payload?.handle;
            if (!cfHandle) {
                return fail("无法获取Codeforces账号信息，请重试", 401);
            }
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
                    await DB.prepare(`INSERT INTO users (username,email,password,codeforces_id,role,totp_secret) VALUES (?,?,?,?,0,null)`)
                        .bind(`cf_${cfHandle}`, `${cfHandle}@codeforces.local`, hash, cfHandle).run();
                } catch (dbErr) {
                    if (String(dbErr?.message || "").includes("no such column")) {
                        return fail("数据库尚未迁移，请先调用 /api/init/ 完成升级", 500);
                    }
                    throw dbErr;
                }
                dbUser = await DB.prepare(`SELECT * FROM users WHERE codeforces_id = ?`).bind(cfHandle).first();
            }
            const sign = await hmacSha256(SECRET, String(dbUser.id));
            const sid = `${dbUser.id}.${sign}`;
            const redirect = Response.redirect(`${ORIGIN}/index.html`, 302);
            redirect.headers.set("Set-Cookie", `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
            return redirect;
        }

        // ===================== 主接口：/api/user =====================
        if (path !== "/api/user") return fail("接口不存在", 404);

        // OAuth跳转入口
        if (action === "githubLogin") {
            const authUrl = `https://github.com/login/oauth/authorize?client_id=${env.GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(`${ORIGIN}/api/githubCallback`)}`;
            return Response.redirect(authUrl, 302);
        }
        if (action === "codeforcesLogin") {
            const authUrl = `https://codeforces.com/oauth/authorize?client_id=${env.CF_CLIENT_ID}&redirect_uri=${encodeURIComponent(`${ORIGIN}/api/codeforcesCallback`)}&response_type=code&scope=openid`;
            return Response.redirect(authUrl, 302);
        }

        // 账号密码登录
        if (action === "login" && method === "POST") {
            const { username, password, totpCode, hCaptchaToken } = await request.json();
            const cfOk = await verifyHCaptcha(hCaptchaToken, env.HCAPTCHA_SECRET_KEY);
            if (!cfOk) return fail("人机验证失败，请完成验证后重试");
            const user = await DB.prepare(`SELECT * FROM users WHERE username = ?`).bind(username).first();
            if (!user) return fail("账号不存在");
            const hashPwd = await secureHashPassword(password, SECRET);
            if (hashPwd !== user.password) return fail("密码错误");
            if (user.totp_secret && !totpCode) return success({ need2fa: true, uid: user.id }, "请输入6位二次验证码");
            if (user.totp_secret) {
                const ok = await verifyTOTP(user.totp_secret, totpCode);
                if (!ok) return fail("验证码错误或过期");
            }
            const sign = await hmacSha256(SECRET, String(user.id));
            const sid = `${user.id}.${sign}`;
            const ip = request.headers.get("cf-connecting-ip") || "未知IP";
            try {
                await sendEmail(env.RESEND_API_KEY, user.email, "账号登录提醒", `<p>登录IP：${ip}</p>`);
            } catch (mailErr) {
                console.error("登录提醒邮件发送失败（不影响登录）：", mailErr);
            }
            const res = success({ uid: user.id, username: user.username, role: user.role }, "登录成功");
            res.headers.set("Set-Cookie", `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
            return res;
        }

        // 注册
        if (action === "register" && method === "POST") {
            const { username, email, password, emailCode, hCaptchaToken } = await request.json();
            const cfOk = await verifyHCaptcha(hCaptchaToken, env.HCAPTCHA_SECRET_KEY);
            if (!cfOk) return fail("人机验证失败，请刷新组件重试");
            if (!emailCode) return fail("请输入邮箱验证码");
            const codeRec = await DB.prepare(`
        SELECT id, uid FROM email_verifications WHERE code = ? AND action = 'register' AND expire_at > ?
      `).bind(String(emailCode).trim(), new Date().toISOString()).first();
            if (!codeRec) return fail("邮箱验证码错误或已过期，请重新获取");
            const exist = await DB.prepare(`SELECT id FROM users WHERE username = ? OR email = ?`).bind(username, email).first();
            if (exist) return fail("用户名/邮箱已注册");
            const hash = await secureHashPassword(password, SECRET);
            await DB.prepare(`INSERT INTO users (username,email,password,role,totp_secret) VALUES (?,?,?,0,null)`).bind(username, email, hash).run();
            await DB.prepare(`DELETE FROM email_verifications WHERE id = ?`).bind(codeRec.id).run();
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
            const { email, type, hCaptchaToken } = await request.json();
            const cfOk = await verifyHCaptcha(hCaptchaToken, env.HCAPTCHA_SECRET_KEY);
            if (!cfOk) return fail("人机验证失败");
            if (!email) return fail("请输入邮箱");
            // register：邮箱必须未注册；resetpwd：邮箱必须已注册
            const codeType = type === "register" ? "register" : "resetpwd";
            const user = await DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
            if (codeType === "register") {
                if (user) return fail("该邮箱已注册，请直接登录");
            } else if (!user) {
                return fail("邮箱未注册");
            }
            const code = await hmacSha256(SECRET, `${email}-${Date.now()}-${Math.random()}`);
            const expire = new Date(Date.now() + 3600 * 1000).toISOString();
            // 注册场景用户尚不存在，uid 用 0 占位（校验时只按 code + action 匹配）
            await DB.prepare(`INSERT INTO email_verifications (uid,code,action,expire_at) VALUES (?,?,?,?)`)
                .bind(codeType === "register" ? 0 : user.id, code, codeType, expire).run();
            if (codeType === "register") {
                const mailRes = await sendEmail(env.RESEND_API_KEY, email, "注册验证码",
                    `<p>您的注册验证码是：<b style="font-size:20px">${code}</b></p><p>1小时内有效。</p>`);
                if (!mailRes?.ok) return fail("邮件发送失败，请稍后重试", 502);
                return success(null, "验证码已发送，请查收邮件");
            }
            const resetUrl = `${ORIGIN}/reset.html?token=${code}`;
            const mailRes = await sendEmail(env.RESEND_API_KEY, email, "密码重置",
                `<p>请点击链接重置密码：<a href="${resetUrl}">${resetUrl}</a></p><p>链接1小时内有效。</p>`);
            if (!mailRes?.ok) return fail("邮件发送失败，请稍后重试", 502);
            return success(null, "邮件已发送");
        }

        // 重置密码
        if (action === "resetPwd" && method === "POST") {
            const { email, code, newPwd } = await request.json();
            const rec = await DB.prepare(`
        SELECT id, uid FROM email_verifications WHERE code = ? AND action = 'resetpwd' AND expire_at > ?
      `).bind(String(code || "").trim(), new Date().toISOString()).first();
            if (!rec) return fail("验证码失效");
            const hash = await secureHashPassword(newPwd, SECRET);
            await DB.prepare(`UPDATE users SET password = ? WHERE id = ?`).bind(hash, rec.uid).run();
            await DB.prepare(`DELETE FROM email_verifications WHERE id = ?`).bind(rec.id).run();
            return success(null, "重置完成");
        }

        // 检测登录状态
        if (action === "check") {
            const user = await getLoginUser(request, SECRET, DB);
            if (!user) return success({ login: false }, "未登录");
            // codeforces_id 单独查询：数据库未迁移时优雅降级为未绑定
            let codeforcesId = null;
            try {
                const cfRow = await DB.prepare(`SELECT codeforces_id FROM users WHERE id = ?`).bind(user.id).first();
                codeforcesId = cfRow?.codeforces_id || null;
            } catch (e) { /* 列不存在即未绑定 */ }
            return success({
                login: true,
                uid: user.id,
                username: user.username,
                role: user.role,
                github_id: user.github_id,
                codeforces_id: codeforcesId
            });
        }

        // 管理员：用户列表
        if (action === "adminList") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!["admin", "owner"].includes(u?.role)) return fail("无管理员权限", 403);
            const list = await DB.prepare(`
        SELECT id, username, email, role, ban_until, is_cancel,
               (totp_secret IS NOT NULL) AS totp_enabled
        FROM users
      `).all();
            return success(list.results);
        }

        // 管理员新建用户
        if (action === "adminAdd" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!["admin", "owner"].includes(u?.role)) return fail("无管理员权限", 403);
            const { username, email, password, role } = await request.json();
            // 仅允许创建低权限角色，防止越权建 owner/admin
            const safeRole = ["guest", "writer", "banned"].includes(role) ? role : "guest";
            const ex = await DB.prepare(`SELECT id FROM users WHERE username=? OR email=?`).bind(username, email).first();
            if (ex) return fail("账号已存在");
            const hash = await secureHashPassword(password, SECRET);
            await DB.prepare(`INSERT INTO users (username,email,password,role,totp_secret) VALUES (?,?,?,?,null)`).bind(username, email, hash, safeRole).run();
            return success(null, "创建成功");
        }

        // 修改角色
        if (action === "setRole" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!["admin", "owner"].includes(u?.role)) return fail("无管理员权限", 403);
            const { targetUid, newRole } = await request.json();
            if (!["owner", "admin", "writer", "guest", "banned"].includes(newRole)) return fail("无效的角色");
            if (targetUid === u.id) return fail("不能修改自己的角色");
            const target = await DB.prepare(`SELECT role FROM users WHERE id = ?`).bind(targetUid).first();
            if (!target) return fail("用户不存在");
            if (target.role === "owner") return fail("不能修改站主的角色");
            if (u.role !== "owner" && target.role === "admin") return fail("管理员不能修改其他管理员的角色");
            await DB.prepare(`UPDATE users SET role = ? WHERE id = ?`).bind(newRole, targetUid).run();
            return success(null, "修改完成");
        }

        // 封禁用户
        if (action === "banUser" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!["admin", "owner"].includes(u?.role)) return fail("无管理员权限");
            const { targetUid, banDays } = await request.json();
            const days = Number(banDays);
            if (!Number.isFinite(days) || days <= 0 || days > 3650) return fail("封禁天数不合法");
            if (targetUid === u.id) return fail("不能封禁自己");
            const target = await DB.prepare(`SELECT role FROM users WHERE id = ?`).bind(targetUid).first();
            if (!target) return fail("用户不存在");
            if (target.role === "owner") return fail("不能封禁站主");
            if (u.role !== "owner" && target.role === "admin") return fail("管理员不能封禁其他管理员");
            const end = new Date(Date.now() + days * 86400 * 1000).toISOString();
            await DB.prepare(`UPDATE users SET ban_until = ? WHERE id = ?`).bind(end, targetUid).run();
            return success(null, "封禁成功");
        }

        // 删除用户
        if (action === "delUser" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!["admin", "owner"].includes(u?.role)) return fail("无管理员权限");
            const { targetUid } = await request.json();
            if (targetUid === u.id) return fail("不能删除自己");
            const target = await DB.prepare(`SELECT role FROM users WHERE id = ?`).bind(targetUid).first();
            if (!target) return fail("用户不存在");
            if (target.role === "owner") return fail("不能删除站主");
            if (u.role !== "owner" && target.role === "admin") return fail("管理员不能删除其他管理员");
            await DB.prepare(`DELETE FROM users WHERE id = ?`).bind(targetUid).run();
            return success(null, "删除完成");
        }

        // 解绑GitHub
        if (action === "unbindGh" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!u) return fail("未登录", 401);
            await DB.prepare(`UPDATE users SET github_id = null WHERE id = ?`).bind(u.id).run();
            return success(null, "解绑GitHub账号成功");
        }

        // 解绑Codeforces
        if (action === "unbindCf" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!u) return fail("未登录", 401);
            await DB.prepare(`UPDATE users SET codeforces_id = null WHERE id = ?`).bind(u.id).run();
            return success(null, "解绑Codeforces账号成功");
        }

        // 2FA：生成密钥
        if (action === "totpGen" && method === "POST") {
            const u = await getLoginUser(request, SECRET, DB);
            if (!u) return fail("未登录", 401);
            if (u.totp_secret) return fail("已绑定二次验证");
            const secret = generateTOTPSecret();
            const issuer = new URL(ORIGIN).host;
            const label = encodeURIComponent(`${issuer}:${u.username || u.email || u.id}`);
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
            const u = await getLoginUser(request, SECRET, DB);
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
    } catch (err) {
        console.error("全局捕获异常：", err);
        return fail(`服务器异常：${err.message}`, 500);
    }
}