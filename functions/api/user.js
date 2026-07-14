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
  return `${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
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
      from: "<notify>@blog.lizhuoxuan.dpdns.org",
      to,
      subject,
      html
    })
  });
}

// ===================== TOTP 2FA 工具 =====================
const BASE32_CHAR = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
// 生成16位Base32密钥
function generateTOTPSecret() {
  let secret = "";
  const rand = new Uint32Array(16);
  crypto.getRandomValues(rand);
  for (let i = 0; i < 16; i++) {
    secret += BASE32_CHAR[rand[i] % 32];
  }
  return secret;
}
// base32转Uint8
function base32ToBytes(s) {
  s = s.toUpperCase().replace(/=+$/, "");
  let bits = "";
  for (const c of s) bits += BASE32_CHAR.indexOf(c).toString(2).padStart(5, "0");
  const buf = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) buf.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(buf);
}
// 获取当前TOTP时间步
function getTOTPStep() {
  return Math.floor(Date.now() / 30000);
}
// 校验TOTP验证码（允许前后1步误差）
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
    const bin = (arr[offset] << 24) | (arr[offset+1] << 16) | (arr[offset+2] << 8) | arr[offset+3];
    const num = bin & 0x7FFFFFFF;
    const nowCode = (num % 1000000).toString().padStart(6, "0");
    if (nowCode === code) return true;
  }
  return false;
}

export async function onRequest({ request, env }) {
  if (request.method === "OPTIONS") return handleOptions();
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const DB = env.DB;
  const SECRET = env.SESSION_HMAC_SECRET;
  const ORIGIN = env.SITE_ORIGIN;

  // 1. 用户密码登录（支持2FA二次验证）
  if (path === "/api/user/login" && method === "POST") {
    const { username, password, totpCode } = await request.json();
    const user = await DB.prepare(`SELECT * FROM users WHERE username = ?`).bind(username).first();
    if (!user) return fail("账号不存在");
    const hashPwd = await secureHashPassword(password, SECRET);
    if (hashPwd !== user.password) return fail("密码错误");

    // 账号开启2FA且未传入验证码，返回需二次验证标记
    if (user.totp_secret && !totpCode) {
      return success({ need2fa: true, uid: user.id }, "请输入二次验证6位验证码");
    }
    // 开启2FA，校验验证码
    if (user.totp_secret) {
      const ok = await verifyTOTP(user.totp_secret, totpCode);
      if (!ok) return fail("二次验证码错误或已过期");
    }

    // 生成会话sid
    const sign = await hmacSha256(SECRET, String(user.id));
    const sid = `${user.id}.${sign}`;
    // 登录通知邮件
    const ip = request.headers.get("cf-connecting-ip") || "未知IP";
    await sendEmail(env.RESEND_API_KEY, user.email, "账号异地登录提醒", `<p>你的账号在 ${ip} 完成登录</p>`);
    const res = success({ uid: user.id, username: user.username, role: user.role }, "登录成功");
    res.headers.set("Set-Cookie", `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
    return res;
  }

  // 2. 用户注册
  if (path === "/api/user/register" && method === "POST") {
    const { username, email, password } = await request.json();
    const existUser = await DB.prepare(`SELECT id FROM users WHERE username = ? OR email = ?`)
      .bind(username, email).first();
    if (existUser) return fail("用户名或邮箱已被注册");
    const hashPwd = await secureHashPassword(password, SECRET);
    await DB.prepare(`INSERT INTO users (username,email,password,role,totp_secret) VALUES (?,?,?,0,null)`)
      .bind(username, email, hashPwd).run();
    return success(null, "注册完成，请登录");
  }

  // 3. 退出登录
  if (path === "/api/user/logout") {
    const resp = success(null, "已退出登录");
    resp.headers.set("Set-Cookie", "sid=; Path=/; HttpOnly; Max-Age=0");
    return resp;
  }

  // 4. 修改密码
  if (path === "/api/user/change-pwd" && method === "POST") {
    const loginUser = await getLoginUser(request, SECRET, DB);
    if (!loginUser) return fail("请登录", 401);
    const { oldPwd, newPwd } = await request.json();
    const oldHash = await secureHashPassword(oldPwd, SECRET);
    if (oldHash !== loginUser.password) return fail("原密码不正确");
    const newHash = await secureHashPassword(newPwd, SECRET);
    await DB.prepare(`UPDATE users SET password = ? WHERE id = ?`).bind(newHash, loginUser.id).run();
    const resp = success(null, "密码修改成功，请重新登录");
    resp.headers.set("Set-Cookie", "sid=; Path=/; HttpOnly; Max-Age=0");
    return resp;
  }

  // 5. 忘记密码，发送重置链接
  if (path === "/api/user/forget-password" && method === "POST") {
    const { email } = await request.json();
    const user = await DB.prepare(`SELECT id,username FROM users WHERE email = ?`).bind(email).first();
    if (!user) return fail("该邮箱未注册");
    const resetToken = await hmacSha256(SECRET, `${user.id}-${Date.now()}`);
    const expire = new Date(Date.now() + 3600 * 1000).toISOString();
    await DB.prepare(`INSERT INTO email_verifications (uid,code,action,expire_at) VALUES (?,?,?,?)`)
      .bind(user.id, resetToken, "reset_pwd", expire).run();
    const resetUrl = `${ORIGIN}/reset.html?token=${resetToken}`;
    await sendEmail(env.RESEND_API_KEY, email, "密码重置链接", `<a href="${resetUrl}">点击重置密码（1小时有效）</a>`);
    return success(null, "重置邮件已发送，请查收");
  }

  // 6. 管理员：获取全部用户
  if (path === "/api/user/admin-list") {
    const loginUser = await getLoginUser(request, SECRET, DB);
    if (!loginUser || loginUser.role !== 1) return fail("无管理员权限", 403);
    const list = await DB.prepare(`SELECT id,username,email,role,ban_until,totp_secret FROM users`).all();
    return success(list.results);
  }

  // 7. 管理员：新增用户
  if (path === "/api/user/admin-add" && method === "POST") {
    const loginUser = await getLoginUser(request, SECRET, DB);
    if (!loginUser || loginUser.role !== 1) return fail("无管理员权限", 403);
    const { username, email, password } = await request.json();
    const exist = await DB.prepare(`SELECT id FROM users WHERE username=? OR email=?`).bind(username, email).first();
    if (exist) return fail("账号已存在");
    const hash = await secureHashPassword(password, SECRET);
    await DB.prepare(`INSERT INTO users (username,email,password,role,totp_secret) VALUES (?,?,?,0,null)`).bind(username, email, hash).run();
    return success(null, "新建用户成功");
  }

  // ===================== 2FA 新增接口 =====================
  // 8. 获取2FA绑定密钥（未绑定状态调用）
  if (path === "/api/user/totp-generate" && method === "POST") {
    const user = await getLoginUser(request, SECRET, DB);
    if (!user) return fail("请登录", 401);
    if (user.totp_secret) return fail("您已绑定二次验证，如需修改请先解绑");
    const secret = generateTOTPSecret();
    // otpauth二维码链接
    const issuer = "blog.lizhuoxuan.dpdns.org";
    const label = encodeURIComponent(`${issuer}:${user.email}`);
    const qrUrl = `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;
    return success({ secret, qrUrl }, "密钥生成完成，使用Authenticator扫描二维码");
  }

  // 9. 确认绑定2FA（输入验证码验证生效）
  if (path === "/api/user/totp-bind" && method === "POST") {
    const user = await getLoginUser(request, SECRET, DB);
    if (!user) return fail("请登录", 401);
    if (user.totp_secret) return fail("已绑定2FA，禁止重复绑定");
    const { secret, code } = await request.json();
    const valid = await verifyTOTP(secret, code);
    if (!valid) return fail("验证码校验失败，请确认密钥无误");
    await DB.prepare(`UPDATE users SET totp_secret = ? WHERE id = ?`).bind(secret, user.id).run();
    return success(null, "二次验证绑定成功，下次登录需要输入验证码");
  }

  // 10. 解绑2FA（需要验证当前密码）
  if (path === "/api/user/totp-unbind" && method === "POST") {
    const user = await getLoginUser(request, SECRET, DB);
    if (!user) return fail("请登录", 401);
    if (!user.totp_secret) return fail("您未绑定二次验证");
    const { password } = await request.json();
    const inputHash = await secureHashPassword(password, SECRET);
    if (inputHash !== user.password) return fail("账户密码错误，无法解绑");
    await DB.prepare(`UPDATE users SET totp_secret = null WHERE id = ?`).bind(user.id).run();
    return success(null, "2FA二次验证已解绑");
  }

  // 11. 获取当前账号2FA状态
  if (path === "/api/user/totp-status") {
    const user = await getLoginUser(request, SECRET, DB);
    if (!user) return fail("请登录", 401);
    return success({ enabled: !!user.totp_secret }, user.totp_secret ? "已开启二次验证" : "未开启二次验证");
  }

  // 12. Microsoft 回调
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
    const userRes = await fetch("https://graph.microsoft.com/me", {
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
        .bind(`ms_${msId.slice(0,8)}`, email, hash, msId).run();
      dbUser = await DB.prepare(`SELECT * FROM users WHERE microsoft_id = ?`).bind(msId).first();
    }
    const sign = await hmacSha256(SECRET, String(dbUser.id));
    const sid = `${dbUser.id}.${sign}`;
    const redirect = Response.redirect(`${ORIGIN}/index.html`, 302);
    redirect.headers.set("Set-Cookie", `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
    return redirect;
  }

  // 13. GitHub 回调
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
      dbUser = await DB.prepare(`SELECT * FROM users WHERE github_id = ?`).first();
    }
    const sign = await hmacSha256(SECRET, String(dbUser.id));
    const sid = `${dbUser.id}.${sign}`;
    const redirect = Response.redirect(`${ORIGIN}/index.html`, 302);
    redirect.headers.set("Set-Cookie", `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
    return redirect;
  }

  return fail("接口不存在",404);
}
