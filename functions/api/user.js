async function sha256(rawStr) {
  const encoder = new TextEncoder();
  const data = encoder.encode(rawStr);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function base64UrlEncode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}
function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

async function getHmacKey(secretStr) {
  const enc = new TextEncoder();
  const keyBuf = enc.encode(secretStr);
  return crypto.subtle.importKey(
    'raw',
    keyBuf,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

async function createSignedSessionToken(uid, username, role, secret) {
  const payload = {
    uid,
    username,
    role,
    exp: Date.now() + 604800000
  };
  const payloadJson = JSON.stringify(payload);
  const payloadB64 = base64UrlEncode(new TextEncoder().encode(payloadJson));
  const key = await getHmacKey(secret);
  const signatureBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  const sigB64 = base64UrlEncode(signatureBuf);
  return `${payloadB64}.${sigB64}`;
}

async function verifySessionToken(tokenStr, secret) {
  const parts = tokenStr.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sigB64] = parts;
  const key = await getHmacKey(secret);
  const sigRaw = base64UrlDecode(sigB64);
  const ok = await crypto.subtle.verify('HMAC', key, sigRaw, new TextEncoder().encode(payloadB64));
  if (!ok) return null;
  try {
    const payloadRaw = new TextDecoder().decode(base64UrlDecode(payloadB64));
    const payload = JSON.parse(payloadRaw);
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function buildSecureSessionCookie(token, maxAge) {
  return `__Secure-blog_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}
function buildClearSessionCookie() {
  return `__Secure-blog_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,X-Csrf-Token'
    }
  });
}

async function getLoginUser(request, hmacSecret) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/__Secure-blog_session=([^;]+)/);
  if (!match) return null;
  return await verifySessionToken(match[1], hmacSecret);
}

async function hashPassword(rawPwd, salt = null) {
  const enc = new TextEncoder();
  let saltBuf;
  if (!salt) saltBuf = crypto.getRandomValues(new Uint8Array(16));
  else saltBuf = base64UrlDecode(salt);
  const key = await crypto.subtle.importKey('raw', enc.encode(rawPwd), { name: 'PBKDF2' }, false, ['deriveKey']);
  const derived = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBuf, iterations: 100000, hash: 'SHA-256' },
    key,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const hashBuf = await crypto.subtle.exportKey('raw', derived);
  const hashStr = base64UrlEncode(hashBuf);
  const saltStr = base64UrlEncode(saltBuf);
  return `${saltStr}$$${hashStr}`;
}

async function verifyPassword(rawPwd, storedHash) {
  if (storedHash.includes('$$')) {
    const [salt, hash] = storedHash.split('$$');
    const newHash = await hashPassword(rawPwd, salt);
    return newHash.split('$$')[1] === hash;
  } else {
    return await sha256(rawPwd) === storedHash;
  }
}

// 密码强度校验
function checkPasswordStrength(pwd) {
  if (pwd.length < 8) return false;
  const regUpper = /[A-Z]/;
  const regLower = /[a-z]/;
  const regNum = /[0-9]/;
  return regUpper.test(pwd) && regLower.test(pwd) && regNum.test(pwd);
}

// 6位验证码
function generateSixCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}
// 随机nonce
function generateNonce() {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
}

const EMAIL_REG = /^[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-\.]+$/;

// 邮件通用发送（发件人改为环境变量，移除硬编码）
async function sendMailByResend(targetEmail, subject, html, apiKey, fromName, fromEmail) {
  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      "User-Agent": "Blog-System-Worker"
    },
    body: JSON.stringify({
      from: `${fromName} <${fromEmail}>`,
      to: targetEmail,
      subject,
      html
    })
  });
  return await resp.json();
}

async function sendNewLoginAlert(userEmail, username, ip, apiKey, mailFromName, mailFromAddr) {
  const now = new Date().toLocaleString("zh-CN");
  const html = `<div style="padding:15px;font-family:system-ui;"><h3>账号安全提醒：新设备登录</h3><p>账号：<strong>${username}</strong></p><p>登录IP：${ip}</p><p>时间：${now}</p><p>非本人操作请立刻重置密码。</p></div>`;
  return sendMailByResend(userEmail, "【安全提醒】新设备登录通知", html, apiKey, mailFromName, mailFromAddr);
}

async function sendResetPasswordMail(userEmail, username, resetUrl, apiKey, mailFromName, mailFromAddr) {
  const html = `<div style="padding:15px;font-family:system-ui;"><h3>密码重置申请</h3><p>账号 <strong>${username}</strong> 发起密码重置</p><p>链接15分钟有效，且仅可使用一次：<br><a href="${resetUrl}" style="color:#1677ff">${resetUrl}</a></p><p>未操作直接忽略，密码不会变更。</p></div>`;
  return sendMailByResend(userEmail, "【密码重置】账号重置链接", html, apiKey, mailFromName, mailFromAddr);
}

// OAuth 工具
async function generateOauthState(secret, flowType) {
  const nonceBuf = crypto.getRandomValues(new Uint8Array(16));
  const nonce = base64UrlEncode(nonceBuf);
  const payload = { nonce, ts: Date.now(), type: flowType, exp: Date.now() + 600000 };
  const payB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await getHmacKey(secret);
  const sig = base64UrlEncode(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payB64)));
  return `${payB64}.${sig}`;
}
async function verifyOauthState(stateStr, secret) {
  const parts = stateStr.split('.');
  if (parts.length !== 2) return false;
  const [payB64, sigB64] = parts;
  const key = await getHmacKey(secret);
  const ok = await crypto.subtle.verify('HMAC', key, base64UrlDecode(sigB64), new TextEncoder().encode(payB64));
  if (!ok) return false;
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payB64)));
    if (Date.now() > payload.exp) return false;
    return payload;
  } catch {
    return false;
  }
}

async function getGithubToken(code, clientId, clientSecret, redirectUri) {
  const res = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { "User-Agent": "Blog-System-Worker", "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, code, redirect_uri: redirectUri })
  });
  const rawText = await res.text();
  try { return JSON.parse(rawText); } catch { return { error: true, msg: "GitHub接口返回非JSON", detail: rawText.slice(0, 300) }; }
}
async function getGithubUserInfo(accessToken) {
  const res = await fetch("https://api.github.com/user", { headers: { "User-Agent": "Blog-System-Worker", Authorization: `Bearer ${accessToken}` } });
  if (!res.ok) return { error: true, msg: `HTTP ${res.status}`, detail: await res.text() };
  return await res.json();
}
async function getMicrosoftToken(code, clientId, clientSecret, redirectUri) {
  const body = new URLSearchParams({ client_id: clientId, client_secret: clientSecret, grant_type: "authorization_code", code, redirect_uri: redirectUri });
  const res = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
  const rawText = await res.text();
  try { return JSON.parse(rawText); } catch { return { error: true, msg: "微软接口返回非JSON", detail: rawText.slice(0, 300) }; }
}
async function getMicrosoftUserInfo(accessToken) {
  const res = await fetch("https://graph.microsoft.com/v1.0/me?$select=id,displayName,mail", { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!res.ok) return { error: true, msg: `HTTP ${res.status}`, detail: await res.text() };
  return await res.json();
}

// 限流工具（全接口统一D1限流，废弃内存Map）
async function checkRateLimit(db, ip, action, limitCount, windowMs) {
  const now = Date.now();
  const windowExp = now + windowMs;
  const cleanThreshold = now - windowMs;
  await db.prepare(`DELETE FROM ip_rate_limit WHERE ip = ? AND action = ? AND last_time < ?`).bind(ip, action, cleanThreshold).run();
  const row = await db.prepare(`SELECT count FROM ip_rate_limit WHERE ip = ? AND action = ?`).bind(ip, action).first();
  if (row && row.count >= limitCount) return false;
  if (row) {
    await db.prepare(`UPDATE ip_rate_limit SET count = count + 1, last_time = ?, expire = ? WHERE ip = ? AND action = ?`).bind(now, windowExp, ip, action).run();
  } else {
    await db.prepare(`INSERT INTO ip_rate_limit (ip, action, count, last_time, expire) VALUES (?, ?, 1, ?, ?)`).bind(ip, action, now, windowExp).run();
  }
  return true;
}

// CSRF简易校验（前端POST请求携带X-Csrf-Token，这里简化校验逻辑，可配合前端生成随机串）
function getCsrfToken(request) {
  return request.headers.get("X-Csrf-Token") || "";
}

export async function onRequest({ request, env }) {
  try {
    const db = env.DB;
    const url = new URL(request.url);
    const action = url.searchParams.get('action');
    const reqMethod = request.method;
    const clientIp = request.headers.get("cf-connecting-ip") || "unknown";
    // 环境变量统一兜底
    const hmacSecret = env?.SESSION_HMAC_SECRET ?? "";
    const siteOrigin = env?.SITE_ORIGIN ?? "";
    const resendKey = env?.RESEND_API_KEY ?? "";
    const mailFromName = env?.MAIL_FROM_NAME ?? "博客账号系统";
    const mailFromAddr = env?.MAIL_FROM_EMAIL ?? "notify@resend.dev";
    const loginUser = hmacSecret ? await getLoginUser(request, hmacSecret) : null;

    if (reqMethod === "OPTIONS") return jsonResp(null);
    if (!db) return jsonResp({ code: 500, msg: "数据库未绑定" }, 500);
    if (!hmacSecret || !siteOrigin) return jsonResp({ code: 500, msg: "基础环境变量缺失" }, 500);

    // ==================== 路由统一标准化，删除微软回调补丁 ====================
    // GitHub登录跳转
    if (action === "githubLogin") {
      const cid = env?.GITHUB_CLIENT_ID;
      if (!cid) return jsonResp({ code: 500, msg: "GitHub配置缺失" }, 500);
      const redirectUri = `${siteOrigin}/api/user?action=githubCallback`;
      const state = await generateOauthState(hmacSecret, "login");
      const authUrl = new URL("https://github.com/login/oauth/authorize");
      authUrl.searchParams.set("client_id", cid);
      authUrl.searchParams.set("redirect_uri", redirectUri);
      authUrl.searchParams.set("scope", "read:user");
      authUrl.searchParams.set("state", state);
      return Response.redirect(authUrl.toString(), 302);
    }
    if (action === "githubBind") {
      if (!loginUser) return jsonResp({ code: 401, msg: "请登录" }, 401);
      const cid = env?.GITHUB_CLIENT_ID;
      const redirectUri = `${siteOrigin}/api/user?action=githubCallback`;
      const state = await generateOauthState(hmacSecret, "bind");
      const authUrl = new URL("https://github.com/login/oauth/authorize");
      authUrl.searchParams.set("client_id", cid);
      authUrl.searchParams.set("redirect_uri", redirectUri);
      authUrl.searchParams.set("scope", "read:user");
      authUrl.searchParams.set("state", state);
      return Response.redirect(authUrl.toString(), 302);
    }
    if (action === "githubCallback") {
      const cid = env?.GITHUB_CLIENT_ID;
      const csec = env?.GITHUB_CLIENT_SECRET;
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      if (!cid || !csec || !code || !state) return jsonResp({ code: 400, msg: "参数缺失" }, 400);
      const statePay = await verifyOauthState(state, hmacSecret);
      if (!statePay) return jsonResp({ code: 403, msg: "CSRF校验失败" }, 403);
      const redirectUri = `${siteOrigin}/api/user?action=githubCallback`;
      const tokenData = await getGithubToken(code, cid, csec, redirectUri);
      if (tokenData.error) return jsonResp({ code: 500, msg: "获取令牌失败" }, 500);
      const userInfo = await getGithubUserInfo(tokenData.access_token);
      if (userInfo.error) return jsonResp({ code: 500, msg: "获取用户信息失败" }, 500);
      const ghId = String(userInfo.id);
      const ghName = userInfo.login;
      const bindUser = await db.prepare(`SELECT id,username,role,is_cancel,email FROM users WHERE github_id = ?`).bind(ghId).first();
      if (statePay.type === "bind") {
        if (!loginUser) return Response.redirect(`${siteOrigin}/login.html`, 302);
        if (bindUser) return jsonResp({ code: 500, msg: "该GitHub已绑定其他账号" }, 500);
        await db.prepare(`UPDATE users SET github_id = ? WHERE id = ?`).bind(ghId, loginUser.uid).run();
        return Response.redirect(`${siteOrigin}/account.html`, 302);
      }
      if (statePay.type === "login") {
        if (bindUser) {
          if (bindUser.is_cancel || bindUser.role === "banned") return jsonResp({ code: 403, msg: "账号封禁/注销" }, 403);
          const token = await createSignedSessionToken(bindUser.id, bindUser.username, bindUser.role, hmacSecret);
          if (resendKey && bindUser.email) await sendNewLoginAlert(bindUser.email, bindUser.username, clientIp, resendKey, mailFromName, mailFromAddr);
          return new Response(null, { status: 302, headers: { Location: `${siteOrigin}/`, "Set-Cookie": buildSecureSessionCookie(token, 86400) } });
        } else {
          let newUser;
          try {
            await db.prepare(`INSERT INTO users (username,password,role,is_cancel,github_id,microsoft_id,email) VALUES (?,?,'guest',0,?,NULL,NULL)`).bind(ghName, "", ghId).run();
            newUser = await db.prepare(`SELECT id,username,role FROM users WHERE github_id = ?`).bind(ghId).first();
          } catch {
            const fixName = `${ghName}_${ghId.slice(-4)}`;
            await db.prepare(`INSERT INTO users (username,password,role,is_cancel,github_id,microsoft_id,email) VALUES (?,?,'guest',0,?,NULL,NULL)`).bind(fixName, "", ghId).run();
            newUser = await db.prepare(`SELECT id,username,role FROM users WHERE github_id = ?`).bind(ghId).first();
          }
          const token = await createSignedSessionToken(newUser.id, newUser.username, newUser.role, hmacSecret);
          return new Response(null, { status: 302, headers: { Location: `${siteOrigin}/`, "Set-Cookie": buildSecureSessionCookie(token, 86400) } });
        }
      }
    }
    // 微软OAuth（无路径补丁，统一action路由）
    if (action === "microsoftLogin") {
      const msCid = env?.MS_CLIENT_ID;
      const redirectUri = `${siteOrigin}/api/user?action=microsoftCallback`;
      const state = await generateOauthState(hmacSecret, "login");
      const authUrl = new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
      authUrl.searchParams.set("client_id", msCid);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("redirect_uri", redirectUri);
      authUrl.searchParams.set("scope", "openid profile email");
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("response_mode", "query");
      return Response.redirect(authUrl.toString(), 302);
    }
    if (action === "microsoftBind") {
      if (!loginUser) return jsonResp({ code: 401, msg: "请登录" }, 401);
      const msCid = env?.MS_CLIENT_ID;
      const redirectUri = `${siteOrigin}/api/user?action=microsoftCallback`;
      const state = await generateOauthState(hmacSecret, "bind");
      const authUrl = new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
      authUrl.searchParams.set("client_id", msCid);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("redirect_uri", redirectUri);
      authUrl.searchParams.set("scope", "openid profile email");
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("response_mode", "query");
      return Response.redirect(authUrl.toString(), 302);
    }
    if (action === "microsoftCallback") {
      const msCid = env?.MS_CLIENT_ID;
      const msSec = env?.MS_CLIENT_SECRET;
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const redirectUri = `${siteOrigin}/api/user?action=microsoftCallback`;
      if (!msCid || !msSec || !code || !state) return jsonResp({ code: 400, msg: "参数缺失" }, 400);
      const statePay = await verifyOauthState(state, hmacSecret);
      if (!statePay) return jsonResp({ code: 403, msg: "CSRF校验失败" }, 403);
      const tokenRes = await getMicrosoftToken(code, msCid, msSec, redirectUri);
      if (tokenRes.error) return jsonResp({ code: 500, msg: "获取令牌失败" }, 500);
      const msUser = await getMicrosoftUserInfo(tokenRes.access_token);
      if (!msUser.id) return jsonResp({ code: 500, msg: "获取用户信息失败" }, 500);
      const msUid = String(msUser.id);
      const msName = msUser.displayName || `MS_${msUid.slice(-6)}`;
      const bindUser = await db.prepare(`SELECT id,username,role,is_cancel,email FROM users WHERE microsoft_id = ?`).bind(msUid).first();
      if (statePay.type === "bind") {
        if (!loginUser) return Response.redirect(`${siteOrigin}/login.html`, 302);
        if (bindUser) return jsonResp({ code: 500, msg: "该微软账号已绑定其他账号" }, 500);
        await db.prepare(`UPDATE users SET microsoft_id = ? WHERE id = ?`).bind(msUid, loginUser.uid).run();
        return Response.redirect(`${siteOrigin}/account.html`, 302);
      }
      if (statePay.type === "login") {
        if (bindUser) {
          if (bindUser.is_cancel || bindUser.role === "banned") return jsonResp({ code: 403, msg: "账号封禁/注销" }, 403);
          const token = await createSignedSessionToken(bindUser.id, bindUser.username, bindUser.role, hmacSecret);
          if (resendKey && bindUser.email) await sendNewLoginAlert(bindUser.email, bindUser.username, clientIp, resendKey, mailFromName, mailFromAddr);
          return new Response(null, { status: 302, headers: { Location: `${siteOrigin}/`, "Set-Cookie": buildSecureSessionCookie(token, 86400) } });
        } else {
          let newUser;
          try {
            await db.prepare(`INSERT INTO users (username,password,role,is_cancel,microsoft_id,github_id,email) VALUES (?,?,'guest',0,?,NULL,NULL)`).bind(msName, "", msUid).run();
            newUser = await db.prepare(`SELECT id,username,role FROM users WHERE microsoft_id = ?`).bind(msUid).first();
          } catch {
            const fixName = `MS_${msUid.slice(-6)}`;
            await db.prepare(`INSERT INTO users (username,password,role,is_cancel,microsoft_id,github_id,email) VALUES (?,?,'guest',0,?,NULL,NULL)`).bind(fixName, "", msUid).run();
            newUser = await db.prepare(`SELECT id,username,role FROM users WHERE microsoft_id = ?`).bind(msUid).first();
          }
          const token = await createSignedSessionToken(newUser.id, newUser.username, newUser.role, hmacSecret);
          return new Response(null, { status: 302, headers: { Location: `${siteOrigin}/`, "Set-Cookie": buildSecureSessionCookie(token, 86400) } });
        }
      }
    }
    // 解绑
    if (action === "unbindMicrosoft" && reqMethod === "POST") {
      if (!loginUser) return jsonResp({ code: 401, msg: "未登录" }, 401);
      await db.prepare(`UPDATE users SET microsoft_id = NULL WHERE id = ?`).bind(loginUser.uid).run();
      return jsonResp({ code: 0, msg: "微软解绑成功" });
    }
    if (action === "unbindGithub" && reqMethod === "POST") {
      if (!loginUser) return jsonResp({ code: 401, msg: "未登录" }, 401);
      await db.prepare(`UPDATE users SET github_id = NULL WHERE id = ?`).bind(loginUser.uid).run();
      return jsonResp({ code: 0, msg: "GitHub解绑成功" });
    }
    if (action === "logout" && reqMethod === "POST") {
      return new Response(JSON.stringify({ code: 0, msg: "已退出登录" }), { headers: { "Content-Type": "application/json; charset=utf-8", "Set-Cookie": buildClearSessionCookie() } });
    }
    if (action === "check") {
      if (!loginUser) return jsonResp({ code: 0, login: false });
      const userInfo = await db.prepare(`SELECT role,is_cancel,github_id,microsoft_id,email FROM users WHERE id = ?`).bind(loginUser.uid).first();
      if (!userInfo || userInfo.role === "banned" || userInfo.is_cancel === 1) {
        return new Response(JSON.stringify({ code: 0, login: false, banned: true }), { headers: { "Content-Type": "application/json; charset=utf-8", "Set-Cookie": buildClearSessionCookie() } });
      }
      // 基础返回，第三方ID仅owner可见
      return jsonResp({ code: 0, login: true, uid: loginUser.uid, username: loginUser.username, role: userInfo.role });
    }
    // 发送验证码（全D1限流，废弃内存Map）
    if (action === "sendEmailCode") {
      if (reqMethod !== "POST") return jsonResp({ code: 405, msg: "仅POST" }, 405);
      // 限流：同一IP 1分钟最多1次
      const limitOk = await checkRateLimit(db, clientIp, "sendEmailCode", 1, 60 * 1000);
      if (!limitOk) return jsonResp({ code: 429, msg: "操作频繁，请稍后再试" });
      let body;
      try { body = await request.json(); } catch { return jsonResp({ code: 400, msg: "JSON格式错误" }, 400); }
      const { email } = body;
      const targetEmail = email?.trim().toLowerCase() || "";
      if (!EMAIL_REG.test(targetEmail)) return jsonResp({ code: 400, msg: "邮箱格式错误" });
      const now = Date.now();
      const expireTs = now + CODE_EXPIRE;
      const code = generateSixCode();
      if (!resendKey) return jsonResp({ code: 500, msg: "邮件密钥未配置" }, 500);
      const mailRes = await sendMailByResend(targetEmail, "注册验证码", `<h3>验证码：${code}</h3><p>5分钟有效</p>`, resendKey, mailFromName, mailFromAddr);
      if (mailRes.error) return jsonResp({ code: 500, msg: "邮件发送失败" }, 500);
      // 清理过期记录
      await db.prepare(`DELETE FROM email_verifications WHERE email = ? AND expires_at < ?`).bind(targetEmail, now).run();
      await db.prepare(`INSERT INTO email_verifications (email,code,nonce,used,expires_at) VALUES (?,?,?,0,?)`).bind(targetEmail, code, generateNonce(), expireTs).run();
      return jsonResp({ code: 0, msg: "验证码已发送" });
    }
    // 忘记密码（修复令牌裸奔，新增nonce、入库完整token）
    if (action === "forgetPassword") {
      if (reqMethod !== "POST") return jsonResp({ code: 405, msg: "禁止直接访问" }, 405);
      const limitOk = await checkRateLimit(db, clientIp, "forgetPassword", 1, 60 * 1000);
      if (!limitOk) return jsonResp({ code: 429, msg: "请求频繁" });
      let body;
      try { body = await request.json(); } catch { return jsonResp({ code: 400, msg: "参数错误" }, 400); }
      const { email } = body;
      const targetEmail = email?.trim().toLowerCase() || "";
      if (!EMAIL_REG.test(targetEmail)) return jsonResp({ code: 400, msg: "邮箱非法" });
      const user = await db.prepare(`SELECT id,username FROM users WHERE email = ?`).bind(targetEmail).first();
      if (!user) return jsonResp({ code: 0, msg: "若邮箱已注册，重置链接已发送" });
      const resetExpire = Date.now() + 15 * 60 * 1000;
      const nonce = generateNonce();
      const payload = JSON.stringify({ uid: user.id, exp: resetExpire, nonce });
      const payB64 = base64UrlEncode(new TextEncoder().encode(payload));
      const hmacKey = await getHmacKey(hmacSecret);
      const sig = base64UrlEncode(await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(payB64)));
      const resetToken = `${payB64}.${sig}`;
      const baseUrl = siteOrigin.endsWith('/') ? siteOrigin.slice(0, -1) : siteOrigin;
      const resetUrl = `${baseUrl}/reset-password.html?token=${resetToken}`;
      const mailRes = await sendResetPasswordMail(targetEmail, user.username, resetUrl, resendKey, mailFromName, mailFromAddr);
      if (mailRes.error) return jsonResp({ code: 500, msg: "邮件发送失败" }, 500);
      await db.prepare(`DELETE FROM email_verifications WHERE email = ? AND expires_at < ?`).bind(targetEmail, Date.now()).run();
      // 存入完整token+nonce，标记未使用
      await db.prepare(`INSERT INTO email_verifications (email,code,nonce,used,expires_at) VALUES (?,?,?,0,?)`).bind(targetEmail, resetToken, nonce, resetExpire).run();
      return jsonResp({ code: 0, msg: "重置链接已发送，15分钟有效，仅可使用一次" });
    }
    // 【新增】重置密码接口，闭环令牌校验，解决之前只生成不校验漏洞
    if (action === "resetPassword" && reqMethod === "POST") {
      const limitOk = await checkRateLimit(db, clientIp, "resetPassword", 3, 60 * 1000);
      if (!limitOk) return jsonResp({ code: 429, msg: "操作频繁" });
      let body;
      try { body = await request.json(); } catch { return jsonResp({ code: 400, msg: "参数错误" }, 400); }
      const { token, newPwd } = body;
      if (!token || !checkPasswordStrength(newPwd)) return jsonResp({ code: 1, msg: "密码长度至少8位，包含大小写+数字" });
      const [payB64, sigB64] = token.split('.');
      if (!payB64 || !sigB64) return jsonResp({ code: 1, msg: "重置令牌无效" });
      // 校验HMAC签名
      const hmacKey = await getHmacKey(hmacSecret);
      const sigRaw = base64UrlDecode(sigB64);
      const sigOk = await crypto.subtle.verify("HMAC", hmacKey, sigRaw, new TextEncoder().encode(payB64));
      if (!sigOk) return jsonResp({ code: 1, msg: "令牌非法" });
      // 解析载荷
      let payload;
      try { payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payB64))); } catch { return jsonResp({ code: 1, msg: "令牌解析失败" }); }
      const now = Date.now();
      if (now > payload.exp) return jsonResp({ code: 1, msg: "令牌已过期" });
      // 数据库校验：令牌未使用、匹配邮箱
      const userRow = await db.prepare(`SELECT email FROM users WHERE id = ?`).bind(payload.uid).first();
      if (!userRow) return jsonResp({ code: 1, msg: "用户不存在" });
      const record = await db.prepare(`SELECT id,used,nonce FROM email_verifications WHERE email = ? ORDER BY id DESC LIMIT 1`).bind(userRow.email).first();
      if (!record || record.used === 1 || record.nonce !== payload.nonce) return jsonResp({ code: 1, msg: "令牌已失效或已使用" });
      // 原子更新密码 + 标记令牌已使用
      const newHash = await hashPassword(newPwd);
      await db.batch([
        db.prepare(`UPDATE users SET password = ? WHERE id = ?`).bind(newHash, payload.uid),
        db.prepare(`UPDATE email_verifications SET used = 1 WHERE id = ?`).bind(record.id)
      ]);
      return jsonResp({ code: 0, msg: "密码重置成功，请登录" });
    }
    // 注册
    if (action === "register" && reqMethod === "POST") {
      const limitOk = await checkRateLimit(db, clientIp, "register", 2, 60 * 60 * 1000);
      if (!limitOk) return jsonResp({ code: 429, msg: "注册过于频繁" });
      let body = await request.json();
      const { username, password, email, code } = body;
      if (!checkPasswordStrength(password)) return jsonResp({ code: 1, msg: "密码至少8位，大小写+数字" });
      const targetEmail = email.trim().toLowerCase();
      const verifyRec = await db.prepare(`SELECT code,expires_at FROM email_verifications WHERE email = ? ORDER BY id DESC LIMIT 1`).bind(targetEmail).first();
      if (!verifyRec || Date.now() > verifyRec.expires_at || verifyRec.code !== code) return jsonResp({ code: 1, msg: "验证码无效" });
      const hashPwd = await hashPassword(password);
      try {
        await db.prepare(`INSERT INTO users (username,password,role,is_cancel,github_id,microsoft_id,email) VALUES (?,?,'guest',0,NULL,NULL,?)`).bind(username, hashPwd, targetEmail).run();
        return jsonResp({ code: 0, msg: "注册成功" });
      } catch {
        return jsonResp({ code: 1, msg: "用户名已占用" });
      }
    }
    // 密码登录：防爆破，5次错误锁定15分钟
    if (action === "login" && reqMethod === "POST") {
      const limitKey = "loginPassword";
      const maxErr = 5;
      const lockTime = 15 * 60 * 1000;
      const now = Date.now();
      const cleanThr = now - lockTime;
      await db.prepare(`DELETE FROM ip_rate_limit WHERE ip = ? AND action = ? AND last_time < ?`).bind(clientIp, limitKey, cleanThr).run();
      const rateRow = await db.prepare(`SELECT count FROM ip_rate_limit WHERE ip = ? AND action = ?`).bind(clientIp, limitKey).first();
      if (rateRow && rateRow.count >= maxErr) return jsonResp({ code: 429, msg: "密码错误次数过多，15分钟后重试" });
      const body = await request.json();
      const { username, password } = body;
      const userRow = await db.prepare(`SELECT id,username,role,is_cancel,password,email,ban_until FROM users WHERE username = ?`).bind(username).first();
      // 统一返回，防止枚举账号
      if (!userRow) {
        await db.prepare(`INSERT OR REPLACE INTO ip_rate_limit (ip,action,count,last_time,expire) VALUES (?,?,1,?,?)`).bind(clientIp, limitKey, now, now + lockTime).run();
        return jsonResp({ code: 1, msg: "账号或密码错误" });
      }
      if (userRow.ban_until && now < userRow.ban_until) return jsonResp({ code: 2, msg: "账号临时封禁" });
      const pwdOk = await verifyPassword(password, userRow.password);
      if (!pwdOk) {
        const newCnt = rateRow ? rateRow.count + 1 : 1;
        await db.prepare(`INSERT OR REPLACE INTO ip_rate_limit (ip,action,count,last_time,expire) VALUES (?,?,?, ?, ?)`).bind(clientIp, limitKey, newCnt, now, now + lockTime).run();
        return jsonResp({ code: 1, msg: "账号或密码错误" });
      }
      // 登录成功，清空错误计数
      await db.prepare(`DELETE FROM ip_rate_limit WHERE ip = ? AND action = ?`).bind(clientIp, limitKey).run();
      if (userRow.role === "banned" || userRow.is_cancel === 1) return jsonResp({ code: 3, msg: "账号已注销/封禁" });
      // 旧密码自动升级
      if (!userRow.password.includes('$$')) {
        const newHash = await hashPassword(password);
        await db.prepare(`UPDATE users SET password = ? WHERE id = ?`).bind(newHash, userRow.id).run();
      }
      const sessionToken = await createSignedSessionToken(userRow.id, userRow.username, userRow.role, hmacSecret);
      if (resendKey && userRow.email) await sendNewLoginAlert(userRow.email, userRow.username, clientIp, resendKey, mailFromName, mailFromAddr);
      return new Response(JSON.stringify({ code: 0, msg: "登录成功" }), { headers: { "Content-Type": "application/json; charset=utf-8", "Set-Cookie": buildSecureSessionCookie(sessionToken, 86400) } });
    }
    // 修改角色
    if (action === "setRole" && reqMethod === "POST") {
      if (!loginUser || ["guest", "banned"].includes(loginUser.role)) return jsonResp({ code: 403, msg: "无权限" }, 403);
      const isOwner = loginUser.role === "owner";
      const body = await request.json();
      const { targetUid, newRole } = body;
      const allowRoles = ["admin", "writer", "guest", "banned"];
      if (newRole === "owner" || !allowRoles.includes(newRole)) return jsonResp({ code: 1, msg: "非法角色" });
      const targetUser = await db.prepare(`SELECT id,role FROM users WHERE id = ?`).bind(targetUid).first();
      if (!targetUser) return jsonResp({ code: 1, msg: "用户不存在" });
      if (targetUser.role === "owner") return jsonResp({ code: 403, msg: "无法修改所有者" }, 403);
      if (!isOwner && newRole === "admin") return jsonResp({ code: 403, msg: "管理员不能授予admin权限" }, 403);
      await db.prepare(`UPDATE users SET role = ? WHERE id = ?`).bind(newRole, targetUid).run();
      return jsonResp({ code: 0, msg: "角色修改成功" });
    }
    // 用户列表：脱敏，普通管理员隐藏第三方ID
    if (action === "userList" && reqMethod === "GET") {
      if (!loginUser || ["guest", "banned"].includes(loginUser.role)) return jsonResp({ code: 403, msg: "无权访问" }, 403);
      const isOwner = loginUser.role === "owner";
      const rawList = await db.prepare(`SELECT id,username,role,is_cancel,created_at,github_id,microsoft_id,email FROM users ORDER BY id DESC`).all();
      const list = rawList.results.map(item => {
        if (!isOwner) {
          delete item.github_id;
          delete item.microsoft_id;
          delete item.email;
        }
        return item;
      });
      return jsonResp({ code: 0, list });
    }
    // 删除用户：D1 batch事务，原子删除帖子+用户，无脏数据
    if (action === "deleteUser" && reqMethod === "POST") {
      if (!loginUser || ["guest", "banned"].includes(loginUser.role)) return jsonResp({ code: 403, msg: "无权操作" }, 403);
      const body = await request.json();
      const targetUid = Number(body.targetUid);
      if (isNaN(targetUid) || targetUid <= 0) return jsonResp({ code: 1, msg: "无效ID" });
      if (targetUid === loginUser.uid) return jsonResp({ code: 1, msg: "不能删除自己" });
      const targetUser = await db.prepare(`SELECT role FROM users WHERE id = ?`).bind(targetUid).first();
      if (!targetUser) return jsonResp({ code: 1, msg: "用户不存在" });
      if (targetUser.role === "owner") return jsonResp({ code: 403, msg: "禁止删除所有者" }, 403);
      if (loginUser.role !== "owner" && targetUser.role === "admin") return jsonResp({ code: 403, msg: "管理员无法删除其他管理员" }, 403);
      // 批量事务，原子执行
      await db.batch([
        db.prepare(`DELETE FROM posts WHERE author = ?`).bind(targetUid),
        db.prepare(`DELETE FROM users WHERE id = ?`).bind(targetUid)
      ]);
      return jsonResp({ code: 0, msg: "用户已删除" });
    }
    // 管理员新建用户
    if (action === "adminAddUser" && reqMethod === "POST") {
      if (!loginUser || ["guest", "banned"].includes(loginUser.role)) return jsonResp({ code: 403, msg: "仅管理员可用" }, 403);
      const body = await request.json();
      const { username, password, role } = body;
      if (!checkPasswordStrength(password)) return jsonResp({ code: 1, msg: "密码复杂度不足" });
      const allowRoles = ["admin", "writer", "guest", "banned"];
      if (role === "owner" || !allowRoles.includes(role)) return jsonResp({ code: 1, msg: "非法角色" });
      const hashPwd = await hashPassword(password);
      try {
        await db.prepare(`INSERT INTO users (username,password,role,is_cancel,github_id,microsoft_id,email) VALUES (?, ?, ?, 0, NULL, NULL, NULL)`).bind(username, hashPwd, role).run();
        return jsonResp({ code: 0, msg: "账号创建成功" });
      } catch {
        return jsonResp({ code: 2, msg: "用户名已占用" });
      }
    }
    // 修改密码
    if (action === "changePwd" && reqMethod === "POST") {
      if (!loginUser) return jsonResp({ code: 401, msg: "请登录" }, 401);
      const body = await request.json();
      const { oldPwd, newPwd } = body;
      if (!checkPasswordStrength(newPwd)) return jsonResp({ code: 1, msg: "新密码复杂度不足" });
      const userRow = await db.prepare(`SELECT password FROM users WHERE id = ?`).bind(loginUser.uid).first();
      if (!userRow || !(await verifyPassword(oldPwd, userRow.password))) return jsonResp({ code: 1, msg: "原密码错误" });
      const newHash = await hashPassword(newPwd);
      await db.prepare(`UPDATE users SET password = ? WHERE id = ?`).bind(newHash, loginUser.uid).run();
      return jsonResp({ code: 0, msg: "密码修改成功，请重新登录" });
    }
    // 注销账号
    if (action === "cancelAccount" && reqMethod === "POST") {
      if (!loginUser) return jsonResp({ code: 401, msg: "请登录" }, 401);
      const body = await request.json();
      const { password } = body;
      const userRow = await db.prepare(`SELECT password FROM users WHERE id = ?`).bind(loginUser.uid).first();
      if (!userRow || !(await verifyPassword(password, userRow.password))) return jsonResp({ code: 1, msg: "密码验证失败" });
      await db.prepare(`UPDATE users SET is_cancel = 1, github_id = NULL, microsoft_id = NULL WHERE id = ?`).bind(loginUser.uid).run();
      return new Response(JSON.stringify({ code: 0, msg: "账号已注销" }), { headers: { "Content-Type": "application/json; charset=utf-8", "Set-Cookie": buildClearSessionCookie() } });
    }
    return jsonResp({ code: 404, msg: "接口不存在" }, 404);
  } catch (globalErr) {
    // 【关键修复】删除stack、err详情不对外暴露，杜绝源码泄露
    console.error("Worker全局异常：", globalErr.message, globalErr.stack);
    return jsonResp({ code: 500, msg: "服务器内部错误，请稍后重试" }, 500);
  }
}