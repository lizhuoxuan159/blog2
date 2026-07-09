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
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000
  };
  const payloadJson = JSON.stringify(payload);
  const payloadB64 = base64UrlEncode(new TextEncoder().encode(payloadJson));
  const key = await getHmacKey(secret);
  const signature = await crypto.subtle.sign('SHA-256', key, new TextEncoder().encode(payloadJson));
  const signB64 = base64UrlEncode(new Uint8Array(signature));
  return `${payloadB64}.${signB64}`;
}

async function verifySessionToken(tokenStr, secret) {
  const parts = tokenStr.split('.');
  if (parts.length !== 2) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0])));
    if (Date.now() > payload.exp) return null;
    const key = await getHmacKey(secret);
    const signatureBuf = base64UrlDecode(parts[1]);
    const ok = await crypto.subtle.verify('SHA-256', key, signatureBuf, new TextEncoder().encode(JSON.stringify(payload)));
    return ok ? payload : null;
  } catch {
    return null;
  }
}

async function hashPassword(rawPwd, salt = null) {
  const enc = new TextEncoder();
  if (!salt) salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(rawPwd), { name: 'PBKDF2' }, false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA‑256" }, key, 256);
  const hashStr = base64UrlEncode(new Uint8Array(derivedBits));
  return base64UrlEncode(salt) + "$$" + hashStr;
}

async function verifyPassword(inputPwd, storedPwd) {
  if (!storedPwd.includes("$$")) {
    return await sha256(inputPwd) === storedPwd;
  }
  const [saltB64, hashB64] = storedPwd.split("$$");
  const salt = base64UrlDecode(saltB64);
  const newHash = await hashPassword(inputPwd, salt);
  return newHash.split("$$")[1] === hashB64;
}

// Cookie配置，SameSite=None 解决OAuth跨域丢失登录态
function buildSecureSessionCookie(token, maxAge) {
  return `__Secure-blog_session=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${maxAge}`;
}
function buildClearSessionCookie() {
  return `__Secure-blog_session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0`;
}

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json;charset=utf-8",
      "Cache-Control": "no-cache"
    }
  })
}

function redirect(targetUrl) {
  return new Response(null, {
    status: 302,
    headers: {
      Location: targetUrl,
      "Cache-Control": "no-cache, no-store, must-revalidate"
    }
  })
}

async function getLoginUser(request, hmacSecret) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/__Secure-blog_session=([^;]+)/);
  if (!match) return null;
  return await verifySessionToken(match[1], hmacSecret);
}

export async function onRequest({ request, env }) {
  try {
    const db = env.DB;
    const url = new URL(request.url);
    const pathname = url.pathname;
    const action = url.searchParams.get("action");
    const reqMethod = request.method;
    const clientIp = request.headers.get("cf-connecting-ip") || "";
    const hmacSecret = env.SESSION_HMAC_SECRET;
    const siteOrigin = env.SITE_ORIGIN ?? "https://blog.lizhuoxuan.dpdns.org";
    const loginUser = await getLoginUser(request, hmacSecret);

    // 处理预检OPTIONS请求，解决POST 405报错
    if (reqMethod === "OPTIONS") {
      return new Response("", {
        headers: {
          "Access-Control-Allow-Origin": siteOrigin,
          "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type"
        }
      })
    }

    // ============ 密码登录接口 /api/user?action=login 只允许POST ============
    if (pathname === "/api/user" && action === "login" && reqMethod === "POST") {
      const limitKey = "loginPassword";
      const maxErr = 5;
      const lockTime = 15 * 60 * 1000;
      const now = Date.now();
      const cleanThr = now - lockTime;
      // 清理超时的错误计数
      await db.prepare(`DELETE FROM ip_rate_limit WHERE ip = ? AND action = ? AND last_time < ?`)
        .bind(clientIp, limitKey, cleanThr).run();

      const rateRow = await db.prepare(`SELECT count FROM ip_rate_limit WHERE ip = ? AND action = ?`)
        .bind(clientIp, limitKey).first();
      if (rateRow && rateRow.count >= maxErr) {
        return jsonResp({ code: 429, msg: "密码错误次数过多，请15分钟后重试" }, 429);
      }
      // 解析前端提交表单
      const body = await request.json();
      const { username, password } = body;
      const userRow = await db.prepare(`
        SELECT id, username, password, role, ban_until FROM users WHERE username = ?
      `).bind(username).first();

      if (!userRow) {
        await db.prepare(`
          INSERT OR REPLACE INTO ip_rate_limit(ip, action, count, last_time, expire)
          VALUES (?, ?, ?, ?, ?)
        `).bind(clientIp, limitKey, rateRow ? rateRow.count + 1 : 1, now, now + lockTime).run();
        return jsonResp({ code: 1, msg: "账号或密码错误" });
      }
      // 判断账号封禁
      if (userRow.ban_until && now < userRow.ban_until) {
        return jsonResp({ code: 2, msg: "账号被临时封禁" });
      }
      // 校验密码
      const passOk = await verifyPassword(password, userRow.password);
      if (!passOk) {
        await db.prepare(`
          INSERT OR REPLACE INTO ip_rate_limit(ip, action, count, last_time, expire)
          VALUES (?, ?, ?, ?, ?)
        `).bind(clientIp, limitKey, rateRow ? rateRow.count + 1 : 1, now, now + lockTime).run();
        return jsonResp({ code: 1, msg: "账号或密码错误" });
      }
      // 登录成功，清除错误计数，生成会话Cookie
      await db.prepare(`DELETE FROM ip_rate_limit WHERE ip = ? AND action = ?`)
        .bind(clientIp, limitKey).run();
      const sessionToken = await createSignedSessionToken(userRow.id, userRow.username, userRow.role, hmacSecret);
      const response = jsonResp({ code: 0, msg: "登录成功" });
      response.headers.set("Set-Cookie", buildSecureSessionCookie(sessionToken, 7 * 24 * 3600));
      return response;
    }

    // ============ 微软独立无参回调路由，解决Azure禁止query参数 ============
    if (pathname === "/api/microsoftCallback") {
      const msCid = env.MS_CLIENT_ID;
      const msSec = env.MS_CLIENT_SECRET;
      const code = url.searchParams.get("code");
      const stateRaw = url.searchParams.get("state");
      const redirectUri = `${siteOrigin}/api/microsoftCallback`;
      if (!msCid || !msSec || !code || !stateRaw) return jsonResp({ code: 400, msg: "参数缺失" }, 400);

      async function generateOauthState(secret, flowType) {
        const nonceBuf = crypto.getRandomValues(new Uint8Array(16));
        const payload = {
          nonce: base64UrlEncode(nonceBuf),
          ts: Date.now(),
          type: flowType,
          exp: Date.now() + 10 * 60 * 1000
        };
        const payloadJson = JSON.stringify(payload);
        const key = await getHmacKey(secret);
        const sign = await crypto.subtle.sign("SHA-256", key, new TextEncoder().encode(payloadJson));
        return base64UrlEncode(new TextEncoder().encode(payloadJson)) + "." + base64UrlEncode(new Uint8Array(sign));
      }
      async function verifyOauthState(stateStr, secret) {
        const parts = stateStr.split(".");
        if (parts.length !== 2) return null;
        try {
          const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0])));
          if (Date.now() > payload.exp) return null;
          const key = await getHmacKey(secret);
          const signBuf = base64UrlDecode(parts[1]);
          const valid = await crypto.subtle.verify("SHA-256", key, signBuf, new TextEncoder().encode(JSON.stringify(payload)));
          return valid ? payload : null;
        } catch {
          return null;
        }
      }

      const statePay = await verifyOauthState(stateRaw, hmacSecret);
      if (!statePay) return jsonResp({ code: 403, msg: "CSRF校验失败" }, 403);
      // 获取微软token
      const tokenRes = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: msCid,
          client_secret: msSec,
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri
        })
      })
      const tokenData = await tokenRes.json();
      if (!tokenData.access_token) return jsonResp({ code: 500, msg: "获取令牌失败" }, 500);
      const msUserRes = await fetch("https://graph.microsoft.com/v1.0/me?$select=id,displayName,mail", {
        headers: { Authorization: `Bearer ${tokenData.access_token}` }
      })
      const msUser = await msUserRes.json();
      const msUid = String(msUser.id);
      const bindUser = await db.prepare(`SELECT id FROM users WHERE microsoft_id = ?`).bind(msUid).first();

      if (statePay.type === "bind") {
        if (!loginUser) return redirect(`${siteOrigin}/login.html`);
        if (bindUser) return jsonResp({ code: 500, msg: "该微软账号已绑定其他账号" }, 500);
        const updateRes = await db.prepare(`UPDATE users SET microsoft_id = ? WHERE id = ?`)
          .bind(msUid, loginUser.uid).run();
        if (updateRes.changes > 0) {
          return redirect(`${siteOrigin}/account.html`);
        } else {
          return redirect(`${siteOrigin}/`);
        }
      }
      if (statePay.type === "login") {
        if (bindUser) {
          const token = await createSignedSessionToken(bindUser.id, bindUser.username, bindUser.role, hmacSecret);
          const resp = redirect(`${siteOrigin}/`);
          resp.headers.set("Set-Cookie", buildSecureSessionCookie(token, 7 * 86400));
          return resp;
        } else {
          return redirect(`${siteOrigin}/register.html`);
        }
      }
    }

    // ============ 微软登录跳转 /api/user?action=microsoftLogin ============
    if (pathname === "/api/user" && action === "microsoftLogin") {
      async function generateOauthState(secret, flowType) {
        const nonceBuf = crypto.getRandomValues(new Uint8Array(16));
        const payload = {
          nonce: base64UrlEncode(nonceBuf),
          ts: Date.now(),
          type: flowType,
          exp: Date.now() + 10 * 60 * 1000
        };
        const payloadJson = JSON.stringify(payload);
        const key = await getHmacKey(secret);
        const sign = await crypto.subtle.sign("SHA-256", key, new TextEncoder().encode(payloadJson));
        return base64UrlEncode(new TextEncoder().encode(payloadJson)) + "." + base64UrlEncode(new Uint8Array(sign));
      }
      const msCid = env.MS_CLIENT_ID;
      const redirectUri = `${siteOrigin}/api/microsoftCallback`;
      if (!msCid) return jsonResp({ code: 500, msg: "未配置MS_CLIENT_ID" }, 500);
      const state = await generateOauthState(hmacSecret, "login");
      const authUrl = new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
      authUrl.searchParams.set("client_id", msCid);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("redirect_uri", redirectUri);
      authUrl.searchParams.set("scope", "openid profile email");
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("response_mode", "query");
      return redirect(authUrl.toString());
    }

    // ============ 微软绑定跳转 /api/user?action=microsoftBind ============
    if (pathname === "/api/user" && action === "microsoftBind") {
      if (!loginUser) return jsonResp({ code: 401, msg: "请先登录" }, 401);
      async function generateOauthState(secret, flowType) {
        const nonceBuf = crypto.getRandomValues(new Uint8Array(16));
        const payload = {
          nonce: base64UrlEncode(nonceBuf),
          ts: Date.now(),
          type: flowType,
          exp: Date.now() + 10 * 60 * 1000
        };
        const payloadJson = JSON.stringify(payload);
        const key = await getHmacKey(secret);
        const sign = await crypto.subtle.sign("SHA-256", key, new TextEncoder().encode(payloadJson));
        return base64UrlEncode(new TextEncoder().encode(payloadJson)) + "." + base64UrlEncode(new Uint8Array(sign));
      }
      const msCid = env.MS_CLIENT_ID;
      const redirectUri = `${siteOrigin}/api/microsoftCallback`;
      const state = await generateOauthState(hmacSecret, "bind");
      const authUrl = new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
      authUrl.searchParams.set("client_id", msCid);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("redirect_uri", redirectUri);
      authUrl.searchParams.set("scope", "openid profile email");
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("response_mode", "query");
      return redirect(authUrl.toString());
    }

    // 兜底404
    return jsonResp({ code: 404, msg: "接口不存在" }, 404);
  } catch (globalErr) {
    console.error("Worker异常：", globalErr.message);
    return jsonResp({ code: 500, msg: "服务器内部错误"+ globalErr.message}, 500);
  }
}
