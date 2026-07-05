async function sha256(rawStr) {
  const encoder = new TextEncoder();
  const data = encoder.encode(rawStr);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Base64URL 工具（JWT标准编码，剔除填充、+/替换）
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

// 导入HMAC密钥
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

// 签名会话生成
async function createSignedSessionToken(uid, username, role, secret) {
  const payload = {
    uid,
    username,
    role,
    exp: Date.now() + 604800000 // 7天有效期
  };
  const payloadJson = JSON.stringify(payload);
  const payloadB64 = base64UrlEncode(new TextEncoder().encode(payloadJson));
  const key = await getHmacKey(secret);
  const signatureBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  const sigB64 = base64UrlEncode(signatureBuf);
  return `${payloadB64}.${sigB64}`;
}

// 校验会话Token
async function verifySessionToken(tokenStr, secret) {
  const parts = tokenStr.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sigB64] = parts;
  const key = await getHmacKey(secret);
  const sigBuf = base64UrlDecode(sigB64);
  const ok = await crypto.subtle.verify(
    'HMAC',
    key,
    sigBuf,
    new TextEncoder().encode(payloadB64)
  );
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

// 安全Cookie工具
function buildSecureSessionCookie(token, maxAge) {
  return `__Host-blog_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}
function buildClearSessionCookie() {
  return `__Host-blog_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

// 升级统一跨域返回
function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    }
  });
}

// 解析当前登录用户
async function getLoginUser(request, hmacSecret) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/__Host-blog_session=([^;]+)/);
  if (!match) return null;
  return await verifySessionToken(match[1], hmacSecret);
}

// 新版PBKDF2密码加密
async function hashPassword(rawPwd, salt = null) {
  const enc = new TextEncoder();
  let saltBuf;
  if (!salt) {
    saltBuf = crypto.getRandomValues(new Uint8Array(16));
  } else {
    saltBuf = base64UrlDecode(salt);
  }
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(rawPwd),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
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

// 【核心兼容】新旧密码同时校验，旧SHA256自动适配
async function verifyPassword(rawPwd, storedHash) {
  if (storedHash.includes('$$')) {
    const parts = storedHash.split('$$');
    if (parts.length !== 2) return false;
    const [salt, hash] = parts;
    const newHash = await hashPassword(rawPwd, salt);
    return newHash.split('$$')[1] === hash;
  } else {
    // 纯旧版SHA256哈希
    const oldCalc = await sha256(rawPwd);
    return oldCalc === storedHash;
  }
}

// GitHub OAuth 请求
async function getGithubToken(code, clientId, clientSecret, redirectUri) {
  const res = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      "User-Agent": "Pages-OAuth/1.0",
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json"
    },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code: code,
      redirect_uri: redirectUri
    })
  });
  const rawText = await res.text();
  try {
    return JSON.parse(rawText);
  } catch {
    return {
      error: true,
      msg: "GitHub授权接口返回非JSON内容",
      detail: rawText.slice(0, 300)
    };
  }
}
async function getGithubUserInfo(accessToken) {
  const res = await fetch("https://api.github.com/user", {
    headers: {
      "User-Agent": "Pages-OAuth/1.0",
      Authorization: `Bearer ${accessToken}`
    }
  });
  if (!res.ok) {
    const raw = await res.text();
    return {
      error: true,
      msg: `GitHub用户接口异常，状态码${res.status}`,
      detail: raw.slice(0, 300)
    };
  }
  const raw = await res.text();
  try {
    return JSON.parse(raw);
  } catch {
    return {
      error: true,
      msg: "拉取GitHub用户信息失败，返回非标准JSON",
      detail: raw.slice(0, 300)
    };
  }
}

// 微软OAuth 请求
async function getMicrosoftToken(code, clientId, clientSecret, redirectUri) {
  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "authorization_code",
    code: code,
    redirect_uri: redirectUri
  });
  const res = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const rawText = await res.text();
  try {
    return JSON.parse(rawText);
  } catch {
    return { error: true, msg: "微软令牌接口返回内容异常", detail: rawText.slice(0,300) };
  }
}
async function getMicrosoftUserInfo(accessToken) {
  const res = await fetch("https://graph.microsoft.com/v1.0/me?$select=id,displayName,mail", {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (!res.ok) {
    const raw = await res.text();
    return { error: true, msg: "获取微软用户信息失败", detail: raw.slice(0,300) };
  }
  return await res.json();
}

// OAuth State 携带场景类型 login/bind 防CSRF
async function generateOauthState(secret, flowType) {
  const nonceBuf = crypto.getRandomValues(new Uint8Array(16));
  const nonce = base64UrlEncode(nonceBuf);
  const payload = { nonce, ts: Date.now(), type: flowType };
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
  const ok = await crypto.subtle.verify(
    'HMAC',
    key,
    base64UrlDecode(sigB64),
    new TextEncoder().encode(payB64)
  );
  if (!ok) return false;
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payB64)));
    if (Date.now() - payload.ts > 600000) return false;
    return payload;
  } catch {
    return false;
  }
}

// 验证码全局缓存、配置
常量 编码存储 = 新的 地图();
常量 CODE_EXPIRE = 5 * 60 * 1000;
常量 RATE_LIMIT = 60 * 1000;

// 生成6位数字验证码
功能 generateSixCode() {
  返回 线(数学.地板(100000 + 数学.随机的() * 900000));
}

//重新发送发信函数，您喜欢notify@blog.Lizhuxuan.dpdns.org
异步 功能 sendMailByResend(targetEmail, 代码, api密钥) {
  常量 响应 = 等待 取来("https://api.resend.com/emails", {
    方法: "POST",
    标题: {
      "Authorization": `Bearer ${api密钥}`,
      "Content-Type": "application/json",
      "User-Agent": "Cloudflare-Pages-Worker"
    },
    身体: JSON.字符串化({
      从:"<notify@blog.lizhuoxuan.dpdns.org>",
      到: targetEmail,
      主题: "账号注册安全验证码",
      超文本标记语言: `
<div style="padding: 15px;font-family: system-ui;">
<h3>注册验证码</h3>
<p>本次验证码：<strong style="字体大小：20px；颜色：#1677ff">${代码}</strong></p>
          <p>验证码5分钟内有效，请勿转发给他人，非本人操作可直接忽略。</p>
        </div>
      `
    })
  });
  返回 等待 响应.json();
}

出口 异步 功能 应要求({ 请求, 环境 }) {
  尝试 {
    常量 数据库 = 环境.数据库;
    让 统一资源定位系统 = 新的 统一资源定位系统(请求.统一资源定位系统);

    // 微软回调路径兼容：无参路径内部补上action参数，适配Entra规则
    如果(统一资源定位系统.路径名 === "/api/microsoftCallback"){
      统一资源定位系统.searchParams.设置("action", "microsoftCallback");
    }

    常量 行动 = 统一资源定位系统.searchParams.得到('action');
    常量 hmacSecret = 环境.SESSION_HMAC_SECRET;
    如果 (!hmacSecret) 返回 jsonResp({ 代码: 500, 味精: "服务端会话密钥未配置" }, 500);
    常量 登录用户 = 等待 getLoginUser(请求, hmacSecret);
    常量 地点起源 = 环境.SITE_ORIGIN;
    常量 reqMethod = 请求.方法;
    常量 客户端Ip = 请求.标题.得到("cf-connecting-ip") || "unknown";

    // 全局OPTIONS跨域预检拦截
    如果(reqMethod === "OPTIONS") 返回 jsonResp(等于零的);

    //========GitHub拆分：拆分：，you mayotax，you mayoto you you=============================================================================================================================
    //1。GitHub游客快捷登录
    如果 (行动 === "githubLogin") {
      常量 客户端 Id = 环境.GITHUB_CLIENT_ID;
      如果 (!客户端 Id|| !地点起源) 返回 jsonResp({ 代码: 500, 味精: "GitHub登录配置缺失" }, 500);
      常量 redirectUri = `${地点起源}/api/user?action=githubCallback`;
      常量 githubAuthUrl = 新的 统一资源定位系统("https://github.com/login/oauth/authorize");
      常量 状态 = 等待 generateOauthState(hmacSecret, "login");
      githubAuthUrl.searchParams.设置("client_id", 客户端 Id);
      githubAuthUrl.searchParams.设置("redirect_uri", redirectUri);
      githubAuthUrl.searchParams.设置("scope", "read:user");
      githubAuthUrl.searchParams.设置("state", 状态);
      返回 反应.改寄(githubAuthUrl.转换为字符串(), 302);
    }
    // 2. GitHub 账号绑定（必须登录）
    如果 (行动 === "githubBind") {
      如果 (!登录用户) 返回 jsonResp({ 代码: 401, 味精: "请登录账号后再执行绑定" }, 401);
      常量 客户端 Id = 环境.GITHUB_CLIENT_ID;
      if (!clientId || !siteOrigin) return jsonResp({ code: 500, msg: "GitHub登录配置缺失" }, 500);
      const redirectUri = `${siteOrigin}/api/user?action=githubCallback`;
      const githubAuthUrl = new URL("https://github.com/login/oauth/authorize");
      const state = await generateOauthState(hmacSecret, "bind");
      githubAuthUrl.searchParams.set("client_id", clientId);
      githubAuthUrl.searchParams.set("redirect_uri", redirectUri);
      githubAuthUrl.searchParams.set("scope", "read:user");
      githubAuthUrl.searchParams.set("state", state);
      return Response.redirect(githubAuthUrl.toString(), 302);
    }

    // GitHub统一回调 自动区分登录/绑定
    if (action === "githubCallback") {
      const clientId = env.GITHUB_CLIENT_ID;
      const clientSecret = env.GITHUB_CLIENT_SECRET;
      if (!clientId || !clientSecret || !siteOrigin) return jsonResp({ code: 500, msg: "GitHub OAuth环境变量未完整配置" }, 500);
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      if (!code || !state) return jsonResp({ code: 500, msg: "授权回调参数缺失，请重新操作" }, 500);
      const statePayload = await verifyOauthState(state, hmacSecret);
      if (!statePayload) return jsonResp({ code: 403, msg: "OAuth请求非法，CSRF校验失败" }, 403);
      const flowType = statePayload.type;

      const redirectUri = `${siteOrigin}/api/user?action=githubCallback`;
      const tokenData = await getGithubToken(code, clientId, clientSecret, redirectUri);
      if (tokenData.error || !tokenData.access_token) return jsonResp({ code: 500, msg: tokenData.msg || "无法获取GitHub授权令牌", detail: tokenData.detail || "" }, 500);
      const userInfo = await getGithubUserInfo(tokenData.access_token);
      if (userInfo.error || !userInfo.id || !userInfo.login) return jsonResp({ code: 500, msg: "获取GitHub账号信息不完整，授权中断", detail: userInfo.detail || "" }, 500);

      const githubId = String(userInfo.id);
      const githubName = userInfo.login;
      const safeGithubId = githubId ?? null;
      let bindUser = await db.prepare(`SELECT id, username, role, is_cancel FROM users WHERE github_id = ?`).bind(safeGithubId).first();

      // 绑定分支
      if (flowType === "bind") {
        if (!loginUser) return Response.redirect(`${siteOrigin}/login.html`, 302);
        if (bindUser) return jsonResp({ code: 500, msg: "该GitHub账号已绑定其他网站账号，无法重复绑定" }, 500);
        await db.prepare(`UPDATE users SET github_id = ? WHERE id = ?`).bind(safeGithubId, loginUser.uid).run();
        const newToken = await createSignedSessionToken(loginUser.uid, loginUser.username, loginUser.role, hmacSecret);
        return new Response(null, { status: 302, headers: { Location: `${siteOrigin}/account.html`, "Set-Cookie": buildSecureSessionCookie(newToken, 86400) } });
      }
      // 登录分支
      if (flowType === "login") {
        if (bindUser) {
          if (bindUser.is_cancel === 1 || bindUser.role === "banned") return jsonResp({ code: 500, msg: "该绑定账号已注销或封禁，禁止登录" }, 500);
          const sessionToken = await createSignedSessionToken(bindUser.id, bindUser.username, bindUser.role, hmacSecret);
          return new Response(null, { status: 302, headers: { Location: `${siteOrigin}/`, "Set-Cookie": buildSecureSessionCookie(sessionToken, 86400) } });
        } else {
          let newUser;
          try {
            await db.prepare(`INSERT INTO users (username, password, role, is_cancel, github_id) VALUES (?, ?, 'guest', 0, ?)`).bind(githubName, "", safeGithubId).run();
            newUser = await db.prepare(`SELECT id, username, role FROM users WHERE github_id = ?`).bind(safeGithubId).first();
          } catch (e) {
            const fixName = `${githubName}_${githubId.slice(-4)}`;
            await db.prepare(`INSERT INTO users (username, password, role, is_cancel, github_id) VALUES (?, ?, 'guest', 0, ?)`).bind(fixName, "", safeGithubId).run();
            newUser = await db.prepare(`SELECT id, username, role FROM users WHERE github_id = ?`).bind(safeGithubId).first();
          }
          const sessionToken = await createSignedSessionToken(newUser.id, newUser.username, newUser.role, hmacSecret);
          return new Response(null, { status: 302, headers: { Location: `${siteOrigin}/`, "Set-Cookie": buildSecureSessionCookie(sessionToken, 86400) } });
        }
      }
    }

    // ========== 微软 拆分：游客登录、已登录绑定 两个独立入口 ==========
    // 1. 微软游客快捷登录
    if(action === "microsoftLogin"){
      const msClientId = env.MS_CLIENT_ID;
      const redirectUri = `${siteOrigin}/api/microsoftCallback`;
      if(!msClientId) return jsonResp({code:500,msg:"微软登录客户端ID未配置"},500);
      const state = await generateOauthState(hmacSecret, "login");
      const msAuthUrl = new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
      msAuthUrl.searchParams.set("client_id", msClientId);
      msAuthUrl.searchParams.set("response_type", "code");
      msAuthUrl.searchParams.set("redirect_uri", redirectUri);
      msAuthUrl.searchParams.set("scope", "openid profile email");
      msAuthUrl.searchParams.set("state", state);
      msAuthUrl.searchParams.set("response_mode", "query");
      return Response.redirect(msAuthUrl.toString(),302);
    }
    // 2. 微软账号绑定（必须登录）
    if(action === "microsoftBind"){
      if (!loginUser) return jsonResp({ code: 401, msg: "请登录账号后再执行绑定" }, 401);
      const msClientId = env.MS_CLIENT_ID;
      const redirectUri = `${siteOrigin}/api/microsoftCallback`;
      if(!msClientId) return jsonResp({code:500,msg:"微软登录客户端ID未配置"},500);
      const state = await generateOauthState(hmacSecret, "bind");
      const msAuthUrl = new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
      msAuthUrl.searchParams.set("client_id", msClientId);
      msAuthUrl.searchParams.set("response_type", "code");
      msAuthUrl.searchParams.set("redirect_uri", redirectUri);
      msAuthUrl.searchParams.set("scope", "openid profile email");
      msAuthUrl.searchParams.set("state", state);
      msAuthUrl.searchParams.set("response_mode", "query");
      return Response.redirect(msAuthUrl.toString(),302);
    }

    // 微软统一回调
    if(action === "microsoftCallback"){
      const msClientId = env.MS_CLIENT_ID;
      const msClientSecret = env.MS_CLIENT_SECRET;
      const redirectUri = `${siteOrigin}/api/microsoftCallback`;
      if(!msClientId || !msClientSecret) return jsonResp({code:500,msg:"微软登录密钥配置缺失"},500);
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      if(!code || !state) return jsonResp({code:500,msg:"微软授权回调参数缺失"},500);
      const statePayload = await verifyOauthState(state,hmacSecret);
      if(!statePayload) return jsonResp({code:403,msg:"微软登录CSRF校验失败"},403);
      const flowType = statePayload.type;

      const tokenRes = await getMicrosoftToken(code,msClientId,msClientSecret,redirectUri);
      if(tokenRes.error || !tokenRes.access_token) return jsonResp({code:500,msg:"获取微软访问令牌失败"},500);
      const msUser = await getMicrosoftUserInfo(tokenRes.access_token);
      if(!msUser.id) return jsonResp({code:500,msg:"读取微软账号信息失败"},500);
      const msUid = msUser.id;
      const msName = msUser.displayName || `MS_${msUid.slice(-6)}`;

      let bindUser = await db.prepare(`SELECT id, username, role, is_cancel FROM users WHERE microsoft_id = ?`).bind(msUid).first();
      // 绑定流程
      if(flowType === "bind"){
        if (!loginUser) return Response.redirect(`${siteOrigin}/login.html`,302);
        if(bindUser) return jsonResp({code:500,msg:"该微软账号已绑定其他账号"});
        await db.prepare(`UPDATE users SET microsoft_id = ? WHERE id = ?`).bind(msUid,loginUser.uid).run();
        const newToken = await createSignedSessionToken(loginUser.uid, loginUser.username, loginUser.role, hmacSecret);
        return new Response(null,{ status:302, headers:{Location:`${siteOrigin}/account.html`,"Set-Cookie":buildSecureSessionCookie(newToken,86400)} });
      }
      // 登录流程
      if(flowType === "login"){
        if(bindUser){
          if(bindUser.is_cancel === 1 || bindUser.role === "banned") return jsonResp({code:500,msg:"账号已封禁或注销"});
          const sessionToken = await createSignedSessionToken(bindUser.id, bindUser.username, bindUser.role, hmacSecret);
          return new Response(null,{ status:302, headers:{Location:`${siteOrigin}/`,"Set-Cookie":buildSecureSessionCookie(sessionToken,86400)} });
        }
        let newUser;
        try{
          await db.prepare(`INSERT INTO users (username, password, role, is_cancel, microsoft_id) VALUES (?, ?, 'guest', 0, ?)`).bind(msName,"",msUid).run();
          newUser = await db.prepare(`SELECT id, username, role FROM users WHERE microsoft_id = ?`).bind(msUid).first();
        }catch(e){
          const fixName = `MS_${msUid.slice(-6)}`;
          await db.prepare(`INSERT INTO users (username, password, role, is_cancel, microsoft_id) VALUES (?, ?, 'guest', 0, ?)`).bind(fixName,"",msUid).run();
          newUser = await db.prepare(`SELECT id, username, role FROM users WHERE microsoft_id = ?`).bind(msUid).first();
        }
        const sessionToken = await createSignedSessionToken(newUser.id, newUser.username, newUser.role, hmacSecret);
        return new Response(null,{ status:302, headers:{Location:`${siteOrigin}/`,"Set-Cookie":buildSecureSessionCookie(sessionToken,86400)} });
      }
    }

    // 解绑微软账号
    if (action === "unbindMicrosoft" && reqMethod === "POST") {
      if (!loginUser) return jsonResp({ code: 99, msg: "请先登录" }, 401);
      await db.prepare(`UPDATE users SET microsoft_id = NULL WHERE id = ?`).bind(loginUser.uid).run();
      return jsonResp({ code: 0, msg: "微软账号解绑成功" });
    }

    // 解绑Github
    if (action === "unbindGithub" && reqMethod === "POST") {
      if (!loginUser) return jsonResp({ code: 99, msg: "请先登录" }, 401);
      const uid = loginUser.uid ?? null;
      await db.prepare(`UPDATE users SET github_id = NULL WHERE id = ?`).bind(uid).run();
      return jsonResp({ code: 0, msg: "GitHub账号解绑成功" });
    }

    // 退出登录
    if (action === 'logout' && reqMethod === 'POST') {
      return new Response(JSON.stringify({ code: 0, msg: '已退出登录' }), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': buildClearSessionCookie()
        }
      });
    }

    // 登录状态检测
    if (action === 'check') {
      if (!loginUser) return jsonResp({ login: false });
      const userInfo = await db.prepare(`SELECT role, is_cancel, github_id, microsoft_id FROM users WHERE id = ?`).bind(loginUser.uid ?? null).first();
      if (!userInfo || userInfo.role === "banned" || userInfo.is_cancel === 1) {
        return new Response(JSON.stringify({ login: false, banned: true }), {
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Set-Cookie': buildClearSessionCookie()
          }
        });
      }
      return jsonResp({
        login: true,
        uid: loginUser.uid,
        username: loginUser.username,
        role: userInfo.role,
        github_id: userInfo.github_id,
        microsoft_id: userInfo.microsoft_id
      });
    }

    // ========== 邮箱验证码发送接口 修复非法请求、JSON捕获、限流 ==========
    if (action === "sendEmailCode") {
      if(reqMethod === "GET") return jsonResp({code:0,msg:"接口运行正常，请POST提交请求"});
      if(reqMethod !== "POST") return jsonResp({ code: 405, msg: "非法请求方式" },405);

      // 捕获错误JSON入参，解决非法请求报错
      let body;
      try {
        body = await request.json();
      } catch (err) {
        return jsonResp({ code: 400, msg: "请求参数格式错误，非法请求" }, 400);
      }

      const {email} = body;
      if (!email || email.trim() === "") return jsonResp({ code: 400, msg: "邮箱地址不能为空" });

      // 清理过期缓存
      const nowTime = Date.now();
      for(const [key, item] of codeStorage.entries()){
        if(nowTime > item.expire) codeStorage.delete(key);
      }

      const limitKey = `${clientIp}_${email}`;
      const record = codeStorage.get(limitKey);
      if(record && nowTime - record.createTime < RATE_LIMIT){
        return jsonResp({ code: 429, msg: "操作过于频繁，请稍后再试" });
      }

      const code = generateSixCode();
      const resendKey = env.RESEND_API_KEY;
      if(!resendKey) return jsonResp({code:500,msg:"邮件服务密钥未配置"});

      // 发送邮件
      const mailRes = await sendMailByResend(email, code, resendKey);
      if(mailRes.error){
        return jsonResp({code:500,msg:"邮件发送失败",detail:mailRes.message});
      }

      // 存入内存缓存
      codeStorage.set(limitKey,{
        code: code,
        createTime: nowTime,
        expire: nowTime + CODE_EXPIRE
      });

      // 写入数据库验证码记录，注册接口校验使用
      await db.prepare(`INSERT INTO email_verifications (email, code, expires_at) VALUES (?, ?, ?)`)
      .bind(email, code, new Date(nowTime + CODE_EXPIRE)).run();

      return jsonResp({ code: 0, msg: "验证码已发送至邮箱，5分钟内有效" });
    }

    // 游客注册
    if (action === 'register' && reqMethod === 'POST') {
      const { username, password, email, code } = await request.json();
      if (!email || !code) return jsonResp({ code: 1, msg: '邮箱和验证码不能为空' });
      // 修复原代码换行空格SQL语法错误
      const verifyRecord = await db.prepare(`SELECT code, expires_at FROM email_verifications WHERE email = ? ORDER BY id DESC LIMIT 1`).bind(email).first();
      if (!verifyRecord) return jsonResp({ code: 1, msg: '请先获取验证码' });
      if (new Date(verifyRecord.expires_at).getTime() < Date.now()) return jsonResp({ code: 1, msg: '验证码已过期，请重新获取' });
      if(verifyRecord.code !== code) return jsonResp({code:1,msg:"验证码错误"});

      const hashPwd = await hashPassword(password);
      try {
        await db.prepare(`INSERT INTO users (username, password, role, is_cancel, github_id, email, microsoft_id) VALUES (?, ?, 'guest', 0, NULL, ?, NULL)`).bind(username, hashPwd, email).run();
        return jsonResp({ code: 0, msg: '注册成功，请登录' });
      } catch (e) {
        return jsonResp({ code: 1, msg: '用户名已存在' });
      }
    }

    // 账号密码登录【含旧密码自动升级新加密】
    if (action === 'login' && reqMethod === 'POST') {
      const { username, password } = await request.json();
      const row = await db.prepare(`SELECT id, username, role, is_cancel, password FROM users WHERE username = ?`).bind(username).first();
      if (!row) return jsonResp({ code: 1, msg: '账号或密码错误' });
      const pwdOk = await verifyPassword(password, row.password);
      if (!pwdOk) return jsonResp({ code: 1, msg: '账号或密码错误' });
      if (row.role === "banned") return jsonResp({ code: 2, msg: '账号已封禁，禁止登录' });
      if (row.is_cancel === 1) return jsonResp({ code: 3, msg: '账号已注销，无法登录' });

      // 登录成功，旧式SHA256密码自动升级为PBKDF2加盐格式
      if (!row.password.includes('$$')) {
        const newSecurePwd = await hashPassword(password);
        await db.prepare(`UPDATE users SET password = ? WHERE id = ?`).bind(newSecurePwd, row.id).run();
      }

      const sessionToken = await createSignedSessionToken(row.id, row.username, row.role, hmacSecret);
      return new Response(JSON.stringify({ code: 0, msg: '登录成功' }), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': buildSecureSessionCookie(sessionToken, 86400)
        }
      });
    }

    // 管理员修改角色权限
    if (action === 'setRole' && reqMethod === 'POST') {
      if (!loginUser) return jsonResp({ code: 99, msg: '无操作权限，仅管理员可用' }, 403);
      const { targetUid, newRole } = await request.json();
      const allowRoles = ['owner', 'admin', 'writer', 'guest', 'banned'];
      if (!allowRoles.includes(newRole)) return jsonResp({ code: 1, msg: '非法角色参数' });
      const targetUser = await db.prepare(`SELECT id, role FROM users WHERE id = ?`).bind(targetUid ?? null).first();
      if (!targetUser) return jsonResp({ code: 1, msg: '用户不存在' });

      if (loginUser.role === 'admin') {
        if (targetUser.role === 'owner') return jsonResp({ code: 98, msg: '无权修改所有者账号权限' }, 403);
        if (newRole === 'owner') return jsonResp({ code: 98, msg: '管理员不能授予所有者权限' }, 403);
      }

      await db.prepare(`UPDATE users SET role = ? WHERE id = ?`).bind(newRole, targetUid ?? null).run();
      return jsonResp({ code: 0, msg: '角色修改成功' });
    }

    // 用户列表
    if (action === 'userList' && reqMethod === 'GET') {
      if (!loginUser || loginUser.role === 'guest' || loginUser.role === 'banned') return jsonResp({ code: 99, msg: '无权访问' }, 403);
      const allUsers = await db.prepare(`SELECT id, username, role, is_cancel, created_at, github_id, microsoft_id FROM users ORDER BY id DESC`).all();
      return jsonResp({ list: allUsers.results });
    }

    // 删除用户
    if (action === 'deleteUser' && reqMethod === 'POST') {
      if (!loginUser || loginUser.role === 'guest' || loginUser.role === 'banned') return jsonResp({ code: 99, msg: '无权操作' }, 403);
      const { targetUid } = await request.json();
      if (Number(targetUid) === loginUser.uid) return jsonResp({ code: 1, msg: '不能删除当前登录账号' });
      const targetUser = await db.prepare(`SELECT role FROM users WHERE id = ?`).bind(targetUid ?? null).first();
      if (!targetUser) return jsonResp({ code: 1, msg: '用户不存在' });
      if (loginUser.role === 'admin' && targetUser.role === 'owner') return jsonResp({ code: 98, msg: '无法删除所有者账号' }, 403);
      await db.prepare(`DELETE FROM posts WHERE author = ?`).bind(targetUid ?? null).run();
      await db.prepare(`DELETE FROM users WHERE id = ?`).bind(targetUid ?? null).run();
      return jsonResp({ code: 0, msg: '用户已删除' });
    }

    // 管理员新建用户
    if (action === 'adminAddUser' && reqMethod === 'POST') {
      if (!loginUser || loginUser.role === 'guest' || loginUser.role === 'banned') return jsonResp({ code: 99, msg: '仅管理员可操作' }, 403);
      const { username, password, role } = await request.json();
      const allowRoles = ['admin', 'writer', 'guest', 'banned'];
      if (role === 'owner') return jsonResp({ code: 1, msg: '不能创建所有者账号' });
      if (!allowRoles.includes(role)) return jsonResp({ code: 1, msg: '非法角色' });
      const hashPwd = await hashPassword(password);
      try {
        await db.prepare(`INSERT INTO users (username, password, role, is_cancel, github_id, microsoft_id) VALUES (?, ?, ?, 0, NULL, NULL)`).bind(username, hashPwd, role).run();
        return jsonResp({ code: 0, msg: '账号创建成功' });
      } catch {
        return jsonResp({ code: 2, msg: '用户名已占用' });
      }
    }

    // 修改密码
    if (action === 'changePwd' && reqMethod === 'POST') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);
      const { oldPwd, newPwd } = await request.json();
      const userRow = await db.prepare(`SELECT password FROM users WHERE id = ?`).bind(loginUser.uid ?? null).first();
      if (!userRow || !(await verifyPassword(oldPwd, userRow.password))) return jsonResp({ code: 1, msg: '原密码错误' });
      const newHash = await hashPassword(newPwd);
      await db.prepare(`UPDATE users SET password = ? WHERE id = ?`).bind(newHash, loginUser.uid ?? null).run();
      return jsonResp({ code: 0, msg: '密码修改成功，请重新登录' });
    }

    // 账号注销
    if (action === 'cancelAccount' && reqMethod === 'POST') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);
      const { password } = await request.json();
      const userRow = await db.prepare(`SELECT password FROM users WHERE id = ?`).bind(loginUser.uid ?? null).first();
      if (!userRow || !(await verifyPassword(password, userRow.password))) return jsonResp({ code: 1, msg: '密码验证失败，无法注销' });
      await db.prepare(`UPDATE users SET is_cancel = 1, github_id = NULL, microsoft_id = NULL WHERE id = ?`).bind(loginUser.uid ?? null).run();
      return new Response(JSON.stringify({ code: 0, msg: '账号已注销' }), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': buildClearSessionCookie()
        }
      });
    }

    return jsonResp({ code: 99, msg: '非法请求' }, 405);
  } catch (globalErr) {
    return jsonResp({
      code: 500,
      msg: '服务器内部错误',
      err: globalErr.message
    }, 500);
  }
}
