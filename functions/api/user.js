// 加密工具
async function sha256(rawStr) {
  const encoder = new TextEncoder();
  const data = encoder.encode(rawStr);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// JWT标准Base64URL编解码
function base64UrlEncode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}
function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const arr = new Uint8Array([...bin].map(c => c.charCodeAt(0)));
  return arr.buffer;
}

// Cookie 修复 SameSite=None 解决OAuth跨域丢失登录态
function buildSecureSessionCookie(token, maxAge) {
  return `__Secure-blog_session=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${maxAge}`;
}
function buildClearSessionCookie() {
  return `__Secure-blog_session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0`;
}

// 统一JSON返回
function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-cache, no-store"
    }
  })
}

// 标准化302跳转，修复跳转失效停首页问题
function redirect(targetUrl) {
  return new Response(null, {
    status: 302,
    headers: {
      Location: targetUrl,
      "Cache-Control": "no-cache, no-store, must-revalidate"
    }
  })
}

// 校验会话，获取当前登录用户
async function getLoginUser(req, DB) {
  const cookieHeader = req.headers.get("Cookie") || "";
  const sessionMatch = cookieHeader.match(/__Secure-blog_session=([^;]+)/);
  if (!sessionMatch) return null;
  const sessionToken = sessionMatch[1];
  const userRow = await DB.prepare(`
    SELECT id as uid, username, email, github_id, microsoft_id
    FROM users WHERE session_token = ?
  `).bind(sessionToken).first();
  return userRow || null;
}

// 生成OAuth state（区分登录/绑定，带随机nonce、过期时间）
async function makeOauthState(type, siteOrigin) {
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const payload = {
    nonce: base64UrlEncode(nonce),
    ts: Date.now(),
    type: type,
    exp: Date.now() + 10 * 60 * 1000 // 10分钟过期
  };
  const payloadBuf = new TextEncoder().encode(JSON.stringify(payload));
  const state = base64UrlEncode(payloadBuf);
  return state;
}

// 主入口路由分发
export default {
  async fetch(request, env, ctx) {
    const req = new Request(request);
    const url = new URL(req.url);
    const path = url.pathname;
    const DB = env.DB;
    const siteOrigin = env.SITE_ORIGIN;

    // 跨域头通用配置
    const corsHeaders = {
      "Access-Control-Allow-Origin": siteOrigin,
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };
    if (req.method === "OPTIONS") return new Response("", { headers: corsHeaders });

    try {
      // ====================== 微软登录跳转接口 ======================
      if (path === "/api/microsoftLogin") {
        const state = await makeOauthState("login", siteOrigin);
        const authUrl = new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
        authUrl.searchParams.set("client_id", env.MS_CLIENT_ID);
        authUrl.searchParams.set("response_type", "code");
        authUrl.searchParams.set("redirect_uri", `${siteOrigin}/api/microsoftCallback`);
        authUrl.searchParams.set("scope", "openid profile email");
        authUrl.searchParams.set("state", state);
        return redirect(authUrl.toString());
      }

      // ====================== 微软绑定跳转接口 ======================
      if (path === "/api/microsoftBind") {
        const loginUser = await getLoginUser(req, DB);
        if (!loginUser) return redirect(`${siteOrigin}/login.html`);
        const state = await makeOauthState("bind", siteOrigin);
        const authUrl = new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
        authUrl.searchParams.set("client_id", env.MS_CLIENT_ID);
        authUrl.searchParams.set("response_type", "code");
        authUrl.searchParams.set("redirect_uri", `${siteOrigin}/api/microsoftCallback`);
        authUrl.searchParams.set("scope", "openid profile email");
        authUrl.searchParams.set("state", state);
        return redirect(authUrl.toString());
      }

      // ====================== 微软回调统一处理 ======================
      if (path === "/api/microsoftCallback") {
        const code = url.searchParams.get("code");
        const stateRaw = url.searchParams.get("state");
        if (!code || !stateRaw) return jsonResp({ code: 400, msg: "缺少授权参数" }, 400);

        // 解析state防篡改
        let statePay;
        try {
          const stateBuf = base64UrlDecode(stateRaw);
          statePay = JSON.parse(new TextDecoder().decode(stateBuf));
        } catch (e) {
          return jsonResp({ code: 400, msg: "非法授权状态" }, 400);
        }
        if (Date.now() > statePay.exp) return jsonResp({ code: 400, msg: "授权已过期" }, 400);

        // 换取微软token
        const tokenRes = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: env.MS_CLIENT_ID,
            client_secret: env.MS_CLIENT_SECRET,
            code,
            redirect_uri: `${siteOrigin}/api/microsoftCallback`,
            grant_type: "authorization_code"
          })
        });
        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) return jsonResp({ code: 400, msg: "微软授权失败" }, 400);

        // 获取微软用户信息
        const msRes = await fetch("https://graph.microsoft.com/v1.0/me", {
          headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const msUser = await msRes.json();
        const msUid = msUser.id;

        const loginUser = await getLoginUser(req, DB);

        // 分支1：绑定账号流程
        if (statePay.type === "bind") {
          console.log("微软绑定流程启动，当前登录用户：", loginUser?.uid);
          if (!loginUser) return redirect(`${siteOrigin}/login.html`);
          // 判断微软账号是否已被绑定
          const bindExist = await DB.prepare(`SELECT uid FROM users WHERE microsoft_id = ?`).bind(msUid).first();
          if (bindExist) return jsonResp({ code: 500, msg: "该微软账号已绑定其他账户" }, 500);
          // 更新数据库绑定微软ID
          const updateRes = await DB.prepare(`
            UPDATE users SET microsoft_id = ? WHERE id = ?
          `).bind(msUid, loginUser.uid).run();
          console.log("绑定数据库变更行数：", updateRes.changes);
          if (updateRes.changes > 0) {
            // 绑定成功强制跳转个人中心
            return redirect(`${siteOrigin}/account.html`);
          } else {
            return redirect(`${siteOrigin}/`);
          }
        }

        // 分支2：纯登录流程（已有绑定直接登录，无绑定跳转注册）
        if (statePay.type === "login") {
          const userRow = await DB.prepare(`
            SELECT id, username, session_token FROM users WHERE microsoft_id = ?
          `).bind(msUid).first();
          if (!userRow) return redirect(`${siteOrigin}/register.html`);
          // 生成新会话
          const sessionToken = await sha256(`${msUid}${Date.now()}${crypto.getRandomValues(new Uint8Array(8))}`);
          await DB.prepare(`UPDATE users SET session_token = ? WHERE id = ?`).bind(sessionToken, userRow.id).run();
          const cookie = buildSecureSessionCookie(sessionToken, 86400 * 7);
          const resp = redirect(`${siteOrigin}/index.html`);
          resp.headers.set("Set-Cookie", cookie);
          return resp;
        }
      }

      // ====================== GitHub 登录跳转 ======================
      if (path === "/api/githubLogin") {
        const state = await makeOauthState("login", siteOrigin);
        const ghUrl = new URL("https://github.com/login/oauth/authorize");
        ghUrl.searchParams.set("client_id", env.GH_CLIENT_ID);
        ghUrl.searchParams.set("redirect_uri", `${siteOrigin}/api/githubCallback`);
        ghUrl.searchParams.set("scope", "user:email");
        ghUrl.searchParams.set("state", state);
        return redirect(ghUrl.toString());
      }

      // ====================== GitHub 绑定跳转 ======================
      if (path === "/api/githubBind") {
        const loginUser = await getLoginUser(req, DB);
        if (!loginUser) return redirect(`${siteOrigin}/login.html`);
        const state = await makeOauthState("bind", siteOrigin);
        const ghUrl = new URL("https://github.com/login/oauth/authorize");
        ghUrl.searchParams.set("client_id", env.GH_CLIENT_ID);
        ghUrl.searchParams.set("redirect_uri", `${siteOrigin}/api/githubCallback`);
        ghUrl.searchParams.set("scope", "user:email");
        ghUrl.searchParams.set("state", state);
        return redirect(ghUrl.toString());
      }

      // ====================== GitHub 回调处理 ======================
      if (path === "/api/githubCallback") {
        const code = url.searchParams.get("code");
        const stateRaw = url.searchParams.get("state");
        if (!code || !stateRaw) return jsonResp({ code: 400, msg: "参数缺失" }, 400);
        let statePay;
        try {
          const stateBuf = base64UrlDecode(stateRaw);
          statePay = JSON.parse(new TextDecoder().decode(stateBuf));
        } catch (e) {
          return jsonResp({ code: 400, msg: "非法state" }, 400);
        }
        if (Date.now() > statePay.exp) return jsonResp({ code: 400, msg: "授权过期" }, 400);

        // 获取github access token
        const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
          body: new URLSearchParams({
            client_id: env.GH_CLIENT_ID,
            client_secret: env.GH_CLIENT_SECRET,
            code,
            redirect_uri: `${siteOrigin}/api/githubCallback`
          })
        });
        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) return jsonResp({ code: 400, msg: "GitHub授权失败" }, 400);

        // 获取github用户信息
        const userRes = await fetch("https://api.github.com/user", {
          headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const ghUser = await userRes.json();
        const ghUid = String(ghUser.id);
        const loginUser = await getLoginUser(req, DB);

        // 绑定分支
        if (statePay.type === "bind") {
          console.log("GitHub绑定流程启动，登录用户：", loginUser?.uid);
          if (!loginUser) return redirect(`${siteOrigin}/login.html`);
          const bindExist = await DB.prepare(`SELECT uid FROM users WHERE github_id = ?`).bind(ghUid).first();
          if (bindExist) return jsonResp({ code: 500, msg: "该GitHub账号已绑定其他账户" }, 500);
          const updateRes = await DB.prepare(`UPDATE users SET github_id = ? WHERE id = ?`).bind(ghUid, loginUser.uid).run();
          console.log("GitHub绑定变更行数：", updateRes.changes);
          if (updateRes.changes > 0) {
            return redirect(`${siteOrigin}/account.html`);
          } else {
            return redirect(`${siteOrigin}/`);
          }
        }

        // 登录分支
        if (statePay.type === "login") {
          const userRow = await DB.prepare(`SELECT id, username FROM users WHERE github_id = ?`).bind(ghUid).first();
          if (!userRow) return redirect(`${siteOrigin}/register.html`);
          const sessionToken = await sha256(`${ghUid}${Date.now()}${crypto.getRandomValues(new Uint8Array(8))}`);
          await DB.prepare(`UPDATE users SET session_token = ? WHERE id = ?`).bind(sessionToken, userRow.id).run();
          const cookie = buildSecureSessionCookie(sessionToken, 86400 * 7);
          const resp = redirect(`${siteOrigin}/index.html`);
          resp.headers.set("Set-Cookie", cookie);
          return resp;
        }
      }

      // ====================== 忘记密码接口（安全加固版） ======================
      if (path === "/api/forgetPassword" && req.method === "POST") {
        const body = await req.json();
        const { email } = body;
        if (!email) return jsonResp({ code: 400, msg: "邮箱不能为空" }, 400);
        const user = await DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
        if (!user) return jsonResp({ code: 404, msg: "该邮箱未注册" }, 404);
        // 生成一次性重置令牌带随机nonce
        const nonceBuf = crypto.getRandomValues(new Uint8Array(32));
        const resetToken = base64UrlEncode(nonceBuf);
        const expire = Date.now() + 30 * 60 * 1000;
        // 存入验证码表区分重置密码action
        await DB.prepare(`
          INSERT INTO email_verifications (uid, code, action, expire_at)
          VALUES (?, ?, 'reset_pwd', ?)
          ON CONFLICT(uid,action) DO UPDATE SET code=?,expire_at=?
        `).bind(user.id, resetToken, expire, resetToken, expire).run();
        // Resend发重置邮件，发件人notify@blog.lizhuoxuan.dpdns.org
        const sendRes = await fetch("https://api.resend.dev/v1/emails", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.RESEND_API_KEY}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            from: "notify@blog.lizhuoxuan.dpdns.org",
            to: email,
            subject: "博客密码重置链接",
            html: `<p>重置链接：${siteOrigin}/reset.html?token=${resetToken}</p><p>30分钟内有效</p>`
          })
        });
        const sendData = await sendRes.json();
        if (sendData.error) return jsonResp({ code: 500, msg: "邮件发送失败" }, 500);
        return jsonResp({ code: 200, msg: "重置邮件已发送，请查收" });
      }

      // ====================== 验证码获取接口修复非法请求 ======================
      if (path === "/api/sendCode" && req.method === "POST") {
        const body = await req.json();
        const { email } = body;
        if (!/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(email)) {
          return jsonResp({ code: 400, msg: "邮箱格式非法" }, 400);
        }
        // 限流：1分钟内仅允许一次
        const recent = await DB.prepare(`
          SELECT id FROM email_verifications WHERE email = ? AND expire_at > ? AND action='register'
        `).bind(email, Date.now()).first();
        if (recent) return jsonResp({ code: 429, msg: "发送过于频繁，请稍后再试" }, 429);
        // 6位数字验证码
        const code = String(Math.floor(100000 + Math.random() * 900000));
        const expire = Date.now() + 10 * 60 * 1000;
        await DB.prepare(`
          INSERT INTO email_verifications (email, code, action, expire_at)
          VALUES (?, ?, 'register', ?)
          ON CONFLICT(email,action) DO UPDATE SET code=?,expire_at=?
        `).bind(email, code, expire, code, expire).run();
        // 发送验证码邮件
        await fetch("https://api.resend.dev/v1/emails", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.RESEND_API_KEY}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            from: "notify@blog.lizhuoxuan.dpdns.org",
            to: email,
            subject: "博客注册验证码",
            html: `<p>你的注册验证码：<b>${code}</b>，10分钟有效</p>`
          })
        });
        return jsonResp({ code: 200, msg: "验证码已发送" });
      }

      // 兜底404
      return jsonResp({ code: 404, msg: "接口不存在" }, 404);

    } catch (err) {
      console.error("服务端异常：", err);
      return jsonResp({ code: 500, msg: "服务器内部错误" }, 500);
    }
  }
}