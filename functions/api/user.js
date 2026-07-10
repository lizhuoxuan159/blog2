import { createHmac } from "node:crypto";

// ===================== 全局安全工具（内置防注入、防彩虹表核心） =====================
/**
 * 统一响应封装
 */
/**
 * 校验当前登录者是否为管理员(admin / owner)
 * @param {Request} request
 * @param {string} secret
 * @param {D1Database} db
 * @returns {number|null} 管理员uid，非管理员返回null
 */
async function getAdminUid(request, secret, db) {
    const sid = getSessionCookie(request);
    const loginUid = verifySessionToken(sid, secret);
    if (!loginUid) return null;
    const user = await db.prepare(`SELECT role FROM users WHERE id = ?`).bind(loginUid).first();
    if (!user) return null;
    if (user.role === "admin" || user.role === "owner") {
        return loginUid;
    }
    return null;
}

/**
 * 管理员新建用户
 */
async function adminCreateUser(db, username, password, role, secret) {
    const exist = await db.prepare(`SELECT id FROM users WHERE username = ?`).bind(username).first();
    if (exist) return { ok: false, msg: "该用户名已存在" };
    const safePwd = secureHashPassword(password, secret);
    await db.prepare(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`).bind(username, safePwd, role).run();
    return { ok: true, msg: "创建用户成功" };
}

/**
 * 修改用户角色
 */
async function setUserRole(db, operatorUid, targetUid, newRole) {
    // 获取操作者和目标用户信息
    const opUser = await db.prepare(`SELECT role FROM users WHERE id = ?`).bind(operatorUid).first();
    const targetUser = await db.prepare(`SELECT role FROM users WHERE id = ?`).bind(targetUid).first();
    if (!targetUser) return { ok: false, msg: "用户不存在" };
    // admin 不能修改 owner 和其他 admin
    if (opUser.role === "admin") {
        if (targetUser.role === "owner" || targetUser.role === "admin") {
            return { ok: false, msg: "管理员无权修改 owner / 其他管理员" };
        }
        if (newRole === "owner" || newRole === "admin") {
            return { ok: false, msg: "管理员不能设置 owner / admin 角色" };
        }
    }
    await db.prepare(`UPDATE users SET role = ? WHERE id = ?`).bind(newRole, targetUid).run();
    return { ok: true, msg: "角色修改成功" };
}

/**
 * 删除用户（仅owner可删除admin，admin不能删admin和owner）
 */
async function deleteOneUser(db, operatorUid, targetUid) {
    const opUser = await db.prepare(`SELECT role FROM users WHERE id = ?`).bind(operatorUid).first();
    const targetUser = await db.prepare(`SELECT role FROM users WHERE id = ?`).bind(targetUid).first();
    if (!targetUser) return { ok: false, msg: "用户不存在" };
    if (opUser.role === "admin") {
        if (targetUser.role === "admin" || targetUser.role === "owner") {
            return { ok: false, msg: "管理员不能删除管理员和站主" };
        }
    }
    // 只删除用户记录，文章保留，前端展示账户已注销
    await db.prepare(`UPDATE posts SET author_id = NULL WHERE author_id = ?`).bind(targetUid).run();
    await db.prepare(`UPDATE comments SET user_id = NULL WHERE user_id = ?`).bind(targetUid).run();
    await db.prepare(`DELETE FROM users WHERE id = ?`).bind(targetUid).run();
    return { ok: true, msg: "删除成功" };
}

const success = (data = null, msg = "操作成功", extraHeaders = {}) => {
  return new Response(JSON.stringify({ code: 0, msg, data }), {
    status: 200,
    headers: { "Content-Type": "application/json;charset=utf-8", ...extraHeaders }
  })
}
const fail = (msg = "操作失败", code = 400) => {
  return new Response(JSON.stringify({ code, msg, data: null }), {
    status: code,
    headers: { "Content-Type": "application/json;charset=utf-8" }
  })
}

/**
 * 【防彩虹表核心】HMAC-SHA256加盐哈希
 * 不是单纯SHA256，使用独立密钥做盐，彩虹表预计算全部失效
 * raw：原始明文密码
 * secret：环境变量SESSION_HMAC_SECRET（随机长字符串，不泄露）
 */
const secureHashPassword = (raw, secret) => {
  return createHmac("sha256", secret)
    .update(raw.trim())
    .digest("hex");
}

/**
 * 会话Cookie HMAC签名，防篡改、伪造登录凭证
 */
const signSessionToken = (uid, secret) => {
  const payload = String(uid);
  const signature = createHmac("sha256", secret).update(payload).digest("hex");
  return `${payload}.${signature}`;
}
const verifySessionToken = (token, secret) => {
  const [uid, sig] = token.split(".");
  if (!uid || !sig) return null;
  const realSig = createHmac("sha256", secret).update(uid).digest("hex");
  return sig === realSig ? Number(uid) : null;
}

/**
 * Cookie 工具：7天有效期，HttpOnly+Secure+SameSite，前端JS无法读取，防XSS窃取
 */
const getSessionCookie = (req) => {
  const cookieRaw = req.headers.get("cookie") || "";
  const cookieMap = Object.fromEntries(cookieRaw.split("; ").map(item => item.split("=")));
  return cookieMap.sid || null;
}
const set7DayLoginCookie = (token) => {
  return {
    "Set-Cookie": `sid=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800`
  }
}
const clearLoginCookie = () => {
  return {
    "Set-Cookie": `sid=; Path=/; HttpOnly; Max-Age=0`
  }
}

/**
 * 用户状态校验：注销/封禁拦截
 */
const checkUserBlockStatus = (user) => {
  if (!user) return "账户不存在";
  if (user.is_cancel === 1) return "该账户已注销，禁止登录";
  if (user.ban_until) {
    const now = new Date();
    const banDeadline = new Date(user.ban_until);
    if (banDeadline > now) return `账户封禁至 ${user.ban_until}，暂时无法登录`;
  }
  return null;
}

// ===================== 主接口入口 =====================
export default {
  async fetch(request, env) {
    const db = env.DB;
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const HMAC_SALT = env.SESSION_HMAC_SECRET;
    const SITE_URL = env.SITE_ORIGIN;

    // 1. 邮箱注册 POST /api/user/register
    if (path === "/api/user/register" && method === "POST") {
      const { email, username, password, code } = await request.json();
      // 【防注入】全部参数使用?占位符，无拼接
      const validCode = await db.prepare(`
        SELECT id FROM email_verifications 
        WHERE email = ? AND type = 'register' AND code = ? AND expire_at > CURRENT_TIMESTAMP
      `).bind(email, code).first();
      if (!validCode) return fail("验证码错误或已过期");

      // 校验用户名/邮箱唯一性
      const existUser = await db.prepare(`
        SELECT id FROM users WHERE username = ? OR email = ?
      `).bind(username, email).first();
      if (existUser) return fail("用户名或邮箱已被注册");

      // 加盐哈希密码入库，抵御彩虹表
      const safePwd = secureHashPassword(password, HMAC_SALT);
      await db.prepare(`
        INSERT INTO users (username, password, email) VALUES (?, ?, ?)
      `).bind(username, safePwd, email).run();
      // 销毁已使用验证码
      await db.prepare("DELETE FROM email_verifications WHERE id = ?").bind(validCode.id).run();
      return success(null, "注册完成，请登录");
    }

    // 2. 账号密码登录 POST /api/user/login
    if (path === "/api/user/login" && method === "POST") {
      const { username, password } = await request.json();
      const user = await db.prepare(`
        SELECT * FROM users WHERE username = ?
      `).bind(username).first();
      if (!user) return fail("用户名不存在");

      // 拦截封禁/注销账户
      const blockMsg = checkUserBlockStatus(user);
      if (blockMsg) return fail(blockMsg, 403);

      // 加盐比对密码，防彩虹表破解
      const inputHash = secureHashPassword(password, HMAC_SALT);
      if (inputHash !== user.password) return fail("用户名或密码错误");

      // 生成安全会话Cookie
      const sessionToken = signSessionToken(user.id, HMAC_SALT);
      return success(
        { uid: user.id, username: user.username, role: user.role },
        "登录成功",
        set7DayLoginCookie(sessionToken)
      );
    }

    // 3. 发送邮箱验证码 POST /api/user/send-code
    if (path === "/api/user/send-code" && method === "POST") {
      const { email, type } = await request.json();
      if (!["register", "resetpwd"].includes(type)) return fail("非法操作类型");
      // 6位数字验证码
      const verifyCode = String(Math.floor(100000 + Math.random() * 900000));
      // 15分钟过期
      const expireTime = new Date(Date.now() + 15 * 60 * 1000).toISOString();

      // 清除该邮箱旧验证码
      await db.prepare(`
        DELETE FROM email_verifications WHERE email = ? AND type = ?
      `).bind(email, type).run();
      // 插入新验证码
      await db.prepare(`
        INSERT INTO email_verifications (email, code, type, expire_at) VALUES (?, ?, ?, ?)
      `).bind(email, verifyCode, type, expireTime).run();

      // Resend发送邮件
      const mailResp = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.RESEND_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          from: `${env.MAIL_FROM_NAME} <${env.MAIL_FROM_EMAIL}>`,
          to: email,
          subject: type === "register" ? "账户注册验证码" : "重置密码验证码",
          text: `你的验证码：${verifyCode}，15分钟内有效，请勿泄露给他人`
        })
      });
      if (!mailResp.ok) return fail("邮件发送失败，请稍后重试");
      return success(null, "验证码已发送至邮箱");
    }

    // 4. 找回密码重置 POST /api/user/reset-pwd
    if (path === "/api/user/reset-pwd" && method === "POST") {
      const { email, code, newPwd } = await request.json();
      const validCode = await db.prepare(`
        SELECT id FROM email_verifications 
        WHERE email = ? AND type = 'resetpwd' AND code = ? AND expire_at > CURRENT_TIMESTAMP
      `).bind(email, code).first();
      if (!validCode) return fail("验证码无效或已过期");

      // 新密码加盐哈希
      const newSafeHash = secureHashPassword(newPwd, HMAC_SALT);
      await db.prepare(`
        UPDATE users SET password = ? WHERE email = ?
      `).bind(newSafeHash, email).run();
      await db.prepare("DELETE FROM email_verifications WHERE id = ?").bind(validCode.id).run();
      return success(null, "密码重置成功，请使用新密码登录");
    }

    // 5. 登出 GET /api/user/logout
    if (path === "/api/user/logout" && method === "GET") {
      return success(null, "已安全退出登录", clearLoginCookie());
    }

    // 6. 永久注销账户 POST /api/user/cancel
    if (path === "/api/user/cancel" && method === "POST") {
      const sid = getSessionCookie(request);
      const loginUid = verifySessionToken(sid, HMAC_SALT);
      if (!loginUid) return fail("请先登录", 401);
      // 标记注销，不再允许登录
      await db.prepare("UPDATE users SET is_cancel = 1 WHERE id = ?").bind(loginUid).run();
      return success(null, "账户已注销", clearLoginCookie());
    }

    // ========== GitHub OAuth 第三方登录 ==========
    // 跳转授权页 GET /api/user/github
    if (path === "/api/user/github" && method === "GET") {
      const authUrl = new URL("https://github.com/login/oauth/authorize");
      authUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
      authUrl.searchParams.set("redirect_uri", `${SITE_URL}/api/user/github/callback`);
      authUrl.searchParams.set("scope", "user:email");
      return new Response("", {
        status: 302,
        headers: { Location: authUrl.toString() }
      })
    }
    // GitHub授权回调 GET /api/user/github/callback
    if (path === "/api/user/github/callback" && method === "GET") {
      const code = url.searchParams.get("code");
      if (!code) return fail("第三方授权中断");
      // 交换access_token
      const tokenResp = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "Blog-Safe-Auth/1.0"
        },
        body: new URLSearchParams({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          redirect_uri: `${SITE_URL}/api/user/github/callback`,
          code
        })
      });
      const tokenText = await tokenResp.text();
      const tokenData = Object.fromEntries(tokenText.split("&").map(i => i.split("=")));
      const accessToken = tokenData.access_token;
      if (!accessToken) return fail("获取登录凭证失败");

      // 获取GitHub用户信息
      const ghUserResp = await fetch("https://api.github.com/user", {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "User-Agent": "Blog-Safe-Auth/1.0"
        }
      });
      const ghUser = await ghUserResp.json();
      const githubId = String(ghUser.id);
      const ghEmail = ghUser.email || null;

      // 查询绑定用户
      let loginUser = await db.prepare(`
        SELECT * FROM users WHERE github_id = ?
      `).bind(githubId).first();
      // 无绑定则自动创建账号
      if (!loginUser) {
        await db.prepare(`
          INSERT INTO users (username, github_id, email) VALUES (?, ?, ?)
        `).bind(ghUser.login, githubId, ghEmail).run();
        loginUser = await db.prepare("SELECT * FROM users WHERE github_id = ?").bind(githubId).first();
      }

      // 校验封禁注销
      const blockMsg = checkUserBlockStatus(loginUser);
      if (blockMsg) return fail(blockMsg, 403);

      // 下发7天登录Cookie，跳转首页
      const sessionToken = signSessionToken(loginUser.id, HMAC_SALT);
      return new Response("", {
        status: 302,
        headers: {
          Location: SITE_URL,
          ...set7DayLoginCookie(sessionToken)
        }
      })
    }

    // ========== Microsoft Entra 微软登录 ==========
    // 跳转授权 GET /api/user/microsoft
    if (path === "/api/user/microsoft" && method === "GET") {
      const authUrl = new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
      authUrl.searchParams.set("client_id", env.MS_CLIENT_ID);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("redirect_uri", `${SITE_URL}/api/user/microsoft/callback`);
      authUrl.searchParams.set("scope", "openid email profile");
      authUrl.searchParams.set("response_mode", "query");
      return new Response("", {
        status: 302,
        headers: { Location: authUrl.toString() }
      })
    }
    // 微软授权回调 GET /api/user/microsoft/callback
    if (path === "/api/user/microsoft/callback" && method === "GET") {
      const code = url.searchParams.get("code");
      if (!code) return fail("微软授权失败");
      // 交换token
      const tokenResp = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: env.MS_CLIENT_ID,
          client_secret: env.MS_CLIENT_SECRET,
          redirect_uri: `${SITE_URL}/api/user/microsoft/callback`,
          grant_type: "authorization_code",
          code
        })
      });
      const tokenData = await tokenResp.json();
      const accessToken = tokenData.access_token;
      if (!accessToken) return fail("获取微软登录凭证失败");

      // 获取微软用户信息
      const msUserResp = await fetch("https://graph.microsoft.com/v1.0/me", {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const msUser = await msUserResp.json();
      const microsoftId = msUser.id;
      const msEmail = msUser.mail || msUser.userPrincipalName;
      const displayName = msUser.displayName || `ms_${microsoftId.slice(0, 8)}`;

      // 查询绑定账号
      let loginUser = await db.prepare(`
        SELECT * FROM users WHERE microsoft_id = ?
      `).bind(microsoftId).first();
      if (!loginUser) {
        await db.prepare(`
          INSERT INTO users (username, microsoft_id, email) VALUES (?, ?, ?)
        `).bind(displayName, microsoftId, msEmail).run();
        loginUser = await db.prepare("SELECT * FROM users WHERE microsoft_id = ?").bind(microsoftId).first();
      }

      const blockMsg = checkUserBlockStatus(loginUser);
      if (blockMsg) return fail(blockMsg, 403);

      const sessionToken = signSessionToken(loginUser.id, HMAC_SALT);
      return new Response("", {
        status: 302,
        headers: {
          Location: SITE_URL,
          ...set7DayLoginCookie(sessionToken)
        }
      })
    }

    // ========== 管理员接口：封禁用户 POST /api/user/admin/ban (需登录管理员) ==========
    if (path === "/api/user/admin/ban" && method === "POST") {
      // 校验管理员登录权限
      const sid = getSessionCookie(request);
      const adminUid = verifySessionToken(sid, HMAC_SALT);
      if (!adminUid) return fail("未登录管理员账号", 401);
      const adminUser = await db.prepare("SELECT role FROM users WHERE id = ?").bind(adminUid).first();
      if (!adminUser || (adminUser.role !== "admin" && adminUser.role !== "owner")) {
        return fail("无管理员操作权限", 403);
      }

      const { targetUid, banDays } = await request.json();
      // 计算封禁到期时间
      const banTime = new Date(Date.now() + banDays * 24 * 60 * 60 * 1000).toISOString();
      await db.prepare(`
        UPDATE users SET ban_until = ? WHERE id = ?
      `).bind(banTime, targetUid).run();
      return success(null, `已封禁用户${banDays}天`);
    }
        // ========== 1.管理员新建用户 POST /api/user/admin/addUser ==========
        if (path === "/api/user/admin/addUser" && method === "POST") {
            const adminUid = await getAdminUid(request, HMAC_SALT, db);
            if (!adminUid) return fail("无管理员权限", 403);
            const { username, password, role } = await request.json();
            const res = await adminCreateUser(db, username, password, role, HMAC_SALT);
            if (!res.ok) return fail(res.msg);
            return success(null, res.msg);
        }

        // ========== 2.修改用户角色 POST /api/user/admin/setRole ==========
        if (path === "/api/user/admin/setRole" && method === "POST") {
            const adminUid = await getAdminUid(request, HMAC_SALT, db);
            if (!adminUid) return fail("无管理员权限", 403);
            const { targetUid, newRole } = await request.json();
            const res = await setUserRole(db, adminUid, targetUid, newRole);
            if (!res.ok) return fail(res.msg);
            return success(null, res.msg);
        }

        // ========== 3.删除用户 POST /api/user/admin/deleteUser ==========
        if (path === "/api/user/admin/deleteUser" && method === "POST") {
            const adminUid = await getAdminUid(request, HMAC_SALT, db);
            if (!adminUid) return fail("无管理员权限", 403);
            const { targetUid } = await request.json();
            const res = await deleteOneUser(db, adminUid, targetUid);
            if (!res.ok) return fail(res.msg);
            return success(null, res.msg);
        }

        // ========== 4.简易获取当前登录用户信息（替代原来的 /api/user?action=check）GET /api/user/check ==========
        if (path === "/api/user/check" && method === "GET") {
            const sid = getSessionCookie(request);
            const loginUid = verifySessionToken(sid, HMAC_SALT);
            if (!loginUid) {
                return success({ login: false });
            }
            const user = await db.prepare(`SELECT id, username, role FROM users WHERE id = ?`).bind(loginUid).first();
            return success({
                login: true,
                uid: user.id,
                username: user.username,
                role: user.role
            });
        }

    // ========== 管理员接口：查询全部用户 GET /api/user/admin/list ==========
    if (path === "/api/user/admin/list" && method === "GET") {
      const sid = getSessionCookie(request);
      const adminUid = verifySessionToken(sid, HMAC_SALT);
      if (!adminUid) return fail("未登录管理员账号", 401);
      const adminUser = await db.prepare("SELECT role FROM users WHERE id = ?").bind(adminUid).first();
      if (!adminUser || (adminUser.role !== "admin" && adminUser.role !== "owner")) {
        return fail("无管理员操作权限", 403);
      }
      // 不返回密码哈希，保护数据
      const { results } = await db.prepare(`
        SELECT id, username, email, github_id, microsoft_id, role, created_at, is_cancel, ban_until 
        FROM users ORDER BY id DESC
      `).all();
      return success(results, "用户列表查询成功");
    }
        // ========== 用户修改自身密码 POST /api/user/change-pwd ==========
        if (path === "/api/user/change-pwd" && method === "POST") {
            const adminUid = await getAdminUid(request, HMAC_SALT, db);
            // 普通登录用户也能进入，getAdminUid仅判断管理员，这里单独取登录uid
            const sid = getSessionCookie(request);
            const loginUid = await verifySessionToken(sid, HMAC_SALT);
            if (!loginUid) return fail("请先登录", 401);

            const { oldPwd, newPwd } = await request.json();
            if (!oldPwd || !newPwd) return fail("原密码和新密码不能为空");

            // 查询当前账号原始密码
            const userRow = await db.prepare(`SELECT password FROM users WHERE id = ?`).bind(loginUid).first();
            const oldHash = secureHashPassword(oldPwd, HMAC_SALT);
            if (oldHash !== user.password) return fail("原密码错误");

            // 生成新密码哈希并更新
            const newHash = secureHashPassword(newPwd, HMAC_SALT);
            await db.prepare(`UPDATE users SET password = ? WHERE id = ?`).bind(newHash, loginUid).run();

            return success(null, "密码修改成功，请重新登录");
        }

    return fail("接口不存在", 404);
  }
}
