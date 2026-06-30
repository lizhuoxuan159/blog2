// user.js
async function sha256(rawStr) {
  const encoder = new TextEncoder();
  const data = encoder.encode(rawStr);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function createSessionToken(uid, username, role) {
  const payload = {
    uid,
    username,
    role,
    exp: Date.now() + 604800000
  };
  return btoa(JSON.stringify(payload));
}

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

async function getLoginUser(request) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/blog_session=([^;]+)/);
  if (!match) return null;
  try {
    const payload = JSON.parse(atob(match[1]));
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

// 直连GitHub获取access_token，无代理
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

// 直连GitHub用户信息接口，强状态码校验
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

export async function onRequest({ request, env }) {
  try {
    const db = env.DB;
    const url = new URL(request.url);
    const action = url.searchParams.get('action');
    const loginUser = await getLoginUser(request);

    // GitHub登录跳转（纯原生github授权地址，无镜像）
    if (action === "githubAuth") {
      const clientId = env.GITHUB_CLIENT_ID;
      const siteOrigin = env.SITE_ORIGIN;
      if (!clientId || !siteOrigin) {
        return jsonResp({ code: 500, msg: "GitHub登录配置缺失" }, 500);
      }
      const redirectUri = `${siteOrigin}/api/user?action=githubCallback`;
      const githubAuthUrl = new URL("https://github.com/login/oauth/authorize");
      githubAuthUrl.searchParams.set("client_id", clientId);
      githubAuthUrl.searchParams.set("redirect_uri", redirectUri);
      githubAuthUrl.searchParams.set("scope", "read:user");
      return Response.redirect(githubAuthUrl.toString(), 302);
    }

    // GitHub授权回调核心逻辑
    if (action === "githubCallback") {
      const clientId = env.GITHUB_CLIENT_ID;
      const clientSecret = env.GITHUB_CLIENT_SECRET;
      const siteOrigin = env.SITE_ORIGIN;

      if (!clientId || !clientSecret || !siteOrigin) {
        return jsonResp({ code: 500, msg: "GitHub OAuth环境变量未完整配置" }, 500);
      }

      const code = url.searchParams.get("code");
      if (!code) {
        return jsonResp({ code: 500, msg: "授权回调缺少code参数，请重新操作" }, 500);
      }

      const redirectUri = `${siteOrigin}/api/user?action=githubCallback`;
      const tokenData = await getGithubToken(code, clientId, clientSecret, redirectUri);

      if (tokenData.error || !tokenData.access_token) {
        return jsonResp({
          code: 500,
          msg: tokenData.msg || "无法获取GitHub授权令牌",
          detail: tokenData.detail || ""
        }, 500);
      }

      const userInfo = await getGithubUserInfo(tokenData.access_token);
      // 强拦截：数据缺失直接返回，绝不进入SQL逻辑
      if (
        userInfo.error
        || typeof userInfo.id === "undefined"
        || !userInfo.id
        || !userInfo.login
      ) {
        return jsonResp({
          code: 500,
          msg: "获取GitHub账号信息不完整，授权中断",
          detail: userInfo.detail || ""
        }, 500);
      }

      // 强制兜底，防止undefined
      const githubId = String(userInfo.id);
      const githubName = userInfo.login;
      const safeGithubId = githubId ?? null;

      let bindUser = await db.prepare(`
        SELECT id, username, role, is_cancel FROM users WHERE github_id = ?
      `).bind(safeGithubId).first();

      // 场景1：已登录账号，绑定GitHub
      if (loginUser) {
        if (bindUser) {
          return jsonResp({ code: 500, msg: "该GitHub账号已绑定其他网站账号，无法重复绑定" }, 500);
        }
        await db.prepare(`UPDATE users SET github_id = ? WHERE id = ?`)
          .bind(safeGithubId, loginUser.id ?? null)
          .run();
        const newToken = createSessionToken(loginUser.id, loginUser.username, loginUser.role);
        return new Response(null, {
          status: 302,
          headers: {
            Location: `${siteOrigin}/account.html`,
            "Set-Cookie": `blog_session=${newToken}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`
          }
        });
      }

      // 场景2：未登录，GitHub快捷登录
      if (bindUser) {
        if (bindUser.is_cancel === 1 || bindUser.role === "banned") {
          return jsonResp({ code: 500, msg: "该绑定账号已注销或封禁，禁止登录" }, 500);
        }
        const sessionToken = createSessionToken(bindUser.id, bindUser.username, bindUser.role);
        return new Response(null, {
          status: 302,
          headers: {
            Location: `${siteOrigin}/`,
            "Set-Cookie": `blog_session=${sessionToken}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`
          }
        });
      } else {
        // 自动新建账号，github_id兜底null
        let newUser;
        try {
          await db.prepare(`
            INSERT INTO users (username, password, role, is_cancel, github_id)
            VALUES (?, ?, 'guest', 0, ?)
          `).bind(githubName, "", safeGithubId).run();
          newUser = await db.prepare(`
            SELECT id, username, role FROM users WHERE github_id = ?
          `).bind(safeGithubId).first();
        } catch (e) {
          const fixName = `${githubName}_${githubId.slice(-4)}`;
          await db.prepare(`
            INSERT INTO users (username, password, role, is_cancel, github_id)
            VALUES (?, ?, 'guest', 0, ?)
          `).bind(fixName, "", safeGithubId).run();
          newUser = await db.prepare(`
            SELECT id, username, role FROM users WHERE github_id = ?
          `).bind(safeGithubId).first();
        }
        const sessionToken = createSessionToken(newUser.id, newUser.username, newUser.role);
        return new Response(null, {
          status: 302,
          headers: {
            Location: `${siteOrigin}/`,
            "Set-Cookie": `blog_session=${sessionToken}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`
          }
        });
      }
    }

    // 解绑GitHub账号接口（前端account.html调用）
    if (action === "unbindGithub" && request.method === "POST") {
      if (!loginUser) {
        return jsonResp({ code: 99, msg: "请先登录" }, 401);
      }
      const uid = loginUser.id ?? null;
      await db.prepare(`UPDATE users SET github_id = NULL WHERE id = ?`)
        .bind(uid)
        .run();
      return jsonResp({ code: 0, msg: "GitHub账号解绑成功" });
    }

    // 退出登录
    if (action === 'logout' && request.method === 'POST') {
      return new Response(JSON.stringify({ code: 0, msg: '已退出登录' }), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': 'blog_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'
        }
      });
    }

    // 登录校验：返回github_id供前端渲染绑定状态
    if (action === 'check' && request.method === 'GET') {
      if (!loginUser) return jsonResp({ login: false });
      const userInfo = await db.prepare(`
        SELECT role, is_cancel, github_id FROM users WHERE id = ?
      `).bind(loginUser.uid ?? null).first();
      if (!userInfo || userInfo.role === "banned" || userInfo.is_cancel === 1) {
        return new Response(JSON.stringify({ login: false, banned: true }), {
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Set-Cookie': 'blog_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'
          }
        });
      }
      return jsonResp({
        login: true,
        uid: loginUser.uid,
        username: loginUser.username,
        role: userInfo.role,
        github_id: userInfo.github_id
      });
    }

    // 游客注册
    if (action === 'register' && request.method === 'POST') {
      const { username, password } = await request.json();
      const hashPwd = await sha256(password);
      try {
        await db.prepare(`
          INSERT INTO users (username, password, role, is_cancel, github_id)
          VALUES (?, ?, 'guest', 0, NULL)
        `).bind(username, hashPwd).run();
        return jsonResp({ code: 0, msg: '注册成功，请登录' });
      } catch (e) {
        return jsonResp({ code: 1, msg: '用户名已存在' });
      }
    }

    // 账号密码登录
    if (action === 'login' && request.method === 'POST') {
      const { username, password } = await request.json();
      const hashPwd = await sha256(password);
      const row = await db.prepare(`
        SELECT id, username, role, is_cancel FROM users WHERE username = ? AND password = ?
      `).bind(username, hashPwd).first();

      if (!row) return jsonResp({ code: 1, msg: '账号或密码错误' });
      if (row.role === "banned") return jsonResp({ code: 2, msg: '账号已封禁，禁止登录' });
      if (row.is_cancel === 1) return jsonResp({ code: 3, msg: '账号已注销，无法登录' });

      const sessionToken = createSessionToken(row.id, row.username, row.role);
      return new Response(JSON.stringify({ code: 0, msg: '登录成功' }), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': `blog_session=${sessionToken}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`
        }
      });
    }

    // 管理员修改角色
    if (action === 'setRole' && request.method === 'POST') {
      if (!loginUser) return jsonResp({ code: 99, msg: '无操作权限，仅管理员可用' }, 403);
      const { targetUid, newRole } = await request.json();
      const allowRoles = ['owner', 'admin', 'writer', 'guest', 'banned'];
      if (!allowRoles.includes(newRole)) {
        return jsonResp({ code: 1, msg: '非法角色参数' });
      }
      const targetUser = await db.prepare(`
        SELECT id, role FROM users WHERE id = ?
      `).bind(targetUid ?? null).first();
      if (!targetUser) return jsonResp({ code: 1, msg: '用户不存在' });

      if (loginUser.role === 'admin') {
        if (targetUser.role === 'owner') return jsonResp({ code: 98, msg: '无权修改所有者账号权限' }, 403);
        if (newRole === 'owner') return jsonResp({ code: 98, msg: '管理员不能授予所有者权限' }, 403);
      }

      await db.prepare(`UPDATE users SET role = ? WHERE id = ?`)
        .bind(newRole, targetUid ?? null)
        .run();
      return jsonResp({ code: 0, msg: '角色修改成功' });
    }

    // 获取全部用户列表
    if (action === 'userList' && request.method === 'GET') {
      if (!loginUser || loginUser.role === 'guest' || loginUser.role === 'banned') {
        return jsonResp({ code: 99, msg: '无权访问' }, 403);
      }
      const allUsers = await db.prepare(`
        SELECT id, username, role, is_cancel, created_at, github_id FROM users ORDER BY id DESC
      `).all();
      return jsonResp({ list: allUsers.results });
    }

    // 删除用户
    if (action === 'deleteUser' && request.method === 'POST') {
      if (!loginUser || loginUser.role === 'guest' || loginUser.role === 'banned') {
        return jsonResp({ code: 99, msg: '无权操作' }, 403);
      }
      const { targetUid } = await request.json();
      if (Number(targetUid) === loginUser.uid) {
        return jsonResp({ code: 1, msg: '不能删除当前登录账号' });
      }
      const targetUser = await db.prepare(`SELECT role FROM users WHERE id = ?`).bind(targetUid ?? null).first();
      if (!targetUser) return jsonResp({ code: 1, msg: '用户不存在' });
      if (loginUser.role === 'admin' && targetUser.role === 'owner') {
        return jsonResp({ code: 98, msg: '无法删除所有者账号' }, 403);
      }
      await db.prepare(`DELETE FROM posts WHERE author = ?`).bind(targetUid ?? null).run();
      await db.prepare(`DELETE FROM users WHERE id = ?`).bind(targetUid ?? null).run();
      return jsonResp({ code: 0, msg: '用户已删除' });
    }

    // 管理员新建用户
    if (action === 'adminAddUser' && request.method === 'POST') {
      if (!loginUser || loginUser.role === 'guest' || loginUser.role === 'banned') {
        return jsonResp({ code: 99, msg: '仅管理员可操作' }, 403);
      }
      const { username, password, role } = await request.json();
      const allowRoles = ['admin', 'writer', 'guest', 'banned'];
      if (role === 'owner') return jsonResp({ code: 1, msg: '不能创建所有者账号' });
      if (!allowRoles.includes(role)) return jsonResp({ code: 1, msg: '非法角色' });
      const hashPwd = await sha256(password);
      try {
        await db.prepare(`
          INSERT INTO users (username, password, role, is_cancel, github_id)
          VALUES (?, ?, ?, 0, NULL)
        `).bind(username, hashPwd, role).run();
        return jsonResp({ code: 0, msg: '账号创建成功' });
      } catch {
        return jsonResp({ code: 2, msg: '用户名已占用' });
      }
    }

    // 修改密码
    if (action === 'changePwd' && request.method === 'POST') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);
      const { oldPwd, newPwd } = await request.json();
      const oldHash = await sha256(oldPwd);
      const userRow = await db.prepare(`
        SELECT password FROM users WHERE id = ?
      `).bind(loginUser.uid ?? null).first();
      if (!userRow || userRow.password !== oldHash) {
        return jsonResp({ code: 1, msg: '原密码错误' });
      }
      const newHash = await sha256(newPwd);
      await db.prepare(`UPDATE users SET password = ? WHERE id = ?`)
        .bind(newHash, loginUser.uid ?? null)
        .run();
      return jsonResp({ code: 0, msg: '密码修改成功，请重新登录' });
    }

    // 注销账号（同步清空github_id）
    if (action === 'cancelAccount' && request.method === 'POST') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);
      const { password } = await request.json();
      const pwdHash = await sha256(password);
      const userRow = await db.prepare(`
        SELECT password FROM users WHERE id = ?
      `).bind(loginUser.uid ?? null).first();
      if (!userRow || userRow.password !== pwdHash) {
        return jsonResp({ code: 1, msg: '密码验证失败，无法注销' });
      }
      await db.prepare(`UPDATE users SET is_cancel = 1, github_id = NULL WHERE id = ?`)
        .bind(loginUser.uid ?? null)
        .run();
      return new Response(JSON.stringify({ code: 0, msg: '账号已注销' }), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': 'blog_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'
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
