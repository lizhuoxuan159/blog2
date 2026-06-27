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
    exp: Date.now() + 86400000
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

// GitHub OAuth 获取token，使用ghproxy避免Worker请求被墙
async function getGithubToken(code, clientId, clientSecret, redirectUri) {
  const res = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code: code,
      redirect_uri: redirectUri
    })
  });
  return await res.json();
}

// 获取GitHub用户信息
async function getGithubUserInfo(accessToken) {
  const res = await fetch("https://api.github.com/user", {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  return await res.json();
}

export async function onRequest({ request, env }) {
  try {
    const db = env.DB;
    const url = new URL(request.url);
    const action = url.searchParams.get('action');
    const loginUser = await getLoginUser(request);

    // GitHub登录跳转
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

    // GitHub授权回调
    if (action === "githubCallback") {
      const clientId = env.GITHUB_CLIENT_ID;
      const clientSecret = env.GITHUB_CLIENT_SECRET;
      const siteOrigin = env.SITE_ORIGIN;
      if (!clientId || !clientSecret || !siteOrigin) {
        return jsonResp({ code: 500, msg: "GitHub登录配置缺失" }, 500);
      }
      const code = url.searchParams.get("code");
      if (!code) {
        return Response.redirect(`${siteOrigin}/login?err=github_auth_fail`, 302);
      }
      const redirectUri = `${siteOrigin}/api/user?action=githubCallback`;
      const tokenData = await getGithubToken(code, clientId, clientSecret, redirectUri);
      if (tokenData.error) {
        return Response.redirect(`${siteOrigin}/login?err=github_token_err`, 302);
      }
      const userInfo = await getGithubUserInfo(tokenData.access_token);
      const githubId = String(userInfo.id);
      const githubName = userInfo.login;

      // 查询已绑定账号
      let dbUser = await db.prepare(`SELECT id, username, role, is_cancel FROM users WHERE github_id = ?`)
        .bind(githubId).first();

      // 无绑定则自动创建账号
      if (!dbUser) {
        try {
          await db.prepare(`
            INSERT INTO users (username, password, role, is_cancel, github_id)
            VALUES (?, ?, 'guest', 0, ?)
          `).bind(githubName, "", githubId).run();
          dbUser = await db.prepare(`SELECT id, username, role FROM users WHERE github_id = ?`)
            .bind(githubId).first();
        } catch (e) {
          // 用户名冲突自动后缀
          const fixName = `${githubName}_${githubId.slice(-4)}`;
          await db.prepare(`
            INSERT INTO users (username, password, role, is_cancel, github_id)
            VALUES (?, ?, 'guest', 0, ?)
          `).bind(fixName, "", githubId).run();
          dbUser = await db.prepare(`SELECT id, username, role FROM users WHERE github_id = ?`)
            .bind(githubId).first();
        }
      }

      // 账号封禁/注销拦截
      if (dbUser.is_cancel === 1 || dbUser.role === "banned") {
        return Response.redirect(`${siteOrigin}/login?err=account_disabled`, 302);
      }

      // 生成登录Cookie，跳转首页
      const sessionToken = createSessionToken(dbUser.id, dbUser.username, dbUser.role);
      return new Response(null, {
        status: 302,
        headers: {
          Location: `${siteOrigin}/`,
          "Set-Cookie": `blog_session=${sessionToken}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`
        }
      });
    }

    // 退出登录
    if (action === 'logout' && request.method === 'POST') {
      return new Response(JSON.stringify({ code:0, msg:'已退出登录' }), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': 'blog_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'
        }
      });
    }

    // 登录状态校验
    if (action === 'check' && request.method === 'GET') {
      if (!loginUser) return jsonResp({ login:false });
      const userInfo = await db.prepare(`SELECT role,is_cancel FROM users WHERE id = ?`)
        .bind(loginUser.uid).first();
      if (!userInfo || userInfo.role === 'banned' || userInfo.is_cancel === 1) {
        return new Response(JSON.stringify({ login:false, banned:true }), {
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Set-Cookie': 'blog_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'
          }
        });
      }
      return jsonResp({
        login:true,
        uid: loginUser.uid,
        username: loginUser.username,
        role: userInfo.role
      });
    }

    // 游客注册
    if (action === 'register' && request.method === 'POST') {
      const { username, password } = await request.json();
      const hashPwd = await sha256(password);
      try {
        await db.prepare(`INSERT INTO users (username, password, role, is_cancel, github_id) VALUES (?, ?, 'guest', 0, NULL)`)
          .bind(username, hashPwd).run();
        return jsonResp({ code:0, msg:'注册成功，请登录' });
      } catch (e) {
        return jsonResp({ code:1, msg:'用户名已存在' });
      }
    }

    // 密码登录
    if (action === 'login' && request.method === 'POST') {
      const { username, password } = await request.json();
      const hashPwd = await sha256(password);
      const res = await db.prepare(`SELECT id, username, role,is_cancel FROM users WHERE username = ? AND password = ?`)
        .bind(username, hashPwd).first();

      if (!res) return jsonResp({ code:1, msg:'账号或密码错误' });
      if (res.role === 'banned') return jsonResp({ code:2, msg:'该账号已被封禁，禁止登录' });
      if (res.is_cancel === 1) return jsonResp({ code:3, msg:'该账户已注销，无法登录' });

      const sessionToken = createSessionToken(res.id, res.username, res.role);
      return new Response(JSON.stringify({ code:0, msg:'登录成功' }), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': `blog_session=${sessionToken}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`
        }
      });
    }

    // 管理员修改用户角色
    if (action === 'setRole' && request.method === 'POST') {
      if (!loginUser) return jsonResp({ code:99, msg:'无权操作，仅管理员可用' }, 403);
      const { targetUid, newRole } = await request.json();
      const allowRoles = ['owner','admin','writer','guest','banned'];
      if (!allowRoles.includes(newRole)) {
        return jsonResp({ code:1, msg:'非法角色值' });
      }
      const targetUser = await db.prepare(`SELECT id, role FROM users WHERE id = ?`).bind(targetUid).first();
      if (!targetUser) return jsonResp({ code:1, msg:'用户不存在' });

      if(loginUser.role === 'admin' && targetUser.role === 'owner'){
        return jsonResp({ code:98, msg:'无权修改所有者账号权限' },403);
      }
      if(loginUser.role === 'admin' && targetUser.role === 'admin'){
        return jsonResp({ code:98, msg:'管理员无法操作其他管理员账号' },403);
      }
      if(loginUser.role === 'admin' && newRole === 'owner'){
        return jsonResp({ code:98, msg:'管理员无权授予所有者权限' },403);
      }

      await db.prepare(`UPDATE users SET role = ? WHERE id = ?`)
        .bind(newRole, targetUid).run();
      return jsonResp({ code:0, msg:'角色修改成功' });
    }

    // 获取全部用户列表（管理员）
    if (action === 'userList' && request.method === 'GET') {
      if (!loginUser || loginUser.role === 'guest' || loginUser.role === 'banned') {
        return jsonResp({ code:99, msg:'无权访问' }, 403);
      }
      const allUsers = await db.prepare(`SELECT id, username, role, is_cancel, created_at, github_id FROM users ORDER BY id`).all();
      return jsonResp({ code:0, list: allUsers.results });
    }

    // 管理员删除用户
    if (action === 'deleteUser' && request.method === 'POST') {
      if (!loginUser || loginUser.role === 'guest' || loginUser.role === 'banned') {
        return jsonResp({ code:99, msg:'无权操作' }, 403);
      }
      const { targetUid } = await request.json();
      if (Number(targetUid) === loginUser.uid) {
        return jsonResp({ code:1, msg:'不能删除当前登录账号' });
      }
      const targetUser = await db.prepare(`SELECT role FROM users WHERE id = ?`).bind(targetUid).first();
      if(!targetUser) return jsonResp({code:1,msg:'用户不存在'});
      if(loginUser.role === 'admin'){
        if(targetUser.role === 'owner') return jsonResp({code:98,msg:'无法删除所有者账号'},403);
        if(targetUser.role === 'admin') return jsonResp({code:98,msg:'管理员无法删除其他管理员'},403);
      }
      await db.prepare(`DELETE FROM posts WHERE author_id = ?`).bind(targetUid).run();
      await db.prepare(`DELETE FROM users WHERE id = ?`).bind(targetUid).run();
      return jsonResp({ code:0, msg:'用户删除成功' });
    }

    // 管理员手动新增用户
    if (action === 'adminAddUser' && request.method === 'POST') {
      if (!loginUser || loginUser.role === 'guest' || loginUser.role === 'banned') {
        return jsonResp({ code:99, msg:'仅管理员可创建用户' }, 403);
      }
      const { username, password, role } = await request.json();
      const allowRoles = ['admin','writer','guest','banned'];
      if (role === 'owner') return jsonResp({ code:1, msg:'管理员无法创建所有者账号' });
      if (!allowRoles.includes(role)) return jsonResp({ code:1, msg:'角色非法' });
      const hashPwd = await sha256(password);
      try {
        await db.prepare(`INSERT INTO users (username,password,role,is_cancel,github_id) VALUES (?,?,?,0,NULL)`)
          .bind(username, hashPwd, role).run();
        return jsonResp({ code:0, msg:'用户创建成功' });
      } catch {
        return jsonResp({ code:2, msg:'用户名已占用' });
      }
    }

    // 用户修改密码
    if (action === 'changePwd' && request.method === 'POST') {
      if (!loginUser) return jsonResp({ code:99, msg:'请先登录' },401);
      const { oldPwd, newPwd } = await request.json();
      const oldHash = await sha256(oldPwd);
      const userRow = await db.prepare(`SELECT password FROM users WHERE id=?`)
        .bind(loginUser.uid).first();
      if (!userRow || userRow.password !== oldHash) {
        return jsonResp({ code:1, msg:'原密码错误' });
      }
      const newHash = await sha256(newPwd);
      await db.prepare(`UPDATE users SET password=? WHERE id=?`)
        .bind(newHash, loginUser.uid).run();
      return jsonResp({ code:0, msg:'密码修改成功，请重新登录' });
    }

    // 用户自助注销账户
    if (action === 'cancelAccount' && request.method === 'POST') {
      if (!loginUser) return jsonResp({ code:99, msg:'请先登录' },401);
      const { password } = await request.json();
      const pwdHash = await sha256(password);
      const userRow = await db.prepare(`SELECT password FROM users WHERE id=?`)
        .bind(loginUser.uid).first();
      if (!userRow || userRow.password !== pwdHash) {
        return jsonResp({ code:1, msg:'密码验证失败，无法注销' });
      }
      await db.prepare(`UPDATE users SET is_cancel=1 WHERE id=?`).bind(loginUser.uid).run();
      return new Response(JSON.stringify({ code:0, msg:'账户注销成功' }), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': 'blog_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'
        }
      });
    }

    return jsonResp({ code:99, msg:'非法请求' }, 405);
  } catch (globalErr) {
    return jsonResp({ code:500, msg:'服务器内部错误', err: globalErr.message }, 500);
  }
}
