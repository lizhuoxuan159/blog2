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
    exp: Date.now() + 86400000 // 1天有效期
  };
  return btoa(JSON.stringify(payload));
}

// 统一返回JSON格式
function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

// 解析Cookie获取登录用户信息
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

export async function onRequest({ request, env }) {
  try {
    const db = env.DB;
    const url = new URL(request.url);
    const action = url.searchParams.get('action');
    const loginUser = await getLoginUser(request);

    // 退出登录
    if (action === 'logout' && request.method === 'POST') {
      return new Response(JSON.stringify({ code:0, msg:'已退出登录' }), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': 'blog_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'
        }
      });
    }

    // 检查登录状态+权限
    if (action === 'check' && request.method === 'GET') {
      if (!loginUser) return jsonResp({ login:false });
      // 校验账号是否被封禁
      const userInfo = await db.prepare(`SELECT role FROM users WHERE id = ?`)
        .bind(loginUser.uid).first();
      if (!userInfo || userInfo.role === 'banned') {
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

    // 注册接口：新用户默认访客 guest
    if (action === 'register' && request.method === 'POST') {
      const { username, password } = await request.json();
      const hashPwd = await sha256(password);
      try {
        await db.prepare(`INSERT INTO users (username, password, role) VALUES (?, ?, 'guest')`)
          .bind(username, hashPwd).run();
        return jsonResp({ code:0, msg:'注册成功，请登录' });
      } catch (e) {
        return jsonResp({ code:1, msg:'用户名已存在' });
      }
    }

    // 登录接口：封禁账号直接拒绝登录
    if (action === 'login' && request.method === 'POST') {
      const { username, password } = await request.json();
      const hashPwd = await sha256(password);
      const res = await db.prepare(`SELECT id, username, role FROM users WHERE username = ? AND password = ?`)
        .bind(username, hashPwd).first();

      if (!res) return jsonResp({ code:1, msg:'账号或密码错误' });
      if (res.role === 'banned') return jsonResp({ code:2, msg:'该账号已被封禁，禁止登录' });

      const sessionToken = createSessionToken(res.id, res.username, res.role);
      return new Response(JSON.stringify({ code:0, msg:'登录成功' }), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': `blog_session=${sessionToken}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`
        }
      });
    }

    // 管理员专属：修改用户角色
    if (action === 'setRole' && request.method === 'POST') {
      // 校验当前操作者是否管理员
      if (!loginUser || loginUser.role !== 'admin') {
        return jsonResp({ code:99, msg:'无权操作，仅管理员可用' }, 403);
      }
      const { targetUid, newRole } = await request.json();
      // 限制合法角色
      const allowRoles = ['admin','writer','guest','banned'];
      if (!allowRoles.includes(newRole)) {
        return jsonResp({ code:1, msg:'非法角色值' });
      }
      await db.prepare(`UPDATE users SET role = ? WHERE id = ?`)
        .bind(newRole, targetUid).run();
      return jsonResp({ code:0, msg:'角色修改成功' });
    }

    // 管理员：获取全部用户列表
    if (action === 'userList' && request.method === 'GET') {
      if (!loginUser || loginUser.role !== 'admin') {
        return jsonResp({ code:99, msg:'无权访问' }, 403);
      }
      const allUsers = await db.prepare(`SELECT id, username, role, created_at FROM users ORDER BY id`).all();
      return jsonResp({ code:0, list: allUsers.results });
    }

    return jsonResp({ code:99, msg:'非法请求' }, 405);
  } catch (globalErr) {
    return jsonResp({ code:500, msg:'服务器内部错误', err: globalErr.message }, 500);
  }
}