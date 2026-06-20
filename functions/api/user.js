async function sha256(rawStr) {
  const encoder = new TextEncoder();
  const data = encoder.encode(rawStr);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function createSessionToken(uid, username) {
  const payload = {
    uid,
    username,
    exp: Date.now() + 86400000
  };
  return btoa(JSON.stringify(payload));
}

export async function onRequest({ request, env }) {
  try {
    const db = env.DB;
    const url = new URL(request.url);
    const action = url.searchParams.get('action');

    if (action === 'logout' && request.method === 'POST') {
      return new Response(JSON.stringify({ code:0, msg:'已退出登录' }), {
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': 'blog_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'
        }
      });
    }

    if (action === 'check' && request.method === 'GET') {
      const cookieHeader = request.headers.get('Cookie') || '';
      const match = cookieHeader.match(/blog_session=([^;]+)/);
      if (!match) {
        return new Response(JSON.stringify({ login:false }), {
          headers: { 'Content-Type': 'application/json; charset=utf-8' }
        });
      }
      try {
        const payload = JSON.parse(atob(match[1]));
        if (Date.now() > payload.exp) {
          return new Response(JSON.stringify({ login:false }), {
            headers: {
              'Content-Type': 'application/json; charset=utf-8',
              'Set-Cookie': 'blog_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'
            }
          });
        }
        return new Response(JSON.stringify({
          login:true,
          uid: payload.uid,
          username: payload.username
        }), { headers: { 'Content-Type': 'application/json; charset=utf-8' } });
      } catch {
        return new Response(JSON.stringify({ login:false }), {
          headers: { 'Content-Type': 'application/json; charset=utf-8' }
        });
      }
    }

    if (request.method === 'POST') {
      const body = await request.json();
      const { username, password } = body;
      const hashPwd = await sha256(password);

      if (action === 'register') {
        try {
          await db.prepare(`INSERT INTO users (username, password) VALUES (?, ?)`)
            .bind(username, hashPwd).run();
          return new Response(JSON.stringify({ code: 0, msg: '注册成功' }), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        } catch (e) {
          return new Response(JSON.stringify({ code: 1, msg: '用户名已存在' }), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }
      }

      if (action === 'login') {
        const res = await db.prepare(`SELECT id, username FROM users WHERE username = ? AND password = ?`)
          .bind(username, hashPwd).first();
        if (res) {
          const sessionToken = createSessionToken(res.id, res.username);
          return new Response(JSON.stringify({ code: 0, msg:'登录成功' }), {
            headers: {
              'Content-Type': 'application/json; charset=utf-8',
              'Set-Cookie': `blog_session=${sessionToken}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`
            }
          });
        } else {
          return new Response(JSON.stringify({ code: 1, msg: '账号密码错误' }), {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
          });
        }
      }
    }

    return new Response(JSON.stringify({code:99,msg:非法请求}), {
      status:405,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  } catch (globalErr) {
    // 全局捕获异常，强制返回JSON，避免返回HTML报错页
    return new Response(JSON.stringify({
      code:500,
      msg:'服务器内部错误',
      err: globalErr.message
    }), {
      status:500,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }
}