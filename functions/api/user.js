import { sha256 } from 'crypto-hash';

export async function onRequest({ request, env }) {
  const db = env.DB;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');

  if (request.method === 'POST') {
    const body = await request.json();
    const { username, password } = body;
    const hashPwd = await sha256(password);

    if (action === 'register') {
      try {
        await db.prepare(`INSERT INTO users (username, password) VALUES (?, ?)`)
          .bind(username, hashPwd).run();
        return new Response(JSON.stringify({ code: 0, msg: '注册成功' }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ code: 1, msg: '用户名已存在' }), {
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    if (action === 'login') {
      const res = await db.prepare(`SELECT id, username FROM users WHERE username = ? AND password = ?`)
        .bind(username, hashPwd).first();
      if (res) {
        const token = btoa(JSON.stringify({ uid: res.id, user: res.username, time: Date.now() }));
        return new Response(JSON.stringify({ code: 0, token, user: res }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } else {
        return new Response(JSON.stringify({ code: 1, msg: '账号密码错误' }), {
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
  }

  return new Response('Method Not Allowed', { status: 405 });
}