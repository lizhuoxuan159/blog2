// ÒÆ³ýÍâ²¿ import { sha256 } from 'crypto-hash';
async function sha256(rawStr) {
  const encoder = new TextEncoder();
  const data = encoder.encode(rawStr);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function onRequest({ request, env }) {
  const db = env.DB;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');

  if (request.method === 'POST') {
    const body = await request.json();
    const { username, password } = body;
    const hashPwd = await sha256(password);

    // ×¢²áÂß¼­
    if (action === 'register') {
      try {
        await db.prepare(`INSERT INTO users (username, password) VALUES (?, ?)`)
          .bind(username, hashPwd).run();
        return new Response(JSON.stringify({ code: 0, msg: '×¢²á³É¹¦' }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ code: 1, msg: 'ÓÃ»§ÃûÒÑ´æÔÚ' }), {
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // µÇÂ¼Âß¼­
    if (action === 'login') {
      const res = await db.prepare(`SELECT id, username FROM users WHERE username = ? AND password = ?`)
        .bind(username, hashPwd).first();
      if (res) {
        const token = btoa(JSON.stringify({ uid: res.id, user: res.username, time: Date.now() }));
        return new Response(JSON.stringify({ code: 0, token, user: res }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } else {
        return new Response(JSON.stringify({ code: 1, msg: 'ÕËºÅÃÜÂë´íÎó' }), {
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
  }

  return new Response('Method Not Allowed', { status: 405 });
}