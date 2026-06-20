// 从Cookie获取登录用户ID
async function getLoginUid(request) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/blog_session=([^;]+)/);
  if (!match) return null;
  try {
    const payload = JSON.parse(atob(match[1]));
    if (Date.now() > payload.exp) return null;
    return payload.uid;
  } catch {
    return null;
  }
}

export async function onRequest({ request, env }) {
  const db = env.DB;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');

  // 获取所有文章（无需登录）
  if (request.method === 'GET' && action === 'list') {
    const list = await db.prepare(`
      SELECT p.id, p.title, p.content, p.created_at, u.username
      FROM posts p LEFT JOIN users u ON p.author_id = u.id
      ORDER BY p.created_at DESC
    `).all();
    return new Response(JSON.stringify(list.results), {
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  // 单篇文章（无需登录）
  if (request.method === 'GET' && action === 'detail') {
    const id = url.searchParams.get('id');
    const row = await db.prepare(`
      SELECT p.*, u.username FROM posts p
      LEFT JOIN users u ON p.author_id = u.id WHERE p.id = ?
    `).bind(id).first();
    return new Response(JSON.stringify(row), {
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  // 新建文章：必须登录
  if (request.method === 'POST' && action === 'create') {
    const uid = await getLoginUid(request);
    if (!uid) {
      return new Response(JSON.stringify({ code: 99, msg:'请先登录' }), {
        status:401,
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
      });
    }
    const { title, content } = await request.json();
    await db.prepare(`INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)`)
      .bind(title, content, uid).run();
    return new Response(JSON.stringify({ code: 0, msg: '发布成功' }), {
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  return new Response('Not Found', { status: 404 });
}