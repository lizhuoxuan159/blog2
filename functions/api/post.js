export async function onRequest({ request, env }) {
  const db = env.DB;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');

  if (request.method === 'GET' && action === 'list') {
    const list = await db.prepare(`
      SELECT p.id, p.title, p.content, p.created_at, u.username
      FROM posts p LEFT JOIN users u ON p.author_id = u.id
      ORDER BY p.created_at DESC
    `).all();
    return new Response(JSON.stringify(list.results), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (request.method === 'GET' && action === 'detail') {
    const id = url.searchParams.get('id');
    const row = await db.prepare(`
      SELECT p.*, u.username FROM posts p
      LEFT JOIN users u ON p.author_id = u.id WHERE p.id = ?
    `).bind(id).first();
    return new Response(JSON.stringify(row), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (request.method === 'POST' && action === 'create') {
    const { title, content, uid } = await request.json();
    await db.prepare(`INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)`)
      .bind(title, content, uid).run();
    return new Response(JSON.stringify({ code: 0, msg: '发布成功' }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  return new Response('Not Found', { status: 404 });
}