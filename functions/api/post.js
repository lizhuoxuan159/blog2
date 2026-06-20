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

export async function onRequest({ request, env }) {
  try {
    const db = env.DB;
    const url = new URL(request.url);
    const action = url.searchParams.get('action');
    const loginUser = await getLoginUser(request);

    // 文章列表，自动判断注销状态
    if (request.method === 'GET' && action === 'list') {
      const rawList = await db.prepare(`
        SELECT p.id, p.title, p.content, p.created_at, u.username, u.role, u.is_cancel
        FROM posts p LEFT JOIN users u ON p.author_id = u.id
        ORDER BY p.created_at DESC
      `).all();
      const list = rawList.results.map(item=>{
        let displayName = item.username;
        // 用户被删除 / 主动注销，统一显示账户已注销
        if(item.is_cancel === 1 || item.username === null){
          displayName = "账户已注销";
        }
        return {
          ...item,
          authorName: displayName
        }
      })
      return jsonResp(list);
    }

    // 文章详情
    if (request.method === 'GET' && action === 'detail') {
      const id = url.searchParams.get('id');
      const row = await db.prepare(`
        SELECT p.*, u.username, u.is_cancel FROM posts p
        LEFT JOIN users u ON p.author_id = u.id WHERE p.id = ?
      `).bind(id).first();
      let displayAuthor = row?.username;
      if(row?.is_cancel === 1 || displayAuthor === null){
        displayAuthor = "账户已注销";
      }
      return jsonResp({...row, displayAuthor});
    }

    // 新建文章权限控制
    if (request.method === 'POST' && action === 'create') {
      if (!loginUser) return jsonResp({ code:99, msg:'请先登录' }, 401);
      const allowPostRole = ['admin','writer'];
      if (!allowPostRole.includes(loginUser.role)) {
        return jsonResp({ code:98, msg:'当前身份不能发布文章' }, 403);
      }
      const { title, content } = await request.json();
      await db.prepare(`INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)`)
        .bind(title, content, loginUser.uid).run();
      return jsonResp({ code:0, msg:'发布成功' });
    }

    // 删除文章权限
    if (request.method === 'POST' && action === 'delete') {
      if (!loginUser) return jsonResp({ code:99, msg:'请先登录' }, 401);
      const { postId } = await request.json();
      const postInfo = await db.prepare(`SELECT author_id FROM posts WHERE id = ?`).bind(postId).first();
      if (!postInfo) return jsonResp({ code:1, msg:'文章不存在' });

      if (loginUser.role !== 'admin' && postInfo.author_id !== loginUser.uid) {
        return jsonResp({ code:98, msg:'无权删除他人文章' }, 403);
      }
      await db.prepare(`DELETE FROM posts WHERE id = ?`).bind(postId).run();
      return jsonResp({ code:0, msg:'删除成功' });
    }

    return jsonResp({ code:99, msg:'接口不存在' }, 404);
  } catch (e) {
    return jsonResp({ code:500, msg:'服务器错误', err:e.message }, 500);
  }
}