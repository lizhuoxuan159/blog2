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
        SELECT p.id, p.title, p.content, p.created_at, u.username, u.role, u.is_cancel, p.author_id
        FROM posts p LEFT JOIN users u ON p.author_id = u.id
        ORDER BY p.created_at DESC
      `).all();
      const list = rawList.results.map(item=>{
        let displayName = item.username;
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
	if (!row) {
    		return jsonResp({ notFound: true }, 404);
  	}
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

    // ========== 评论接口 1：获取某文章全部评论 ==========
    if (request.method === 'GET' && action === 'getComment') {
      const postId = url.searchParams.get('postId');
      // 联表查询，注销用户显示「账户已注销」
      const comments = await db.prepare(`
        SELECT c.id, c.content, c.created_at, c.user_id, u.username, u.is_cancel
        FROM comments c
        LEFT JOIN users u ON c.user_id = u.id
        WHERE c.post_id = ?
        ORDER BY c.id ASC
      `).bind(postId).all();
      const resList = comments.results.map(cm=>{
        let name = cm.username;
        if(cm.is_cancel === 1 || name === null) name = "账户已注销";
        return {
          id: cm.id,
          content: cm.content,
          createTime: cm.created_at,
          userId: cm.user_id,
          userName: name
        }
      })
      return jsonResp(resList);
    }

    // ========== 评论接口 2：发表评论 ==========
    if (request.method === 'POST' && action === 'addComment') {
      if (!loginUser) return jsonResp({ code:99, msg:'请登录后发表评论' }, 401);
      // 封禁、访客禁止发评论
      // 仅封禁账号禁止发评论
	const banRole = ['banned'];
	if(banRole.includes(loginUser.role)){
  		return jsonResp({ code:98, msg:'封禁账号无法发表评论' }, 403);
	}
      const { postId, content } = await request.json();
      if(!content.trim()) return jsonResp({code:1, msg:'评论内容不能为空'});
      await db.prepare(`INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)`)
        .bind(postId, loginUser.uid, content.trim()).run();
      return jsonResp({code:0, msg:'评论发表成功'});
    }

    // ========== 评论接口 3：删除评论 ==========
    if (request.method === 'POST' && action === 'delComment') {
      if (!loginUser) return jsonResp({ code:99, msg:'请先登录' }, 401);
      const { commentId } = await request.json();
      const cmInfo = await db.prepare(`SELECT user_id FROM comments WHERE id = ?`).bind(commentId).first();
      if(!cmInfo) return jsonResp({code:1, msg:'评论不存在'});
      // 管理员可删全部，普通人只能删自己评论
      if(loginUser.role !== 'admin' && cmInfo.user_id !== loginUser.uid){
        return jsonResp({code:98, msg:'无权删除这条评论'}, 403);
      }
      await db.prepare(`DELETE FROM comments WHERE id = ?`).bind(commentId).run();
      return jsonResp({code:0, msg:'评论已删除'});
    }

    return jsonResp({ code:99, msg:'接口不存在' }, 404);
  } catch (e) {
    return jsonResp({ code:500, msg:'服务器错误', err:e.message }, 500);
  }
}