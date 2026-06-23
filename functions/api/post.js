function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

// 工具函数：将 UTC 时间转换为东八区（UTC+8）的格式化时间
function toUTC8Time(utcTime) {
  if (!utcTime) return null;
  const date = new Date(utcTime);
  date.setHours(date.getHours() + 8);
  const pad = (n) => n.toString().padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
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

    // 文章列表
    if (request.method === 'GET' && action === 'list') {
      const rawList = await db.prepare(`
        SELECT p.id, p.title, p.content, p.created_at, p.publish_time, u.username, u.role, u.is_cancel, p.author_id
        FROM posts p LEFT JOIN users u ON p.author_id = u.id
        ORDER BY p.publish_time DESC
      `).all();
      const list = rawList.results.map(item=>{
        let displayName = item.username;
        if(item.is_cancel === 1 || item.username === null){
          displayName = "账户已注销";
        }
        return {
          ...item,
          authorName: displayName,
          created_at: toUTC8Time(item.created_at),
          publish_time: toUTC8Time(item.publish_time)
        }
      })
      return jsonResp(list);
    }

    // 文章详情 + 不存在返回404
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
      return jsonResp({
        ...row,
        displayAuthor,
        created_at: toUTC8Time(row.created_at),
        publish_time: toUTC8Time(row.publish_time)
      });
    }

    // 新建文章（支持定时发布 publishTime）
    if (request.method === 'POST' && action === 'create') {
      if (!loginUser) return jsonResp({ code:99, msg:'请先登录' }, 401);
      // 新增 owner 角色可发布文章
      const allowPostRole = ['admin','writer','owner'];
      if (!allowPostRole.includes(loginUser.role)) {
        return jsonResp({ code:98, msg:'当前身份不能发布文章' }, 403);
      }
      const { title, content, publishTime } = await request.json();
      if (!title || !content) return jsonResp({ code:1, msg:'标题和内容不能为空' });
      const finalPublish = publishTime || new Date().toISOString();
      await db.prepare(`INSERT INTO posts (title, content, author_id, publish_time) VALUES (?, ?, ?, ?)`)
        .bind(title, content, loginUser.uid, finalPublish).run();
      return jsonResp({ code:0, msg:'发布成功' });
    }

    // 编辑文章接口
    if (request.method === 'POST' && action === 'edit') {
      if (!loginUser) return jsonResp({ code:99, msg:'请先登录' }, 401);
      const { postId, title, content } = await request.json();

      const post = await db.prepare("SELECT author_id FROM posts WHERE id = ?")
        .bind(postId).first();

      if (!post) return jsonResp({ code:1, msg:'文章不存在' });

      // admin/owner/文章作者均可编辑
      if (loginUser.role !== 'admin' && loginUser.role !== 'owner' && post.author_id !== loginUser.uid) {
        return jsonResp({ code:98, msg:'无权限编辑' }, 403);
      }

      await db.prepare("UPDATE posts SET title = ?, content = ? WHERE id = ?")
        .bind(title, content, postId).run();

      return jsonResp({ code:0, msg:'修改成功' });
    }

    // 删除文章
    if (request.method === 'POST' && action === 'delete') {
      if (!loginUser) return jsonResp({ code:99, msg:'请先登录' }, 401);
      const { postId } = await request.json();
      const postInfo = await db.prepare(`SELECT author_id FROM posts WHERE id = ?`).bind(postId).first();
      if (!postInfo) return jsonResp({ code:1, msg:'文章不存在' });

      // admin/owner/文章作者均可删除
      if (loginUser.role !== 'admin' && loginUser.role !== 'owner' && postInfo.author_id !== loginUser.uid) {
        return jsonResp({ code:98, msg:'无权删除他人文章' }, 403);
      }
      await db.prepare(`DELETE FROM posts WHERE id = ?`).bind(postId).run();
      return jsonResp({ code:0, msg:'删除成功' });
    }

    // 获取评论列表
    if (request.method === 'GET' && action === 'getComment') {
      const postId = url.searchParams.get('postId');
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
          createTime: toUTC8Time(cm.created_at),
          userId: cm.user_id,
          userName: name
        }
      })
      return jsonResp(resList);
    }

    // 发表评论（访客可评论，仅封禁禁止）
    if (request.method === 'POST' && action === 'addComment') {
      if (!loginUser) return jsonResp({ code:99, msg:'请登录后发表评论' }, 401);
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

    // 删除评论
    if (request.method === 'POST' && action === 'delComment') {
      if (!loginUser) return jsonResp({ code:99, msg:'请先登录' }, 401);
      const { commentId } = await request.json();
      const cmInfo = await db.prepare(`SELECT user_id FROM comments WHERE id = ?`).bind(commentId).first();
      if(!cmInfo) return jsonResp({code:1, msg:'评论不存在'});
      // admin、owner、评论本人可删评论
      if(loginUser.role !== 'admin' && loginUser.role !== 'owner' && cmInfo.user_id !== loginUser.uid){
        return jsonResp({code:98, msg:'无权删除这条评论'}, 403);
      }
      await db.prepare(`DELETE FROM comments WHERE id = ?`).bind(commentId).run();
      return jsonResp({code:0, msg:'评论已删除'});
    }

    // 未知action兜底404
    return jsonResp({ code:99, msg:'接口不存在' }, 404);
  } catch (e) {
    // 全局异常捕获，统一500返回
    return jsonResp({ code:500, msg:'服务器错误', err:e.message }, 500);
  }
}
