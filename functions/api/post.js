function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

// 工具函数：UTC转东八区时间
function toUTC8Time(utcTime) {
  if (!utcTime) return null;
  const date = new Date(utcTime);
  date.setHours(date.getHours() + 8);
  const pad = (n) => n.toString().padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

// 获取登录用户
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

    // 文章列表 - 未登录/普通用户看所有人已发布；admin/owner看全部（草稿+发布）
    if (request.method === 'GET' && action === 'list') {
      const isAdmin = loginUser && ['admin','owner'].includes(loginUser.role);
      let sql = `
        SELECT p.id, p.title, p.content, p.created_at, p.publish_time, p.publish, u.username, u.role, u.is_cancel, p.author_id
        FROM posts p LEFT JOIN users u ON p.author_id = u.id
      `;
      // 非管理员（游客、writer）仅展示已发布文章，可查看所有人
      if(!isAdmin){
        sql += ` WHERE p.publish = 1 `;
      }
      sql += ` ORDER BY p.publish_time DESC`;

      const rawList = await db.prepare(sql).all();
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
      // 草稿仅作者/管理员/owner可见；已发布所有人可看
      const isSelf = loginUser && loginUser.uid === row.author_id;
      const isAdmin = loginUser && ['admin','owner'].includes(loginUser.role);
      if(row.publish === 0 && !isSelf && !isAdmin){
        return jsonResp({code:403, msg:'该文章为草稿，无权查看'},403)
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

    // 新建文章（owner/admin/writer允许发布）
    if (request.method === 'POST' && action === 'create') {
      if (!loginUser) return jsonResp({ code:99, msg:'请先登录' }, 401);
      const allowPostRole = ['admin','writer','owner'];
      if (!allowPostRole.includes(loginUser.role)) {
        return jsonResp({ code:98, msg:'当前身份不能发布文章' }, 403);
      }
      const { title, content, publishTime, publish = 0 } = await request.json();
      if (!title || !content) return jsonResp({ code:1, msg:'标题和内容不能为空' });
      let finalPublishTime = null;
      // 修复变量名：publishingTime → publishTime
      if (publishTime) {
        finalPublishTime = publishTime;
      } else if (publish === 1) {
        finalPublishTime = new Date().toISOString();
      }
      // 补全created_at避免数据库非空报错
      await db.prepare(`
        INSERT INTO posts (title, content, author_id, publish_time, publish, created_at) 
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      `).bind(title, content, loginUser.uid, finalPublishTime, publish).run();
      return jsonResp({ code:0, msg:'保存成功' });
    }

    // 编辑文章
    if (request.method === 'POST' && action === 'edit') {
      if (!loginUser) return jsonResp({ code:99, msg:'请先登录' }, 401);
      const { postId, title, content, publish } = await request.json();

      const post = await db.prepare("SELECT author_id FROM posts WHERE id = ?")
        .bind(postId).first();

      if (!post) return jsonResp({ code:1, msg:'文章不存在' });

      if (loginUser.role !== 'admin' && loginUser.role !== 'owner' && post.author_id !== loginUser.uid) {
        return jsonResp({ code:98, msg:'无权限编辑' }, 403);
      }
      // 修复变量名 publishing → publish
      if (publish === 1) {
        await db.prepare(`
          UPDATE posts 
          SET title = ?, content = ?, publish = ?, publish_time = ? 
          WHERE id = ?
        `).bind(title, content, publish, new Date().toISOString(), postId).run();
      } else {
        await db.prepare(`
          UPDATE posts 
          SET title = ?, content = ?, publish = ? 
          WHERE id = ?
        `).bind(title, content, publish, postId).run();
      }

      return jsonResp({ code:0, msg:'修改成功' });
    }

    // 删除文章
    if (request.method === 'POST' && action === 'delete') {
      if (!loginUser) return jsonResp({ code:99, msg:'请先登录' }, 401);
      const { postId } = await request.json();
      const postInfo = await db.prepare(`SELECT author_id FROM posts WHERE id = ?`).bind(postId).first();
      if (!postInfo) return jsonResp({ code:1, msg:'文章不存在' });

      if (loginUser.role !== 'admin' && loginUser.role !== 'owner' && postInfo.author_id !== loginUser.uid) {
        return jsonResp({ code:98, msg:'无权删除他人文章' }, 403);
      }
      await db.prepare(`DELETE FROM posts WHERE id = ?`).bind(postId).run();
      return jsonResp({ code:0, msg:'删除成功' });
    }

    // 切换草稿/发布状态
    if(request.method === 'POST' && action === 'changePublish'){
      if (!loginUser) return jsonResp({ code:99, msg:'请先登录' }, 401);
      const { postId, publish } = await request.json();
      const post = await db.prepare("SELECT author_id FROM posts WHERE id = ?").bind(postId).first();
      if(!post) return jsonResp({code:1,msg:'文章不存在'});
      if (loginUser.role !== 'admin' && loginUser.role !== 'owner' && post.author_id !== loginUser.uid) {
        return jsonResp({ code:98, msg:'无权限操作' }, 403);
      }
      // 修复变量名 publishing → publish
      if (publish === 1) {
        await db.prepare(`UPDATE posts SET publish = ?, publish_time = ? WHERE id = ?`)
          .bind(publish, new Date().toISOString(), postId).run();
      } else {
        await db.prepare(`UPDATE posts SET publish = ? WHERE id = ?`)
          .bind(publish, postId).run();
      }
      return jsonResp({code:0,msg:publish===1?'已设为发布':'已设为草稿'});
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

    // 发表评论
    if (request.method === 'POST' && action === 'addComment') {
      if (!loginUser) return jsonResp({ code:99, msg:'请登录后发表评论' }, 401);
      const banRole = ['banned'];
      if(banRole.includes(loginUser.role)){
        return jsonResp({ code:98, msg:'封禁账号无法发表评论' }, 403);
      }
      const { postId, content } = await request.json();
      if(!content.trim()) return jsonResp({code:1, msg:'评论内容不能为空'});
      // 禁止给草稿文章评论
      const p = await db.prepare("SELECT publish FROM posts WHERE id=?").bind(postId).first();
      if(!p) return jsonResp({code:1,msg:'文章不存在'});
      if(p.publish === 0) return jsonResp({code:403,msg:'草稿文章暂不支持评论'},403);

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
      if(loginUser.role !== 'admin' && loginUser.role !== 'owner' && cmInfo.user_id !== loginUser.uid){
        return jsonResp({code:98, msg:'无权删除这条评论'}, 403);
      }
      await db.prepare(`DELETE FROM comments WHERE id = ?`).bind(commentId).run();
      return jsonResp({code:0, msg:'评论已删除'});
    }

    return jsonResp({ code:99, msg:'接口不存在' }, 404);
  } catch (e) {
    console.error("接口捕获异常：", e);
    return jsonResp({ code:500, msg:'服务器错误：' + e.message, err:e.message }, 500);
  }
}
