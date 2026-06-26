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

    // ==================== 消息相关 ====================

    // 获取消息列表
    if (request.method === 'GET' && action === 'list') {
      const limit = parseInt(url.searchParams.get('limit')) || 30;
      const page = parseInt(url.searchParams.get('page')) || 1;
      const offset = (page - 1) * limit;

      const rawList = await db.prepare(`
        SELECT m.id, m.content, m.like_count, m.comment_count, m.created_at, m.user_id,
               u.username, u.role, u.is_cancel
        FROM messages m
        LEFT JOIN users u ON m.user_id = u.id
        ORDER BY m.id DESC
        LIMIT ? OFFSET ?
      `).bind(limit, offset).all();

      // 查询当前用户点赞了哪些消息
      let likedIds = new Set();
      if (loginUser) {
        const likes = await db.prepare(`
          SELECT message_id FROM message_likes WHERE user_id = ?
        `).bind(loginUser.uid).all();
        likes.results.forEach(l => likedIds.add(l.message_id));
      }

      const list = rawList.results.map(item => {
        let displayName = item.username;
        if (item.is_cancel === 1 || item.username === null) {
          displayName = "账户已注销";
        }
        return {
          id: item.id,
          content: item.content,
          likeCount: item.like_count || 0,
          commentCount: item.comment_count || 0,
          createTime: toUTC8Time(item.created_at),
          userId: item.user_id,
          userName: displayName,
          userRole: item.role,
          liked: likedIds.has(item.id)
        };
      });

      return jsonResp(list);
    }

    // 发布消息
    if (request.method === 'POST' && action === 'send') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);
      
      const banRole = ['banned'];
      if (banRole.includes(loginUser.role)) {
        return jsonResp({ code: 98, msg: '封禁账号无法发送消息' }, 403);
      }

      const { content } = await request.json();
      if (!content || !content.trim()) {
        return jsonResp({ code: 1, msg: '消息内容不能为空' });
      }
      if (content.length > 500) {
        return jsonResp({ code: 2, msg: '消息不能超过500字' });
      }

      const result = await db.prepare(`
        INSERT INTO messages (user_id, content)
        VALUES (?, ?)
      `).bind(loginUser.uid, content.trim()).run();

      return jsonResp({ code: 0, msg: '发送成功', id: result.meta.last_row_id });
    }

    // 删除消息
    if (request.method === 'POST' && action === 'delete') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);

      const { msgId } = await request.json();
      const msg = await db.prepare(`SELECT user_id FROM messages WHERE id = ?`)
        .bind(msgId).first();

      if (!msg) return jsonResp({ code: 1, msg: '消息不存在' });

      const isAdmin = ['admin', 'owner'].includes(loginUser.role);
      if (!isAdmin && msg.user_id !== loginUser.uid) {
        return jsonResp({ code: 98, msg: '无权删除这条消息' }, 403);
      }

      // 删除消息、相关点赞和评论
      await db.prepare(`DELETE FROM messages WHERE id = ?`).bind(msgId).run();
      await db.prepare(`DELETE FROM message_likes WHERE message_id = ?`).bind(msgId).run();
      await db.prepare(`DELETE FROM message_comments WHERE message_id = ?`).bind(msgId).run();

      return jsonResp({ code: 0, msg: '删除成功' });
    }

    // 点赞/取消点赞
    if (request.method === 'POST' && action === 'like') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);

      const { msgId } = await request.json();
      const msg = await db.prepare(`SELECT id FROM messages WHERE id = ?`)
        .bind(msgId).first();

      if (!msg) return jsonResp({ code: 1, msg: '消息不存在' });

      // 检查是否已经点赞
      const existing = await db.prepare(`
        SELECT id FROM message_likes WHERE message_id = ? AND user_id = ?
      `).bind(msgId, loginUser.uid).first();

      if (existing) {
        // 取消点赞
        await db.prepare(`DELETE FROM message_likes WHERE id = ?`).bind(existing.id).run();
        await db.prepare(`UPDATE messages SET like_count = like_count - 1 WHERE id = ?`)
          .bind(msgId).run();
        return jsonResp({ code: 0, msg: '已取消点赞', liked: false, likeCount: -1 });
      } else {
        // 点赞
        await db.prepare(`INSERT INTO message_likes (message_id, user_id) VALUES (?, ?)`)
          .bind(msgId, loginUser.uid).run();
        await db.prepare(`UPDATE messages SET like_count = like_count + 1 WHERE id = ?`)
          .bind(msgId).run();
        return jsonResp({ code: 0, msg: '点赞成功', liked: true, likeCount: 1 });
      }
    }

    // ==================== 评论相关 ====================

    // 获取评论列表
    if (request.method === 'GET' && action === 'getComments') {
      const msgId = url.searchParams.get('msgId');
      if (!msgId) return jsonResp({ code: 1, msg: '参数错误' });

      const rawComments = await db.prepare(`
        SELECT c.id, c.content, c.reply_to, c.created_at, c.user_id,
               u.username, u.role, u.is_cancel
        FROM message_comments c
        LEFT JOIN users u ON c.user_id = u.id
        WHERE c.message_id = ?
        ORDER BY c.id ASC
      `).bind(msgId).all();

      const comments = rawComments.results.map(item => {
        let displayName = item.username;
        if (item.is_cancel === 1 || item.username === null) {
          displayName = "账户已注销";
        }
        return {
          id: item.id,
          content: item.content,
          replyTo: item.reply_to,
          createTime: toUTC8Time(item.created_at),
          userId: item.user_id,
          userName: displayName,
          userRole: item.role
        };
      });

      return jsonResp(comments);
    }

    // 发表评论
    if (request.method === 'POST' && action === 'addComment') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);

      const banRole = ['banned'];
      if (banRole.includes(loginUser.role)) {
        return jsonResp({ code: 98, msg: '封禁账号无法评论' }, 403);
      }

      const { msgId, content, replyTo } = await request.json();
      if (!content || !content.trim()) {
        return jsonResp({ code: 1, msg: '评论内容不能为空' });
      }
      if (content.length > 300) {
        return jsonResp({ code: 2, msg: '评论不能超过300字' });
      }

      const msg = await db.prepare(`SELECT id FROM messages WHERE id = ?`)
        .bind(msgId).first();
      if (!msg) return jsonResp({ code: 1, msg: '消息不存在' });

      await db.prepare(`
        INSERT INTO message_comments (message_id, user_id, content, reply_to)
        VALUES (?, ?, ?, ?)
      `).bind(msgId, loginUser.uid, content.trim(), replyTo || null).run();

      // 更新评论数
      await db.prepare(`UPDATE messages SET comment_count = comment_count + 1 WHERE id = ?`)
        .bind(msgId).run();

      return jsonResp({ code: 0, msg: '评论成功' });
    }

    // 删除评论
    if (request.method === 'POST' && action === 'delComment') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);

      const { commentId } = await request.json();
      const comment = await db.prepare(`
        SELECT c.id, c.user_id, c.message_id 
        FROM message_comments c 
        WHERE c.id = ?
      `).bind(commentId).first();

      if (!comment) return jsonResp({ code: 1, msg: '评论不存在' });

      const isAdmin = ['admin', 'owner'].includes(loginUser.role);
      if (!isAdmin && comment.user_id !== loginUser.uid) {
        return jsonResp({ code: 98, msg: '无权删除这条评论' }, 403);
      }

      await db.prepare(`DELETE FROM message_comments WHERE id = ?`).bind(commentId).run();
      await db.prepare(`UPDATE messages SET comment_count = comment_count - 1 WHERE id = ?`)
        .bind(comment.message_id).run();

      return jsonResp({ code: 0, msg: '删除成功' });
    }
    // ==================== 私聊相关 ====================

    // 获取会话列表
    if (request.method === 'GET' && action === 'conversationList') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);

      const uid = loginUser.uid;
      
      // 找出所有和当前用户聊过天的用户，以及最后一条消息
      const rawConversations = await db.prepare(`
        SELECT 
          CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as other_user_id,
          MAX(id) as last_msg_id
        FROM private_messages
        WHERE sender_id = ? OR receiver_id = ?
        GROUP BY other_user_id
        ORDER BY last_msg_id DESC
      `).bind(uid, uid, uid).all();

      const conversations = [];
      for (const conv of rawConversations.results) {
        // 获取最后一条消息
        const lastMsg = await db.prepare(`
          SELECT content, created_at, sender_id, is_read
          FROM private_messages
          WHERE id = ?
        `).bind(conv.last_msg_id).first();

        // 获取对方用户信息
        const otherUser = await db.prepare(`
          SELECT username, role, is_cancel
          FROM users
          WHERE id = ?
        `).bind(conv.other_user_id).first();

        // 计算未读数
        const unreadRes = await db.prepare(`
          SELECT COUNT(*) as count
          FROM private_messages
          WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
        `).bind(conv.other_user_id, uid).first();

        let displayName = otherUser?.username || '未知用户';
        if (otherUser?.is_cancel === 1) displayName = '账户已注销';

        conversations.push({
          userId: conv.other_user_id,
          userName: displayName,
          userRole: otherUser?.role,
          lastMessage: lastMsg?.content || '',
          lastTime: toUTC8Time(lastMsg?.created_at),
          unreadCount: unreadRes?.count || 0,
          isLastFromMe: lastMsg?.sender_id === uid
        });
      }

      return jsonResp(conversations);
    }

    // 获取和某人的聊天记录
    if (request.method === 'GET' && action === 'getPrivateMessages') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);

      const otherUserId = parseInt(url.searchParams.get('userId'));
      if (!otherUserId) return jsonResp({ code: 1, msg: '参数错误' });

      const uid = loginUser.uid;
      const limit = parseInt(url.searchParams.get('limit')) || 50;

      // 获取消息（最新的50条，然后倒序）
      const rawMsgs = await db.prepare(`
        SELECT id, sender_id, receiver_id, content, is_read, created_at
        FROM private_messages
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY id DESC
        LIMIT ?
      `).bind(uid, otherUserId, otherUserId, uid, limit).all();

      // 标记为已读（对方发的消息）
      await db.prepare(`
        UPDATE private_messages
        SET is_read = 1
        WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
      `).bind(otherUserId, uid).run();

      // 倒序排列（最新的在下面）
      const messages = rawMsgs.results.reverse().map(msg => ({
        id: msg.id,
        content: msg.content,
        isMe: msg.sender_id === uid,
        createTime: toUTC8Time(msg.created_at),
        isRead: msg.is_read
      }));

      return jsonResp(messages);
    }

    // 发送私聊消息
    if (request.method === 'POST' && action === 'sendPrivate') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);

      const banRole = ['banned'];
      if (banRole.includes(loginUser.role)) {
        return jsonResp({ code: 98, msg: '封禁账号无法发送消息' }, 403);
      }

      const { userId, content } = await request.json();
      if (!userId || !content || !content.trim()) {
        return jsonResp({ code: 1, msg: '参数错误' });
      }
      if (content.length > 500) {
        return jsonResp({ code: 2, msg: '消息不能超过500字' });
      }

      // 检查对方用户是否存在
      const receiver = await db.prepare(`
        SELECT id, is_cancel FROM users WHERE id = ?
      `).bind(userId).first();
      if (!receiver) return jsonResp({ code: 1, msg: '用户不存在' });
      if (receiver.is_cancel === 1) return jsonResp({ code: 1, msg: '对方账户已注销' });

      // 不能给自己发消息
      if (userId === loginUser.uid) {
        return jsonResp({ code: 1, msg: '不能给自己发消息' });
      }

      const result = await db.prepare(`
        INSERT INTO private_messages (sender_id, receiver_id, content)
        VALUES (?, ?, ?)
      `).bind(loginUser.uid, userId, content.trim()).run();

      return jsonResp({ 
        code: 0, 
        msg: '发送成功',
        id: result.meta.last_row_id,
        createTime: toUTC8Time(new Date().toISOString())
      });
    }

    // 获取未读消息总数
    if (request.method === 'GET' && action === 'getUnreadCount') {
      if (!loginUser) return jsonResp({ total: 0 });

      const res = await db.prepare(`
        SELECT COUNT(*) as total
        FROM private_messages
        WHERE receiver_id = ? AND is_read = 0
      `).bind(loginUser.uid).first();

      return jsonResp({ total: res?.total || 0 });
    }

    // 标记会话已读
    if (request.method === 'POST' && action === 'markRead') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);

      const { userId } = await request.json();
      await db.prepare(`
        UPDATE private_messages
        SET is_read = 1
        WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
      `).bind(userId, loginUser.uid).run();

      return jsonResp({ code: 0, msg: '已标记为已读' });
    }
    return jsonResp({ code: 99, msg: '接口不存在' }, 404);
  } catch (e) {
    console.error("聊天接口捕获异常：", e);
    return jsonResp({ code: 500, msg: '服务器错误：' + e.message, err: e.message }, 500);
  }
}