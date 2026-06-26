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

// 检查并结算到期的投票
async function checkAndSettleVotes(db) {
  const now = new Date().toISOString();
  
  // 找出所有到期但未结算的投票
  const activeVotes = await db.prepare(`
    SELECT id, target_user_id, yes_count, no_count, duration_hours
    FROM ban_votes
    WHERE status = 'active' AND end_time <= ?
  `).bind(now).all();

  for (const vote of activeVotes.results) {
    // 规则：支持票 >= 10 且 支持票 > 反对票 → 放逐成功
    const passed = vote.yes_count >= 10 && vote.yes_count > vote.no_count;
    
    if (passed) {
      // 放逐成功：更新状态 + 禁言用户
      await db.prepare(`
        UPDATE ban_votes SET status = 'passed' WHERE id = ?
      `).bind(vote.id).run();
      
      // 设置禁言到期时间
      const banUntil = new Date(Date.now() + vote.duration_hours * 60 * 60 * 1000).toISOString();
      await db.prepare(`
        UPDATE users SET ban_until = ? WHERE id = ?
      `).bind(banUntil, vote.target_user_id).run();
    } else {
      // 放逐失败
      await db.prepare(`
        UPDATE ban_votes SET status = 'failed' WHERE id = ?
      `).bind(vote.id).run();
    }
  }
}

// 检查用户是否被禁言
async function checkUserBanned(db, userId) {
  const user = await db.prepare(`
    SELECT role, ban_until FROM users WHERE id = ?
  `).bind(userId).first();
  
  if (!user) return false;
  
  // 永久封禁
  if (user.role === 'banned') return true;
  
  // 临时禁言
  if (user.ban_until) {
    const banUntil = new Date(user.ban_until).getTime();
    if (banUntil > Date.now()) {
      return true;
    } else {
      // 禁言已到期，自动解封
      await db.prepare(`UPDATE users SET ban_until = NULL WHERE id = ?`).bind(userId).run();
    }
  }
  
  return false;
}

export async function onRequest({ request, env }) {
  try {
    const db = env.DB;
    const url = new URL(request.url);
    const action = url.searchParams.get('action');
    const loginUser = await getLoginUser(request);

    // 每次请求都检查并结算到期投票
    await checkAndSettleVotes(db);

    // 获取投票列表
    if (request.method === 'GET' && action === 'list') {
      const rawList = await db.prepare(`
        SELECT v.id, v.target_user_id, v.initiator_id, v.reason, v.yes_count, v.no_count,
               v.status, v.duration_hours, v.end_time, v.created_at,
               tu.username as target_name, tu.role as target_role,
               iu.username as initiator_name
        FROM ban_votes v
        LEFT JOIN users tu ON v.target_user_id = tu.id
        LEFT JOIN users iu ON v.initiator_id = iu.id
        ORDER BY v.id DESC
        LIMIT 50
      `).all();

      // 查询当前用户投过哪些票
      let votedIds = new Map();
      if (loginUser) {
        const records = await db.prepare(`
          SELECT vote_id, vote_type FROM ban_vote_records WHERE user_id = ?
        `).bind(loginUser.uid).all();
        records.results.forEach(r => votedIds.set(r.vote_id, r.vote_type));
      }

      const list = rawList.results.map(item => ({
        id: item.id,
        targetUserId: item.target_user_id,
        targetUserName: item.target_name || '未知用户',
        targetUserRole: item.target_role,
        initiatorName: item.initiator_name || '未知用户',
        reason: item.reason,
        yesCount: item.yes_count,
        noCount: item.no_count,
        status: item.status,
        durationHours: item.duration_hours,
        endTime: toUTC8Time(item.end_time),
        createTime: toUTC8Time(item.created_at),
        myVote: votedIds.get(item.id) || null
      }));

      return jsonResp(list);
    }

    // 获取投票详情
    if (request.method === 'GET' && action === 'detail') {
      const voteId = url.searchParams.get('id');
      if (!voteId) return jsonResp({ code: 1, msg: '参数错误' });

      const vote = await db.prepare(`
        SELECT v.id, v.target_user_id, v.initiator_id, v.reason, v.yes_count, v.no_count,
               v.status, v.duration_hours, v.end_time, v.created_at,
               tu.username as target_name, tu.role as target_role,
               iu.username as initiator_name
        FROM ban_votes v
        LEFT JOIN users tu ON v.target_user_id = tu.id
        LEFT JOIN users iu ON v.initiator_id = iu.id
        WHERE v.id = ?
      `).bind(voteId).first();

      if (!vote) return jsonResp({ code: 1, msg: '投票不存在' });

      // 查询当前用户是否投过票
      let myVote = null;
      if (loginUser) {
        const record = await db.prepare(`
          SELECT vote_type FROM ban_vote_records WHERE vote_id = ? AND user_id = ?
        `).bind(voteId, loginUser.uid).first();
        if (record) myVote = record.vote_type;
      }

      return jsonResp({
        id: vote.id,
        targetUserId: vote.target_user_id,
        targetUserName: vote.target_name || '未知用户',
        targetUserRole: vote.target_role,
        initiatorName: vote.initiator_name || '未知用户',
        reason: vote.reason,
        yesCount: vote.yes_count,
        noCount: vote.no_count,
        status: vote.status,
        durationHours: vote.duration_hours,
        endTime: toUTC8Time(vote.end_time),
        createTime: toUTC8Time(vote.created_at),
        myVote
      });
    }

    // 发起投票
    if (request.method === 'POST' && action === 'create') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);

      // 检查是否被禁言
      const isBanned = await checkUserBanned(db, loginUser.uid);
      if (isBanned) return jsonResp({ code: 98, msg: '你已被禁言，无法发起投票' }, 403);

      // 检查权限：admin/owner 不能被放逐
      const { targetUserId, reason, durationHours } = await request.json();
      
      const targetUser = await db.prepare(`
        SELECT id, username, role, ban_until FROM users WHERE id = ?
      `).bind(targetUserId).first();
      
      if (!targetUser) return jsonResp({ code: 1, msg: '用户不存在' });
      
      if (['admin', 'owner'].includes(targetUser.role)) {
        return jsonResp({ code: 1, msg: '不能放逐管理员和站长' });
      }

      // 不能放逐自己
      if (targetUserId === loginUser.uid) {
        return jsonResp({ code: 1, msg: '不能放逐自己' });
      }

      // 检查该用户是否已经有进行中的投票
      const existing = await db.prepare(`
        SELECT id FROM ban_votes WHERE target_user_id = ? AND status = 'active'
      `).bind(targetUserId).first();
      if (existing) {
        return jsonResp({ code: 1, msg: '该用户已有进行中的投票' });
      }

      // 检查发起人今天是否已经发起过投票
      const todayStart = new Date();
      todayStart.setHours(0, 0, 0, 0);
      const todayVotes = await db.prepare(`
        SELECT COUNT(*) as count FROM ban_votes WHERE initiator_id = ? AND created_at >= ?
      `).bind(loginUser.uid, todayStart.toISOString()).first();
      
      if (todayVotes.count >= 1 && !['admin', 'owner'].includes(loginUser.role)) {
        return jsonResp({ code: 1, msg: '每天只能发起一次放逐投票' });
      }

      // 理由不能为空
      if (!reason || !reason.trim()) {
        return jsonResp({ code: 1, msg: '请填写放逐理由' });
      }
      if (reason.length > 200) {
        return jsonResp({ code: 1, msg: '理由不能超过200字' });
      }

      // 禁言时长（默认24小时，最大72小时）
      const duration = Math.min(Math.max(durationHours || 24, 1), 72);

      // 投票结束时间：24小时后
      const endTime = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

      const result = await db.prepare(`
        INSERT INTO ban_votes (target_user_id, initiator_id, reason, duration_hours, end_time)
        VALUES (?, ?, ?, ?, ?)
      `).bind(targetUserId, loginUser.uid, reason.trim(), duration, endTime).run();

      // 发起人自动投支持票
      const voteId = result.meta.last_row_id;
      await db.prepare(`
        INSERT INTO ban_vote_records (vote_id, user_id, vote_type)
        VALUES (?, ?, 'yes')
      `).bind(voteId, loginUser.uid).run();
      
      await db.prepare(`
        UPDATE ban_votes SET yes_count = yes_count + 1 WHERE id = ?
      `).bind(voteId).run();

      return jsonResp({ code: 0, msg: '发起成功', id: voteId });
    }

    // 投票
    if (request.method === 'POST' && action === 'vote') {
      if (!loginUser) return jsonResp({ code: 99, msg: '请先登录' }, 401);

      // 检查是否被禁言
      const isBanned = await checkUserBanned(db, loginUser.uid);
      if (isBanned) return jsonResp({ code: 98, msg: '你已被禁言，无法投票' }, 403);

      const { voteId, voteType } = await request.json();
      
      if (!['yes', 'no'].includes(voteType)) {
        return jsonResp({ code: 1, msg: '投票类型错误' });
      }

      // 检查投票是否存在且在进行中
      const vote = await db.prepare(`
        SELECT id, status FROM ban_votes WHERE id = ?
      `).bind(voteId).first();
      
      if (!vote) return jsonResp({ code: 1, msg: '投票不存在' });
      if (vote.status !== 'active') {
        return jsonResp({ code: 1, msg: '投票已结束' });
      }

      // 检查是否已经投过票
      const existing = await db.prepare(`
        SELECT id, vote_type FROM ban_vote_records WHERE vote_id = ? AND user_id = ?
      `).bind(voteId, loginUser.uid).first();

      if (existing) {
        // 已经投过票，不能改票
        return jsonResp({ code: 1, msg: '你已经投过票了' });
      }

      // 记录投票
      await db.prepare(`
        INSERT INTO ban_vote_records (vote_id, user_id, vote_type)
        VALUES (?, ?, ?)
      `).bind(voteId, loginUser.uid, voteType).run();

      // 更新票数
      if (voteType === 'yes') {
        await db.prepare(`UPDATE ban_votes SET yes_count = yes_count + 1 WHERE id = ?`)
          .bind(voteId).run();
      } else {
        await db.prepare(`UPDATE ban_votes SET no_count = no_count + 1 WHERE id = ?`)
          .bind(voteId).run();
      }

      return jsonResp({ code: 0, msg: '投票成功' });
    }

    return jsonResp({ code: 99, msg: '接口不存在' }, 404);
  } catch (e) {
    console.error("陶片放逐接口捕获异常：", e);
    return jsonResp({ code: 500, msg: '服务器错误：' + e.message, err: e.message }, 500);
  }
}