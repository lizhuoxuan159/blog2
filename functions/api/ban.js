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
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

// 统一会话工具（和user、post完全一致）
function getSessionCookie(request) {
    const cookieRaw = request.headers.get("cookie") || "";
    const cookieMap = Object.fromEntries(cookieRaw.split("; ").map(item => item.split("=")));
    return cookieMap.sid || null;
}

async function verifySessionToken(token, secret) {
    const { createHmac } = await import("crypto");
    const [uid, sig] = token.split(".");
    if (!uid || !sig) return null;
    const realSig = createHmac("sha256", secret).update(uid).digest("hex");
    return sig === realSig ? Number(uid) : null;
}

async function getLoginUser(request, secret, db) {
    const sid = getSessionCookie(request);
    if (!sid) return null;
    const uid = await verifySessionToken(sid, secret);
    if (!uid) return null;
    const user = await db.prepare(`SELECT id, username, role, ban_until FROM users WHERE id = ?`).bind(uid).first();
    if (!user) return null;
    return {
        uid: user.id,
        username: user.username,
        role: user.role,
        ban_until: user.ban_until
    };
}

// 检查并结算到期的投票
async function checkAndSettleVotes(db) {
    const now = new Date().toISOString();
    const activeVotes = await db.prepare(`
    SELECT id, target_user_id, yes_count, no_count, duration_hours
    FROM ban_votes
    WHERE status = 'active' AND end_time <= ?
  `).bind(now).all();
    for (const vote of activeVotes.results) {
        const passed = vote.yes_count >= 10 && vote.yes_count > vote.no_count;
        if (passed) {
            await db.prepare(`UPDATE ban_votes SET status = 'passed' WHERE id = ?`).bind(vote.id).run();
            const banUntil = new Date(Date.now() + vote.duration_hours * 60 * 60 * 1000).toISOString();
            await db.prepare(`UPDATE users SET ban_until = ? WHERE id = ?`).bind(banUntil, vote.target_user_id).run();
        } else {
            await db.prepare(`UPDATE ban_votes SET status = 'failed' WHERE id = ?`).bind(vote.id).run();
        }
    }
}

// 检查用户是否被禁言
async function checkUserBanned(db, userId) {
    const user = await db.prepare(`SELECT role, ban_until FROM users WHERE id = ?`).bind(userId).first();
    if (!user) return false;
    if (user.role === 'banned') return true;
    if (user.ban_until) {
        const banUntil = new Date(user.ban_until).getTime();
        if (banUntil > Date.now()) {
            return true;
        } else {
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
        const HMAC_SALT = env.SESSION_HMAC_SECRET;
        const SITE_URL = env.SITE_ORIGIN;

        // 跨域预检
        if (request.method === "OPTIONS") {
            return new Response("", {
                headers: {
                    "Access-Control-Allow-Origin": SITE_URL,
                    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type"
                }
            })
        }

        const loginUser = await getLoginUser(request, HMAC_SALT, env.DB);
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
            const isBanned = await checkUserBanned(db, loginUser.uid);
            if (isBanned) return jsonResp({ code: 98, msg: '你已被禁言，无法发起投票' }, 403);
            const { targetUserId, reason, durationHours } = await request.json();
            const targetUser = await db.prepare(`
        SELECT id, username, role, ban_until FROM users WHERE id = ?
      `).bind(targetUserId).first();
            if (!targetUser) return jsonResp({ code: 1, msg: '用户不存在' });
            if (['admin', 'owner'].includes(targetUser.role)) {
                return jsonResp({ code: 1, msg: '不能放逐管理员和站长' });
            }
            if (targetUserId === loginUser.uid) {
                return jsonResp({ code: 1, msg: '不能放逐自己' });
            }
            const existing = await db.prepare(`
        SELECT id FROM ban_votes WHERE target_user_id = ? AND status = 'active'
      `).bind(targetUserId).first();
            if (existing) {
                return jsonResp({ code: 1, msg: '该用户已有进行中的投票' });
            }
            const todayStart = new Date();
            todayStart.setHours(0, 0, 0, 0);
            const todayVotes = await db.prepare(`
        SELECT COUNT(*) as count FROM ban_votes WHERE initiator_id = ? AND created_at >= ?
      `).bind(loginUser.uid, todayStart.toISOString()).first();
            if (todayVotes.count >= 1 && !['admin', 'owner'].includes(loginUser.role)) {
                return jsonResp({ code: 1, msg: '每天只能发起一次放逐投票' });
            }
            if (!reason || !reason.trim()) {
                return jsonResp({ code: 1, msg: '请填写放逐理由' });
            }
            if (reason.length > 200) {
                return jsonResp({ code: 1, msg: '理由不能超过200字' });
            }
            const duration = Math.min(Math.max(durationHours || 24, 1), 72);
            const endTime = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
            const result = await db.prepare(`
        INSERT INTO ban_votes (target_user_id, initiator_id, reason, duration_hours, end_time)
        VALUES (?, ?, ?, ?, ?)
      `).bind(targetUserId, loginUser.uid, reason.trim(), duration, endTime).run();
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
            const isBanned = await checkUserBanned(db, loginUser.uid);
            if (isBanned) return jsonResp({ code: 98, msg: '你已被禁言，无法投票' }, 403);
            const { voteId, voteType } = await request.json();
            if (!['yes', 'no'].includes(voteType)) {
                return jsonResp({ code: 1, msg: '投票类型错误' });
            }
            const vote = await db.prepare(`
        SELECT id, status FROM ban_votes WHERE id = ?
      `).bind(voteId).first();
            if (!vote) return jsonResp({ code: 1, msg: '投票不存在' });
            if (vote.status !== 'active') {
                return jsonResp({ code: 1, msg: '投票已结束' });
            }
            const existing = await db.prepare(`
        SELECT id, vote_type FROM ban_vote_records WHERE vote_id = ? AND user_id = ?
      `).bind(voteId, loginUser.uid).first();
            if (existing) {
                return jsonResp({ code: 1, msg: '你已经投过票了' });
            }
            await db.prepare(`
        INSERT INTO ban_vote_records (vote_id, user_id, vote_type)
        VALUES (?, ?, ?)
      `).bind(voteId, loginUser.uid, voteType).run();
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
