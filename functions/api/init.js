function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

export async function onRequest({ request, env }) {
  try {
    const db = env.DB;
    const results = [];

    // ========== 聊天消息表 ==========
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        like_count INTEGER DEFAULT 0,
        comment_count INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `).run();
    results.push('✅ messages 表（聊天消息）已就绪');

    // 迁移：给旧 messages 表加字段
    try {
      await db.prepare(`ALTER TABLE messages ADD COLUMN like_count INTEGER DEFAULT 0`).run();
      results.push('➕ 新增 like_count 字段');
    } catch (e) { /* 已存在，忽略 */ }
    
    try {
      await db.prepare(`ALTER TABLE messages ADD COLUMN comment_count INTEGER DEFAULT 0`).run();
      results.push('➕ 新增 comment_count 字段');
    } catch (e) { /* 已存在，忽略 */ }

    // ========== 聊天评论表 ==========
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS message_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        reply_to INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `).run();
    results.push('✅ message_comments 表（聊天评论）已就绪');

    // ========== 点赞表 ==========
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS message_likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(message_id, user_id)
      )
    `).run();
    results.push('✅ message_likes 表（点赞）已就绪');

    return jsonResp({ 
      code: 0, 
      msg: '数据库初始化完成', 
      results 
    });

  } catch (e) {
    console.error("初始化失败：", e);
    return jsonResp({ code: 500, msg: '初始化失败：' + e.message, err: e.message }, 500);
  }
}