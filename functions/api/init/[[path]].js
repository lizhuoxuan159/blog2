// ============================================================
// /api/init/  管理员初始化接口
//
// 功能：
//   1) 幂等创建全部数据表（表已存在时自动跳过）
//   2) 创建站长(owner)账号 / 重置站长密码
//
// 用法：
//   POST /api/init/
//   Content-Type: application/json
//   { "adminname": "admin", "adminpassword": "your_password" }
//
//   GET /api/init/  查看初始化状态（不执行任何写操作）
//
// 安全策略：
//   - 数据库中不存在 owner 时：允许自助初始化（首次部署场景）
//   - 已存在 owner 时：拒绝执行；必须同时携带正确的 initSecret
//     （对应环境变量 INIT_SECRET，用 wrangler secret put 配置）
//     才允许重置站长密码
// ============================================================

// ---------- 建表语句（与 init.sql 保持一致，全部幂等） ----------
const TABLES = [
  `CREATE TABLE IF NOT EXISTS users (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username     TEXT NOT NULL UNIQUE,
  email        TEXT,
  password     TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'guest',
  ban_until    TEXT,
  github_id    TEXT,
  codeforces_id TEXT,
  totp_secret  TEXT,
  is_cancel    INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
)`,
  `CREATE TABLE IF NOT EXISTS posts (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  title        TEXT NOT NULL,
  content      TEXT NOT NULL,
  author_id    INTEGER NOT NULL,
  publish      INTEGER NOT NULL DEFAULT 0,
  publish_time TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
)`,
  `CREATE TABLE IF NOT EXISTS comments (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id    INTEGER NOT NULL,
  user_id    INTEGER NOT NULL,
  content    TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
)`,
  `CREATE TABLE IF NOT EXISTS email_verifications (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  uid       INTEGER NOT NULL DEFAULT 0,
  code      TEXT NOT NULL UNIQUE,
  action    TEXT NOT NULL,
  expire_at TEXT NOT NULL
)`,
  `CREATE TABLE IF NOT EXISTS ban_votes (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  target_user_id  INTEGER NOT NULL,
  initiator_id    INTEGER NOT NULL,
  reason          TEXT NOT NULL,
  yes_count       INTEGER NOT NULL DEFAULT 0,
  no_count        INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'active',
  duration_hours  INTEGER NOT NULL DEFAULT 24,
  end_time        TEXT NOT NULL,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
)`,
  `CREATE TABLE IF NOT EXISTS ban_vote_records (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  vote_id   INTEGER NOT NULL,
  user_id   INTEGER NOT NULL,
  vote_type TEXT NOT NULL,
  UNIQUE (vote_id, user_id)
)`,
  `CREATE TABLE IF NOT EXISTS messages (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL,
  content       TEXT NOT NULL,
  like_count    INTEGER NOT NULL DEFAULT 0,
  comment_count INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
)`,
  `CREATE TABLE IF NOT EXISTS message_likes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id INTEGER NOT NULL,
  user_id    INTEGER NOT NULL,
  UNIQUE (message_id, user_id)
)`,
  `CREATE TABLE IF NOT EXISTS message_comments (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id INTEGER NOT NULL,
  user_id    INTEGER NOT NULL,
  content    TEXT NOT NULL,
  reply_to   INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
)`,
  `CREATE TABLE IF NOT EXISTS private_messages (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id   INTEGER NOT NULL,
  receiver_id INTEGER NOT NULL,
  content     TEXT NOT NULL,
  is_read     INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
)`,
  `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
  `CREATE INDEX IF NOT EXISTS idx_users_gh ON users(github_id)`,
  `CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_id)`,
  `CREATE INDEX IF NOT EXISTS idx_posts_pub ON posts(publish, publish_time)`,
  `CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id)`,
  `CREATE INDEX IF NOT EXISTS idx_email_verif_action ON email_verifications(action, expire_at)`,
  `CREATE INDEX IF NOT EXISTS idx_ban_votes_status ON ban_votes(status, end_time)`,
  `CREATE INDEX IF NOT EXISTS idx_ban_votes_init ON ban_votes(initiator_id, created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_msg_comments_msg ON message_comments(message_id)`,
  `CREATE INDEX IF NOT EXISTS idx_pm_sender ON private_messages(sender_id, receiver_id)`,
  `CREATE INDEX IF NOT EXISTS idx_pm_receiver ON private_messages(receiver_id, is_read)`
];

// ---------- 基础工具（与 user.js 保持一致） ----------
function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}
function success(data = null, msg = "操作成功") {
  return jsonResp({ code: 0, msg, data });
}
function fail(msg = "操作失败", code = 400) {
  return jsonResp({ code, msg, data: null }, code);
}
function handleOptions() {
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400"
    }
  });
}

async function hmacSha256(secret, content) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(content));
  return Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}
async function secureHashPassword(rawStr, hmacSecret) {
  return await hmacSha256(hmacSecret, String(rawStr).trim());
}

async function hasOwner(DB) {
  try {
    const row = await DB.prepare(`SELECT id FROM users WHERE role = 'owner' LIMIT 1`).first();
    return !!row;
  } catch (e) {
    // users 表不存在即视为未初始化
    return false;
  }
}

// 轻量迁移：为旧库补齐新增列（幂等，已存在则跳过）
async function migrateColumns(DB) {
  const wanted = ["codeforces_id"];
  let cols = [];
  try {
    const info = await DB.prepare(`PRAGMA table_info(users)`).all();
    cols = (info?.results || []).map(r => r.name);
  } catch (e) {
    return; // users 表不存在，建表流程会创建
  }
  for (const col of wanted) {
    if (!cols.includes(col)) {
      await DB.prepare(`ALTER TABLE users ADD COLUMN ${col} TEXT`).run();
    }
  }
}

export async function onRequest({ request, env }) {
  try {
    if (request.method === "OPTIONS") return handleOptions();

    const DB = env.DB;
    const SECRET = env.SESSION_HMAC_SECRET;
    if (!DB) return fail("数据库未绑定（DB binding 缺失）", 500);
    if (!SECRET) return fail("SESSION_HMAC_SECRET 未配置", 500);

    // ---------- GET：查询初始化状态 ----------
    if (request.method === "GET") {
      const initialized = await hasOwner(DB);
      if (!initialized) {
        return success({ initialized: false, adminname: null }, "尚未初始化，请 POST 提交 adminname/adminpassword");
      }
      const owner = await DB.prepare(`SELECT username FROM users WHERE role = 'owner' LIMIT 1`).first();
      return success({ initialized: true, adminname: owner?.username || null }, "已初始化");
    }

    if (request.method !== "POST") return fail("仅支持 GET / POST", 405);

    // ---------- POST：执行初始化 / 重置 ----------
    let body;
    try {
      body = await request.json();
    } catch (e) {
      return fail("请求体必须是 JSON：{ adminname, adminpassword }");
    }
    const adminname = String(body.adminname || "").trim();
    const adminpassword = String(body.adminpassword || "");
    const initSecret = String(body.initSecret || "");

    if (!adminname || !adminpassword) return fail("缺少参数：adminname 和 adminpassword 必填");
    if (!/^[a-zA-Z0-9_-]{2,32}$/.test(adminname)) {
      return fail("adminname 只能包含字母、数字、_ 或 -，长度 2-32");
    }
    if (adminpassword.length < 6) return fail("adminpassword 长度至少 6 位");

    const ownerExists = await hasOwner(DB);
    if (ownerExists) {
      // 已初始化：必须携带正确的 INIT_SECRET 才允许重置站长密码
      if (!env.INIT_SECRET || initSecret !== env.INIT_SECRET) {
        return fail("数据库已初始化。如需重置站长密码，请携带正确的 initSecret", 403);
      }
    }

    // 1) 建表（幂等，已存在的表自动跳过）+ 旧库列迁移
    let created = 0;
    for (const sql of TABLES) {
      await DB.prepare(sql).run();
      created++;
    }
    await migrateColumns(DB);

    // 2) 创建站长账号 或 重置站长密码
    //    优先使用数据库中已有的 owner（已初始化场景），
    //    仅未初始化时才使用传入的 adminname 创建新站长
    const hash = await secureHashPassword(adminpassword, SECRET);
    if (ownerExists) {
      const owner = await DB.prepare(`SELECT username FROM users WHERE role = 'owner' ORDER BY id LIMIT 1`).first();
      const res = await DB.prepare(`
        UPDATE users SET password = ? WHERE role = 'owner' AND id = (
          SELECT id FROM users WHERE role = 'owner' ORDER BY id LIMIT 1
        )
      `).bind(hash).run();
      const changed = res?.meta?.changes ?? 0;
      if (!changed) {
        return fail("未能重置站长密码，请重试", 500);
      }
      return success({ adminname: owner?.username || null, tablesEnsured: created }, "站长密码已重置");
    }

    await DB.prepare(`
      INSERT INTO users (username, email, password, role)
      VALUES (?, ?, ?, 'owner')
    `).bind(adminname, null, hash).run();

    return success({ adminname, tablesEnsured: created }, "初始化完成，站长账号已创建");
  } catch (err) {
    console.error("初始化接口异常：", err);
    return fail(`服务器异常：${err.message}`, 500);
  }
}
