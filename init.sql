-- ============================================================
-- blog2 数据库 Schema（Cloudflare D1 / SQLite）
-- 本文件从 functions/api/*.js 的实际 SQL 反推重建，
-- 用于新环境初始化与结构参考。线上库已存在时无需重复执行。
-- ============================================================

-- ---------- 用户表 ----------
CREATE TABLE IF NOT EXISTS users (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username     TEXT NOT NULL UNIQUE,
  email        TEXT,
  password     TEXT NOT NULL,                -- HMAC-SHA256 散列
  role         TEXT NOT NULL DEFAULT 'guest',-- owner / admin / writer / guest / banned
  ban_until    TEXT,                         -- 禁言截止时间（ISO 字符串），NULL 表示未禁言
  microsoft_id TEXT,                         -- 微软 OAuth 绑定
  github_id    TEXT,                         -- GitHub OAuth 绑定
  totp_secret  TEXT,                         -- 2FA 密钥（Base32），NULL 表示未开启
  is_cancel    INTEGER NOT NULL DEFAULT 0,   -- 1 = 账号已注销
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_ms    ON users(microsoft_id);
CREATE INDEX IF NOT EXISTS idx_users_gh    ON users(github_id);

-- ---------- 文章表 ----------
CREATE TABLE IF NOT EXISTS posts (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  title        TEXT NOT NULL,
  content      TEXT NOT NULL,
  author_id    INTEGER NOT NULL,
  publish      INTEGER NOT NULL DEFAULT 0,   -- 1 = 已发布，0 = 草稿
  publish_time TEXT,                         -- 发布时间（ISO 字符串）
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (author_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_id);
CREATE INDEX IF NOT EXISTS idx_posts_pub    ON posts(publish, publish_time);

-- ---------- 文章评论表 ----------
CREATE TABLE IF NOT EXISTS comments (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id    INTEGER NOT NULL,
  user_id    INTEGER NOT NULL,
  content    TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (post_id) REFERENCES posts(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);

-- ---------- 邮箱验证码表 ----------
-- action: 'register' 注册验证码（uid=0 占位） | 'resetpwd' 密码重置
CREATE TABLE IF NOT EXISTS email_verifications (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  uid       INTEGER NOT NULL DEFAULT 0,
  code      TEXT NOT NULL UNIQUE,
  action    TEXT NOT NULL,
  expire_at TEXT NOT NULL                    -- 过期时间（ISO 字符串）
);
CREATE INDEX IF NOT EXISTS idx_email_verif_action ON email_verifications(action, expire_at);

-- ---------- 放逐投票表 ----------
CREATE TABLE IF NOT EXISTS ban_votes (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  target_user_id  INTEGER NOT NULL,          -- 被投票用户
  initiator_id    INTEGER NOT NULL,          -- 发起人
  reason          TEXT NOT NULL,
  yes_count       INTEGER NOT NULL DEFAULT 0,
  no_count        INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'active', -- active / passed / failed
  duration_hours  INTEGER NOT NULL DEFAULT 24,    -- 通过后的禁言时长（1-72 小时）
  end_time        TEXT NOT NULL,             -- 投票截止时间（ISO 字符串）
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (target_user_id) REFERENCES users(id),
  FOREIGN KEY (initiator_id)   REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_ban_votes_status ON ban_votes(status, end_time);
CREATE INDEX IF NOT EXISTS idx_ban_votes_init   ON ban_votes(initiator_id, created_at);

-- ---------- 放逐投票记录表 ----------
CREATE TABLE IF NOT EXISTS ban_vote_records (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  vote_id   INTEGER NOT NULL,
  user_id   INTEGER NOT NULL,
  vote_type TEXT NOT NULL,                   -- yes / no
  UNIQUE (vote_id, user_id),
  FOREIGN KEY (vote_id) REFERENCES ban_votes(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ---------- 犇犇广场消息表 ----------
CREATE TABLE IF NOT EXISTS messages (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL,
  content       TEXT NOT NULL,
  like_count    INTEGER NOT NULL DEFAULT 0,
  comment_count INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ---------- 消息点赞表 ----------
CREATE TABLE IF NOT EXISTS message_likes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id INTEGER NOT NULL,
  user_id    INTEGER NOT NULL,
  UNIQUE (message_id, user_id),
  FOREIGN KEY (message_id) REFERENCES messages(id),
  FOREIGN KEY (user_id)    REFERENCES users(id)
);

-- ---------- 消息评论表 ----------
CREATE TABLE IF NOT EXISTS message_comments (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id INTEGER NOT NULL,
  user_id    INTEGER NOT NULL,
  content    TEXT NOT NULL,
  reply_to   INTEGER,                       -- 回复的评论 id（可空）
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (message_id) REFERENCES messages(id),
  FOREIGN KEY (user_id)    REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_msg_comments_msg ON message_comments(message_id);

-- ---------- 私聊消息表 ----------
CREATE TABLE IF NOT EXISTS private_messages (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id   INTEGER NOT NULL,
  receiver_id INTEGER NOT NULL,
  content     TEXT NOT NULL,
  is_read     INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (sender_id)   REFERENCES users(id),
  FOREIGN KEY (receiver_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_pm_sender   ON private_messages(sender_id, receiver_id);
CREATE INDEX IF NOT EXISTS idx_pm_receiver ON private_messages(receiver_id, is_read);

-- ---------- 初始站长账号 ----------
-- 默认密码 admin123，登录后请立即修改！
-- 密码散列值由 SESSION_HMAC_SECRET 作为密钥计算，首次部署后建议改密。
INSERT OR IGNORE INTO users (username, email, password, role)
VALUES ('admin', 'admin@example.com', 'PLACEHOLDER_RESET_VIA_APP', 'owner');
