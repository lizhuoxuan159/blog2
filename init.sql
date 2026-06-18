-- 用户表
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  isAdmin INTEGER DEFAULT 0,
  create_time DATETIME
);

-- 文章表 cover 存储base64图片
CREATE TABLE IF NOT EXISTS articles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  cover TEXT,
  category TEXT,
  tags TEXT,
  create_time DATETIME
);

-- 评论表
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  article_id INTEGER,
  user_id INTEGER,
  content TEXT,
  create_time DATETIME
);

-- 分类表
CREATE TABLE IF NOT EXISTS category (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE
);

-- 初始化管理员账号
INSERT INTO users (username,email,password,isAdmin)
VALUES ('admin','admin@blog.com',btoa('123456'),1);
