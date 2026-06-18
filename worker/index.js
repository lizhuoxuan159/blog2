import { Hono } from 'hono'
import { jwt } from 'hono/jwt'
const app = new Hono()

// 全局环境
let DB, JWT_SECRET
app.use('*', async (c, next) => {
  DB = c.env.DB
  JWT_SECRET = c.env.JWT_SECRET
  await next()
})

// 管理员鉴权中间件
const adminGuard = async (c, next) => {
  const authHeader = c.req.header('Authorization')
  if (!authHeader) return c.json({ code: 401, msg: "请先登录" }, 401)
  const token = authHeader.split(' ')[1]
  try {
    const payload = await jwt.verify(token, JWT_SECRET)
    if (!payload.isAdmin) return c.json({ code: 403, msg: "无管理员权限" }, 403)
    c.set("admin", payload)
    await next()
  } catch (err) {
    return c.json({ code: 401, msg: "Token失效，请重新登录" }, 401)
  }
}

// 1. 用户注册
app.post("/api/register", async c => {
  const { username, email, password } = await c.req.json()
  const exist = await DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first()
  if (exist) return c.json({ code: 400, msg: "邮箱已注册" })
  // 简易加密，生产推荐bcrypt
  const pwdHash = btoa(password)
  await DB.prepare(`
    INSERT INTO users (username, email, password, isAdmin, create_time)
    VALUES (?, ?, ?, 0, datetime())
  `).bind(username, email, pwdHash).run()
  return c.json({ code: 200, msg: "注册成功" })
})

// 2. 用户登录颁发JWT
app.post("/api/login", async c => {
  const { email, password } = await c.req.json()
  const user = await DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first()
  if (!user || btoa(password) !== user.password) {
    return c.json({ code: 400, msg: "账号或密码错误" })
  }
  const token = await jwt.sign(
    { id: user.id, username: user.username, isAdmin: user.isAdmin },
    JWT_SECRET,
    { expiresIn: "7d" }
  )
  return c.json({
    code: 200,
    data: { token, user: { id: user.id, username: user.username, isAdmin: user.isAdmin } }
  })
})

// 3. 获取文章列表（公开接口）
app.get("/api/articles", async c => {
  const list = await DB.prepare(`
    SELECT id,title,cover,category,tags,create_time
    FROM articles ORDER BY create_time DESC
  `).all()
  return c.json({ code: 200, data: list.results })
})

// 4. 获取单篇文章详情（Base64封面图存在cover字段）
app.get("/api/article/:id", async c => {
  const id = c.req.param("id")
  const article = await DB.prepare("SELECT * FROM articles WHERE id = ?").bind(id).first()
  return c.json({ code: 200, data: article })
})

// 5. 管理员发布文章（图片转为base64存入D1，替代R2）
app.post("/api/admin/article", adminGuard, async c => {
  const { title, content, coverBase64, category, tags } = await c.req.json()
  await DB.prepare(`
    INSERT INTO articles (title,content,cover,category,tags,create_time)
    VALUES (?,?,?,?,?,datetime())
  `).bind(title, content, coverBase64 || "", category, tags).run()
  return c.json({ code: 200, msg: "文章发布成功" })
})

// 6. 管理员编辑/删除文章、用户管理、评论接口逻辑结构同上
app.put("/api/admin/article/:id", adminGuard, async c => {
  const id = c.req.param("id")
  const { title, content, coverBase64, category, tags } = await c.req.json()
  await DB.prepare(`
    UPDATE articles SET title=?,content=?,cover=?,category=?,tags=? WHERE id=?
  `).bind(title, content, coverBase64, category, tags, id).run()
  return c.json({ code: 200, msg: "更新成功" })
})

app.delete("/api/admin/article/:id", adminGuard, async c => {
  const id = c.req.param("id")
  await DB.prepare("DELETE FROM articles WHERE id = ?").bind(id).run()
  return c.json({ code: 200, msg: "删除完成" })
})

// 7. 评论提交
app.post("/api/comment", async c => {
  const { articleId, userId, content } = await c.req.json()
  await DB.prepare(`
    INSERT INTO comments (article_id,user_id,content,create_time)
    VALUES (?,?,?,datetime())
  `).bind(articleId, userId, content).run()
  return c.json({ code: 200, msg: "评论发表成功" })
})

export default app
