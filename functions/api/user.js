// 哈希加密函数
async function sha256(rawStr) {
  const encoder = new TextEncoder();
  const data = encoder.encode(rawStr);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// JWT格式Base64URL编解码
function base64UrlEncode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}
function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

// 生成会话Token
function createSessionToken(uid, username, role) {
  const payload = {
    uid,
    username,
    role,
    exp: Date.now() + 86400000
  };
  return btoa(JSON.stringify(payload));
}

// 统一JSON返回格式
function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    }
  });
}

// 验证码内存缓存（IP+邮箱 限流，解决非法请求报错）
const codeStorage = new Map();
const CODE_EXPIRE = 5 * 60 * 1000; // 5分钟有效期
const RATE_LIMIT = 60 * 1000; // 同一邮箱1分钟只能请求一次

// Resend.dev 发送验证码核心函数（无需域名校验）
async function sendVerifyCode(targetEmail, code, API_KEY) {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${API_KEY}`,
      "Content-Type": "application/json",
      "User-Agent": "Cloudflare-Workers"
    },
    body: JSON.stringify({
      from: "竹轩博客系统 <notify@resend.dev>",
      to: targetEmail,
      subject: "账号注册登录验证码",
      html: `
        <div style="padding:20px">
          <h3>账号安全验证码</h3>
          <p>您的验证码：<strong style="font-size:22px;color:#2563eb">${code}</strong></p>
          <p>验证码5分钟内有效，请勿向任何人泄露，如非本人操作可忽略本条邮件。</p>
        </div>
      `
    })
  });
  return await res.json();
}

// 生成6位纯数字验证码
function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// 主请求分发入口
export default async function fetchHandler(request, env, ctx) {
  const url = new URL(request.url);
  const pathname = url.pathname;
  const searchParams = url.searchParams;

  // OPTIONS跨域预检
  if (request.method === "OPTIONS") {
    return jsonResp(null);
  }

  // 获取IP用于限流
  const clientIp = request.headers.get("cf-connecting-ip") || "unknown";

  // 验证码获取接口
  if (pathname === "/api/getCode") {
    if (request.method !== "POST") {
      return jsonResp({ code: 400, msg: "请求方式非法" }, 400);
    }
    const body = await request.json().catch(() => null);
    if (!body?.email) {
      return jsonResp({ code: 400, msg: "邮箱参数缺失" }, 400);
    }
    const email = body.email.trim();
    const now = Date.now();

    // 清理过期缓存
    [...codeStorage.entries()].forEach(([key, item]) => {
      if (now > item.expire) codeStorage.delete(key);
    });

    const cacheKey = `${clientIp}_${email}`;
    const cacheItem = codeStorage.get(cacheKey);

    // 频率限制校验，修复非法请求拦截报错
    if (cacheItem && now - cacheItem.createTime < RATE_LIMIT) {
      return jsonResp({ code: 403, msg: "请求过于频繁，请稍后再试" }, 403);
    }

    const verifyCode = generateCode();
    // 存入缓存
    codeStorage.set(cacheKey, {
      code: verifyCode,
      createTime: now,
      expire: now + CODE_EXPIRE
    });

    // 调用resend.dev发信
    const sendResult = await sendVerifyCode(email, verifyCode, env.RESEND_API_KEY);
    if (sendResult.error) {
      return jsonResp({ code: 500, msg: "邮件发送失败", err: sendResult.error.message }, 500);
    }
    return jsonResp({ code: 200, msg: "验证码已发送至邮箱" });
  }

  // 下方保留你原有 GitHub、微软登录/绑定、登录、注册、个人信息 所有路由接口
  // /api/githubLogin、/api/githubCallback、/api/githubBind
  // /api/microsoftLogin、/api/microsoftCallback、/api/microsoftBind
  // 登录、密码修改、用户信息读取接口均可原样沿用，无需改动

  // 404兜底
  return jsonResp({ code: 404, msg: "接口不存在" }, 404);
}
