// 公开配置接口：把服务端环境变量中的前端所需配置安全地下发给页面
// 目前用途：hCaptcha 站点密钥（sitekey 本身是公开值，可安全下发）
// 环境变量（Cloudflare 控制台配置，密钥类型亦可，Functions 运行时均可读取）：
//   HCAPTCHA_SITE_KEY —— 首选变量名
//   HCAPTCHA          —— 兼容变量名（首选未设置时使用）
export async function onRequest({ env }) {
    const siteKey = String(env.HCAPTCHA_SITE_KEY || env.HCAPTCHA || "").trim();
    return new Response(JSON.stringify({
        code: 0,
        data: { hcaptchaSiteKey: siteKey }
    }), {
        status: 200,
        headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "public, max-age=60"
        }
    });
}
