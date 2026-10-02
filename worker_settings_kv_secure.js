/**
 * Cloudflare Worker：播放列表 + 门禁（密码仅存服务端）
 *
 * 绑定：
 *   PLAYLIST_KV          KV 命名空间
 * 密钥 / 变量：
 *   ADMIN_PASSWORD       后台管理密码（必填）
 *   WATCH_PASSWORD       观看门禁密码（可选；也可用后台写入 KV）
 *
 * 安全约定：
 *   - 公开接口永不返回 watchPass
 *   - 门禁校验只走 POST /api/watch/verify
 *   - 管理密码只与 env.ADMIN_PASSWORD 比对
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const cors = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, PUT, POST, OPTIONS",
    };
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    const json = (obj, status = 200) =>
      new Response(JSON.stringify(obj), {
        status,
        headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" },
      });

    const bearer = () => {
      const h = request.headers.get("Authorization") || "";
      return h.startsWith("Bearer ") ? h.slice(7) : "";
    };

    const authed = async () => {
      const token = bearer();
      if (!token || token.length > 200) return false;
      return !!(await env.PLAYLIST_KV.get("admin_token:" + token));
    };

    const readSettings = async () => {
      try {
        const raw = await env.PLAYLIST_KV.get("settings");
        return raw ? JSON.parse(raw) : {};
      } catch {
        return {};
      }
    };

    /** 门禁密码：优先 KV（后台可改），否则环境变量 WATCH_PASSWORD / VIP_PASSWORD */
    const resolveWatchPass = async () => {
      const s = await readSettings();
      const fromKv = String(s.watchPass || "").trim();
      if (fromKv) return fromKv;
      return String(env.WATCH_PASSWORD || env.VIP_PASSWORD || "").trim();
    };

    const isVipEnabled = async () => {
      const s = await readSettings();
      if (typeof s.vipEnabled === "boolean") return s.vipEnabled;
      // 未写过设置时：若配置了任一密码源则默认开启门禁
      const pass = await resolveWatchPass();
      return !!pass;
    };

    const timingSafeEqual = (a, b) => {
      const ea = new TextEncoder().encode(String(a));
      const eb = new TextEncoder().encode(String(b));
      const n = Math.max(ea.length, eb.length);
      let diff = ea.length === eb.length ? 0 : 1;
      for (let i = 0; i < n; i++) diff |= (ea[i] || 0) ^ (eb[i] || 0);
      return diff === 0;
    };

    const sha256Hex = async (s) => {
      const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
      return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
    };

    // ---------- 公开：播放列表 ----------
    if (path === "/api/playlist" && request.method === "GET") {
      const raw = await env.PLAYLIST_KV.get("playlist");
      let data = [];
      try {
        data = raw ? JSON.parse(raw) : [];
      } catch {
        data = [];
      }
      return json({ data: Array.isArray(data) ? data : [] });
    }

    // ---------- 公开：设置（绝不返回密码）----------
    if (path === "/api/settings" && request.method === "GET") {
      const s = await readSettings();
      const vipEnabled = await isVipEnabled();
      const hasWatchPass = !!(await resolveWatchPass());
      return json({
        vipEnabled,
        hasWatchPass,
        autoNext: s.autoNext !== false,
        loop: !!s.loop,
        nightMode: !!s.nightMode,
        dataSaver: !!s.dataSaver,
        updatedAt: s.updatedAt || null,
      });
    }

    // ---------- 公开：门禁验证（密码只在服务端比对）----------
    if (path === "/api/watch/verify" && request.method === "POST") {
      const vipOn = await isVipEnabled();
      if (!vipOn) {
        // 门禁关闭：直接放行
        const token = crypto.randomUUID();
        return json({ ok: true, token, ttl: 86400, vipEnabled: false });
      }
      const expected = await resolveWatchPass();
      if (!expected) {
        return json({ ok: false, error: "服务端未配置观看密码（WATCH_PASSWORD 或后台设置）" }, 503);
      }
      let body = {};
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "无效请求" }, 400);
      }
      const password = String(body.password || "");
      if (!password || password.length > 128) {
        return json({ ok: false, error: "密码错误，无法播放" }, 401);
      }
      if (!timingSafeEqual(password, expected)) {
        return json({ ok: false, error: "密码错误，无法播放" }, 401);
      }
      const token = await sha256Hex(expected + "|" + crypto.randomUUID() + "|" + Date.now());
      // 可选：把会话记入 KV，便于服务端吊销
      try {
        await env.PLAYLIST_KV.put("watch_session:" + token, "1", { expirationTtl: 86400 });
      } catch (_) {}
      return json({ ok: true, token, ttl: 86400, vipEnabled: true });
    }

    // ---------- 管理登录（ADMIN_PASSWORD 环境变量）----------
    if (path === "/api/admin/login" && request.method === "POST") {
      let body = {};
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "无效请求" }, 400);
      }
      const password = String(body.password || "");
      const admin = String(env.ADMIN_PASSWORD || "");
      if (!admin) return json({ ok: false, error: "服务端未配置 ADMIN_PASSWORD" }, 503);
      if (!password || !timingSafeEqual(password, admin)) {
        return json({ ok: false, error: "密码错误" }, 401);
      }
      const token = crypto.randomUUID();
      await env.PLAYLIST_KV.put("admin_token:" + token, "1", { expirationTtl: 7 * 86400 });
      return json({ ok: true, token });
    }

    // ---------- 写播放列表 ----------
    if (path === "/api/admin/playlist" && request.method === "PUT") {
      if (!(await authed())) return json({ ok: false, error: "未授权" }, 401);
      const list = await request.json();
      if (!Array.isArray(list)) return json({ ok: false, error: "格式错误" }, 400);
      await env.PLAYLIST_KV.put("playlist", JSON.stringify(list));
      return json({ ok: true, count: list.length });
    }

    // ---------- 管理：读/写设置 ----------
    if (path === "/api/admin/settings") {
      if (!(await authed())) return json({ ok: false, error: "未授权" }, 401);

      if (request.method === "GET") {
        const s = await readSettings();
        return json({
          vipEnabled: await isVipEnabled(),
          hasWatchPass: !!(await resolveWatchPass()),
          // 管理端也不回传明文密码，只表示是否已设置
          watchPassSet: !!(s.watchPass || env.WATCH_PASSWORD || env.VIP_PASSWORD),
          autoNext: s.autoNext !== false,
          loop: !!s.loop,
          nightMode: !!s.nightMode,
          dataSaver: !!s.dataSaver,
          updatedAt: s.updatedAt || null,
        });
      }

      if (request.method === "PUT") {
        const body = await request.json();
        const prev = await readSettings();
        const settings = {
          vipEnabled: body.vipEnabled !== undefined ? !!body.vipEnabled : !!prev.vipEnabled,
          // 仅当传入非空字符串时更新密码；传空字符串可清除 KV 密码（回退到环境变量）
          watchPass:
            body.watchPass !== undefined
              ? String(body.watchPass || "")
              : String(prev.watchPass || ""),
          autoNext: body.autoNext !== false,
          loop: !!body.loop,
          nightMode: !!body.nightMode,
          dataSaver: !!body.dataSaver,
          updatedAt: new Date().toISOString(),
        };
        await env.PLAYLIST_KV.put("settings", JSON.stringify(settings));
        return json({
          ok: true,
          settings: {
            vipEnabled: settings.vipEnabled,
            hasWatchPass: !!(settings.watchPass || env.WATCH_PASSWORD || env.VIP_PASSWORD),
            autoNext: settings.autoNext,
            loop: settings.loop,
            nightMode: settings.nightMode,
            dataSaver: settings.dataSaver,
            updatedAt: settings.updatedAt,
          },
        });
      }
    }

    return json({ ok: false, error: "Not found" }, 404);
  },
};
