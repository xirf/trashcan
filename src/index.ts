import { Elysia, t } from "elysia";
import { html } from "@elysiajs/html";
import { randomBytes, createHash } from "crypto";
import sanitizeHtml from "sanitize-html";
import { db } from "./db/schema";

const SESSION_COOKIE = "session_id";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme";
const RATE_LIMIT_WINDOW_MINUTES = 5;
const DAILY_SALT = new Date().toISOString().slice(0, 10);

const app = new Elysia()
  .use(html())
  .derive(({ request, cookie }) => {
    let session = cookie?.[SESSION_COOKIE];
    if (!session) {
      session = randomBytes(16).toString("hex");
      cookie.set(SESSION_COOKIE, session, {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        path: "/",
        maxAge: 60 * 60 * 24 * 365,
      });
    }
    const ip =
      request.headers.get("x-forwarded-for") ||
      request.headers.get("x-real-ip") ||
      request.headers.get("cf-connecting-ip") ||
      request.headers.get("x-client-ip") ||
      request.headers.get("forwarded") ||
      request.headers.get("remote-addr") ||
      "unknown";
    const ipHash = createHash("sha256")
      .update(`${DAILY_SALT}:${ip}`)
      .digest("hex");
    return { session, ipHash };
  })
  .guard(
    {
      query: t.Optional(
        t.Object({
          admin: t.Optional(t.String()),
        })
      ),
    },
    ({ query }) => {
      const isAdmin = query?.admin === ADMIN_PASSWORD;
      return { isAdmin };
    }
  )
  .get("/", ({ set, html, isAdmin }) => {
    const posts = db
      .query<Post>(
        "SELECT * FROM posts WHERE status='active' ORDER BY datetime(created_at) DESC"
      )
      .all();
    set.headers["Content-Type"] = "text/html; charset=utf-8";
    return html(renderPage(posts, isAdmin));
  })
  .post(
    "/post",
    ({ body, session, ipHash, set }) => {
      const text = sanitize(body?.text || "");
      if (!text.trim()) {
        set.status = 400;
        return { error: "Empty body" };
      }
      if (isRateLimited(ipHash)) {
        set.status = 429;
        return { error: "Too many posts. Please wait a bit." };
      }
      db.query(
        "INSERT INTO posts (body, session_id, ip_hash, status) VALUES (?1, ?2, ?3, 'active')"
      ).run(text, session, ipHash);
      db.query("INSERT INTO rate_limits (ip_hash) VALUES (?1)").run(ipHash);
      return { ok: true };
    },
    {
      body: t.Object({
        text: t.String(),
      }),
    }
  )
  .post(
    "/react/:id/:type",
    ({ params, set }) => {
      const { id, type } = params;
      if (type !== "hug" && type !== "care") {
        set.status = 400;
        return { error: "Invalid reaction" };
      }
      const column = type === "hug" ? "hugs" : "cares";
      db.query(`UPDATE posts SET ${column} = ${column} + 1 WHERE id = ?1`).run(
        Number(id)
      );
      return { ok: true };
    },
    {
      params: t.Object({
        id: t.String(),
        type: t.String(),
      }),
    }
  )
  .post(
    "/delete/:id",
    ({ params, session, set }) => {
      const { id } = params;
      db.query(
        "UPDATE posts SET status='deleted' WHERE id = ?1 AND session_id = ?2"
      ).run(Number(id), session);
      return { ok: true };
    },
    {
      params: t.Object({
        id: t.String(),
      }),
    }
  )
  .post(
    "/admin/delete/:id",
    ({ params, isAdmin, set }) => {
      if (!isAdmin) {
        set.status = 401;
        return { error: "Unauthorized" };
      }
      const { id } = params;
      db.query("UPDATE posts SET status='deleted' WHERE id = ?1").run(
        Number(id)
      );
      return { ok: true };
    },
    {
      params: t.Object({
        id: t.String(),
      }),
    }
  )
  .get("/admin", ({ isAdmin, set }) => {
    if (!isAdmin) {
      set.status = 401;
      return "Unauthorized";
    }
    const posts = db
      .query<Post>("SELECT * FROM posts ORDER BY datetime(created_at) DESC")
      .all();
    set.headers["Content-Type"] = "text/html; charset=utf-8";
    return renderAdmin(posts);
  })
  .listen(3000);

function sanitize(input: string) {
  return sanitizeHtml(input, {
    allowedTags: [],
    allowedAttributes: {},
  });
}

function isRateLimited(ipHash: string) {
  const since = new Date(Date.now() - RATE_LIMIT_WINDOW_MINUTES * 60 * 1000)
    .toISOString()
    .slice(0, 19)
    .replace("T", " ");
  const row = db
    .query(
      "SELECT COUNT(*) as count FROM rate_limits WHERE ip_hash = ?1 AND datetime(created_at) >= datetime(?2)"
    )
    .get(ipHash, since) as { count: number };
  return row.count > 0;
}

function renderPage(posts: Post[], isAdmin: boolean) {
  const banner =
    '<div class="bg-red-100 text-red-900 p-3 rounded mb-4 text-sm">If you are struggling, please seek help. Share kindly and avoid harmful content.</div>';
  const form = `<form hx-post="/post" hx-trigger="submit" hx-target="#feed" hx-swap="outerHTML">
    <textarea name="text" class="w-full border p-2 rounded mb-2" rows="3" placeholder="Share your thoughts..."></textarea>
    <button class="bg-blue-600 text-white px-4 py-2 rounded" type="submit">Post</button>
  </form>`;
  const feed = renderFeed(posts, isAdmin);
  return `<!doctype html>
  <html>
    <head>
      <meta charset="utf-8" />
      <title>Anon Vent</title>
      <script src="https://unpkg.com/htmx.org@1.9.10"></script>
      <link href="https://cdn.jsdelivr.net/npm/tailwindcss@3.4.1/dist/tailwind.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-100 text-slate-900">
      <div class="max-w-2xl mx-auto p-4">
        <h1 class="text-2xl font-bold mb-3">Anonymous Vent Board</h1>
        ${banner}
        ${form}
        <div id="feed">${feed}</div>
      </div>
    </body>
  </html>`;
}

function renderFeed(posts: Post[], isAdmin: boolean) {
  if (!posts.length) {
    return `<div class="text-sm text-slate-500">No posts yet. Share something.</div>`;
  }
  return posts
    .map((p) => {
      const actions = `
        <button hx-post="/react/${p.id}/hug" hx-swap="outerHTML" class="text-sm text-pink-700">🤗 Hug (${p.hugs})</button>
        <button hx-post="/react/${p.id}/care" hx-swap="outerHTML" class="text-sm text-orange-700 ml-3">❤️ Care (${p.cares})</button>
        <button hx-post="/delete/${p.id}" hx-target="#post-${p.id}" hx-swap="outerHTML" class="text-sm text-slate-500 ml-3">Delete</button>
        ${
          isAdmin
            ? `<button hx-post="/admin/delete/${p.id}" hx-target="#post-${p.id}" hx-swap="outerHTML" class="text-sm text-red-500 ml-3">Admin Delete</button>`
            : ""
        }
      `;
      return `<div id="post-${p.id}" class="bg-white border rounded p-3 mb-2">
        <div class="text-sm whitespace-pre-wrap">${p.body}</div>
        <div class="mt-2 flex items-center gap-2">${actions}</div>
      </div>`;
    })
    .join("");
}

function renderAdmin(posts: Post[]) {
  return `<!doctype html>
  <html>
    <head>
      <meta charset="utf-8" />
      <title>Admin</title>
      <script src="https://unpkg.com/htmx.org@1.9.10"></script>
      <link href="https://cdn.jsdelivr.net/npm/tailwindcss@3.4.1/dist/tailwind.min.css" rel="stylesheet">
    </head>
    <body class="bg-slate-100 text-slate-900">
      <div class="max-w-3xl mx-auto p-4">
        <h1 class="text-2xl font-bold mb-4">Admin</h1>
        ${renderFeed(posts, true)}
      </div>
    </body>
  </html>`;
}
