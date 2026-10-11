// A SAML IdP on Cloudflare Workers with Postgres (Neon) through Hyperdrive: Better Auth's API and
// the plugin's endpoints under /api/auth, and two small pages (/ and /sign-in).
import { AsyncLocalStorage } from "node:async_hooks";
import { Hono } from "hono";
import { Pool } from "pg";
import { type AuthEnv, buildAuth } from "./auth.ts";
import { APP_JS, homePage, signInPage } from "./pages.ts";

type Env = AuthEnv & { HYPERDRIVE: Hyperdrive };

/** What belongs to one request: its connections, and the work Better Auth leaves running. */
interface RequestScope {
  pool: Pool;
  background: Promise<unknown>[];
}
const scope = new AsyncLocalStorage<RequestScope>();

/**
 * The pool Better Auth is given: each query uses the current request's own pool. A connection
 * can't be used by another request on Workers, but Better Auth and the plugin are built once per
 * isolate (building them costs about 25 ms of CPU), so they reach the request's pool through here.
 */
const requestPool = {
  connect() {
    const current = scope.getStore();
    if (!current) throw new Error("[example] database used outside a request");
    return current.pool.connect();
  },
  // Each request ends its own pool (below).
  async end() {},
} as unknown as Pool;

function runInBackground(task: Promise<unknown>) {
  const current = scope.getStore();
  if (current) current.background.push(task);
  else void task.catch(() => {});
}

/** One instance per origin and configuration (the entity ID follows the host). */
const instances = new Map<string, ReturnType<typeof buildAuth>>();
function authFor(env: Env, origin: string) {
  const key = `${origin}\n${env.SAML_SERVICE_PROVIDERS}\n${env.SAML_IDP_CERT}`;
  let auth = instances.get(key);
  if (!auth) {
    if (instances.size >= 8) instances.clear();
    auth = buildAuth(env, origin, requestPool, runInBackground);
    instances.set(key, auth);
  }
  return auth;
}

const app = new Hono<{ Bindings: Env }>();

app.use("*", async (c, next) => {
  await next();
  // Pages load only /app.js; nothing may frame them. The plugin sets its own headers on SAML pages.
  if (!c.req.path.startsWith("/api/")) {
    c.header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Referrer-Policy", "no-referrer");
  }
});

app.on(["GET", "POST"], "/api/auth/*", (c) => {
  // This request's pool. Workers allow six open connections per request; Hyperdrive keeps the
  // real connections to the database and hands this pool fast local ones.
  const current: RequestScope = { pool: new Pool({ connectionString: c.env.HYPERDRIVE.connectionString, max: 5 }), background: [] };
  return scope.run(current, async () => {
    try {
      return await authFor(c.env, new URL(c.req.url).origin).handler(c.req.raw);
    } finally {
      // Close the pool after the response, once the work Better Auth left running is done.
      c.executionCtx.waitUntil(
        (async () => {
          while (current.background.length) await Promise.allSettled(current.background.splice(0));
          await current.pool.end();
        })(),
      );
    }
  });
});

app.get("/", (c) => {
  const origin = new URL(c.req.url).origin;
  const sps = (JSON.parse(c.env.SAML_SERVICE_PROVIDERS || "[]") as { id: string; entityId: string }[]).map((sp) => sp.id);
  return c.html(homePage(origin, sps));
});
app.get("/sign-in", (c) => c.html(signInPage()));
app.get("/app.js", (c) => c.body(APP_JS, 200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-cache" }));

export default app;
