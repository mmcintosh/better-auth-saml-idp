import { Hono } from "hono";
import { devMailbox, getAuth, idpInitiatedApps, requestCf, requestWaitUntil, type Env } from "./auth";
import { signInPage } from "./sign-in";

const app = new Hono<{ Bindings: Env }>();

type Ctx = { env: Env; req: { raw: Request; url: string }; executionCtx: { waitUntil(p: Promise<unknown>): void } };
const authFor = (c: Ctx) => getAuth(c.env, new URL(c.req.url).origin);
/** Run `fn` with this request's `cf` visible to the shared auth instance. */
const withCf = <T>(c: Ctx, fn: () => T) =>
  requestWaitUntil.run(
    (p) => c.executionCtx.waitUntil(p),
    () => requestCf.run((c.req.raw as { cf?: IncomingRequestCfProperties }).cf ?? {}, fn),
  );

app.all("/api/auth/*", (c) => withCf(c, () => authFor(c).handler(c.req.raw)));

app.get("/sign-in", (c) => signInPage(c.req.url));

// DEVELOPMENT ONLY (DEV_MAILBOX="true"): read the verification link that would have been emailed.
app.get("/dev/mailbox", (c) => {
  if (c.env.DEV_MAILBOX !== "true") return c.notFound();
  const email = c.req.query("email") ?? "";
  const link = devMailbox.get(email);
  return link ? c.json({ email, link }) : c.json({ email, link: null }, 404);
});

app.get("/", async (c) => {
  const origin = new URL(c.req.url).origin;
  const session = await withCf(c, () => authFor(c).api.getSession({ headers: c.req.raw.headers }));
  const who = session ? `Signed in as ${escapeHtml(session.user.email)}` : "Not signed in";
  // IdP-initiated SSO launcher: SPs with "allowIdpInitiated": true in SAML_SERVICE_PROVIDERS.
  const apps = idpInitiatedApps(c.env);
  const appList = apps.length
    ? `<h2>Apps</h2><ul>${apps
        .map((id) => `<li><a href="/api/auth/saml2/idp/init?sp=${encodeURIComponent(id)}">${escapeHtml(id)}</a></li>`)
        .join("")}</ul>`
    : "";
  return c.html(
    `<!doctype html><meta charset="utf-8"><title>SAML IdP example</title>` +
      `<body style="font:16px system-ui;margin:2rem"><h1>better-auth-saml-idp example</h1><p>${who}</p>` +
      appList +
      `<p>IdP metadata: <a href="/api/auth/saml2/idp/metadata">${origin}/api/auth/saml2/idp/metadata</a></p>` +
      `<p><a href="/sign-in">Sign in / sign up</a></p></body>`,
  );
});

export function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
}

export default app;
