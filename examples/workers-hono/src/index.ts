import { Hono } from "hono";
import { createAuth, type Env } from "./auth";
import { signInPage } from "./sign-in";

const app = new Hono<{ Bindings: Env }>();

const authFor = (c: { env: Env; req: { raw: Request; url: string } }) =>
  createAuth(c.env, ((c.req.raw as { cf?: IncomingRequestCfProperties }).cf ?? {}) as IncomingRequestCfProperties, new URL(c.req.url).origin);

app.all("/api/auth/*", (c) => authFor(c).handler(c.req.raw));

app.get("/sign-in", (c) => signInPage(c.req.url));

app.get("/", async (c) => {
  const origin = new URL(c.req.url).origin;
  const session = await authFor(c).api.getSession({ headers: c.req.raw.headers });
  const who = session ? `Signed in as ${escapeHtml(session.user.email)}` : "Not signed in";
  return c.html(
    `<!doctype html><meta charset="utf-8"><title>SAML IdP example</title>` +
      `<body style="font:16px system-ui;margin:2rem"><h1>better-auth-saml-idp example</h1><p>${who}</p>` +
      `<p>IdP metadata: <a href="/api/auth/saml2/idp/metadata">${origin}/api/auth/saml2/idp/metadata</a></p>` +
      `<p><a href="/sign-in">Sign in / sign up</a></p></body>`,
  );
});

export function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
}

export default app;
