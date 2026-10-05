import { Hono } from "hono";
import { devMailbox, getAuth, idpInitiatedApps, isRegistryAdmin, requestCf, requestWaitUntil, type Env } from "./auth";
import { registerAdmin } from "./admin";
import { signInPage } from "./sign-in";
import { JS } from "./ui/client";
import { card, esc, head, htmlResponse, page, type Viewer } from "./ui/layout";
import { CSS } from "./ui/styles";

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

// The pages' stylesheet and code: same origin, so their CSP allows no inline code.
const asset = (body: string, type: string) => () => new Response(body, { headers: { "content-type": `${type}; charset=utf-8`, "cache-control": "no-cache" } });
app.get("/assets/app.css", asset(CSS, "text/css"));
app.get("/assets/app.js", asset(JS, "text/javascript"));

// A reference admin page for SAML_REGISTRY_ADMINS (src/admin.ts): the IdP's details, the SPs
// (edit, enable, delete, add from metadata), and recent audit events.
registerAdmin(app, authFor as any, withCf as any);

// DEVELOPMENT ONLY (DEV_MAILBOX="true"): read the verification link that would have been emailed.
app.get("/dev/mailbox", (c) => {
  if (c.env.DEV_MAILBOX !== "true") return c.notFound();
  const email = c.req.query("email") ?? "";
  const link = devMailbox.get(email);
  return link ? c.json({ email, link }) : c.json({ email, link: null }, 404);
});

// Home: for a visitor, what this is and a way in; for a signed-in user, the apps they can open
// (IdP-initiated SSO: SPs with "allowIdpInitiated": true) and the tenants' metadata.
app.get("/", (c) =>
  withCf(c, async () => {
    const auth = authFor(c);
    const session = await auth.api.getSession({ headers: c.req.raw.headers });
    const viewer: Viewer = session ? { email: session.user.email, admin: isRegistryAdmin(c.env, session.user) } : null;
    const origin = new URL(c.req.url).origin;
    const ctx = await auth.$context;
    const tenants = (await ctx.adapter.findMany({ model: "samlIdpTenant", where: [{ field: "enabled", value: true }], sortBy: { field: "tenantKey", direction: "asc" }, limit: 100 })) as { tenantKey: string }[];
    const metadata = `${origin}/api/auth/saml2/idp/metadata`;
    let content: string;
    if (!viewer) {
      content =
        head("Better Auth IdP", "A Better Auth app acting as a SAML identity provider: it signs people in to other apps (Cloudflare Access, Google Workspace, AWS, Okta, Salesforce…) with their account here.") +
        card("Sign in", `<p>Sign in, or create an account, to open your apps.</p><div class="row top"><a class="button" href="/sign-in">Sign in</a></div>`) +
        card("For service providers", `<p>This IdP's metadata: <a href="${esc(metadata)}">${esc(metadata)}</a></p>`);
    } else {
      // Apps that allow sign-in started here: from code, and stored (registry) SPs that say so.
      const stored = (await ctx.adapter.findMany({ model: "samlIdpServiceProvider", where: [{ field: "enabled", value: true }], limit: 200 })) as { spId: string; config: string; tenantId?: string }[];
      const storedApps = stored
        .filter((r) => !r.tenantId && (() => { try { return (JSON.parse(r.config) as { allowIdpInitiated?: unknown }).allowIdpInitiated === true; } catch { return false; } })())
        .map((r) => r.spId);
      const apps = [...new Set([...idpInitiatedApps(c.env), ...storedApps])].sort();
      content =
        head("My apps", "Apps you can open from here. Others start the sign-in themselves: go to the app and choose this identity provider.") +
        card(
          "Apps",
          apps.length
            ? `<div class="tiles">${apps.map((id) => `<div class="tile"><strong>${esc(id)}</strong><a class="button small" href="/api/auth/saml2/idp/init?sp=${encodeURIComponent(id)}">Open</a></div>`).join("")}</div>`
            : `<p class="empty">No apps to open from here yet.</p>`,
        ) +
        (tenants.length
          ? card("Tenants", `<ul class="list">${tenants.map((t) => `<li><code>${esc(t.tenantKey)}</code> · <a href="/api/auth/saml2/idp/metadata/${encodeURIComponent(t.tenantKey)}">metadata</a></li>`).join("")}</ul>`, { subtitle: "Each has its own entity ID, metadata and signing key." })
          : "") +
        (viewer.admin ? card("Administration", `<p>Manage service providers, tenants and keys, and see activity.</p><div class="row top"><a class="button" href="/admin">Open the admin</a></div>`) : "");
    }
    return htmlResponse(page({ title: viewer ? "My apps" : "Home", active: "/", viewer, content }));
  }),
);

export function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
}

export default app;
