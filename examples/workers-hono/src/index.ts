import { Hono } from "hono";
import { renderSVG } from "uqr";
import { devMailbox, getAuth, hasProvisioning, idpInitiatedApps, isRegistryAdmin, requestCf, requestWaitUntil, type Env } from "./auth";
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

// Two-step sign-in setup: the authenticator link as a QR code (SVG), drawn here so the key never
// goes to a third-party QR service. Signed-in users only, and only otpauth://totp links.
app.post("/two-step/qr", (c) =>
  withCf(c, async () => {
    const session = await authFor(c).api.getSession({ headers: c.req.raw.headers });
    if (!session) return c.json({ message: "Sign in first" }, 401);
    const { uri } = (await c.req.json().catch(() => ({}))) as { uri?: unknown };
    if (typeof uri !== "string" || uri.length > 512 || !uri.startsWith("otpauth://totp/")) return c.json({ message: "Not an authenticator link" }, 400);
    return new Response(renderSVG(uri, { border: 2 }), { headers: { "content-type": "image/svg+xml", "cache-control": "no-store" } });
  }),
);

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
        twoStepCard(session?.user as { twoFactorEnabled?: unknown } | undefined) +
        passkeysCard((await ctx.adapter.findMany({ model: "passkey", where: [{ field: "userId", value: session?.user.id ?? "" }], sortBy: { field: "createdAt", direction: "asc" }, limit: 20 })) as Passkey[]) +
        (viewer.admin ? card("Administration", `<p>Manage service providers, tenants and keys, and see activity.</p><div class="row top"><a class="button" href="/admin">Open the admin</a></div>`) : "");
    }
    return htmlResponse(page({ title: viewer ? "My apps" : "Home", active: "/", viewer, content, provisioning: hasProvisioning(c.env), ...(viewer ? { script: "home" } : {}) }));
  }),
);

type Passkey = { id: string; name?: string | null; createdAt?: Date | null; deviceType?: string };

/** Passkeys (migration 0013): sign in with a fingerprint, face, PIN or security key instead of a password. */
function passkeysCard(keys: Passkey[]): string {
  const rows = keys
    .map((k) => `<li><strong>${esc(k.name || "Passkey")}</strong> <span class="muted small">${k.deviceType === "multiDevice" ? "synced" : "this device only"}${k.createdAt ? ` · added ${esc(new Date(k.createdAt).toISOString().slice(0, 10))}` : ""}</span> <button class="ghost small" type="button" data-pk-delete="${esc(k.id)}">Remove</button></li>`)
    .join("");
  return card(
    "Passkeys",
    `<p>Sign in with your fingerprint, face, device PIN or a security key instead of a password. A passkey counts as MFA: apps that ask for it, such as Microsoft 365, are told a passkey sign-in was MFA.</p>
${keys.length ? `<ul class="list">${rows}</ul>` : `<p class="muted">No passkeys yet.</p>`}
<form id="pkAdd" class="row top"><input id="pkName" placeholder="Name, e.g. Pixel or YubiKey" maxlength="60"><button type="submit">Add a passkey</button></form>
<p id="pkErr" class="error" role="alert"></p>`,
  );
}

/** Two-step sign-in (migration 0012): turn it on with an authenticator app, or off. */
function twoStepCard(user: { twoFactorEnabled?: unknown } | undefined): string {
  const enabled = [true, 1, "1"].includes(user?.twoFactorEnabled as never);
  return card(
    "Two-step sign-in",
    enabled
      ? `<p>On: signing in takes your password and a code from your authenticator app. Apps that ask for MFA, such as Microsoft 365, are told this sign-in was MFA.</p>
<form id="tfaOff" class="row top"><input id="tfaOffPw" type="password" placeholder="Password" autocomplete="current-password" required><button class="ghost" type="submit">Turn off</button></form>
<p id="tfaErr" class="error" role="alert"></p>`
      : `<p>Off. Turn it on to sign in with your password and a code from an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password…). Apps that ask for MFA, such as Microsoft 365, are then told your sign-in was MFA.</p>
<form id="tfaOn" class="row top"><input id="tfaPw" type="password" placeholder="Password" autocomplete="current-password" required><button type="submit">Turn on</button></form>
<div id="tfaSetup" hidden>
<p>Scan this QR code with your authenticator app (or type in the key below, time-based), then enter the 6-digit code it shows. You'll then be signed out everywhere, and sign in again with your code.</p>
<p><img id="tfaQr" alt="QR code for your authenticator app" width="200" height="200" hidden></p>
<p><code id="tfaSecret" class="break"></code> <button class="ghost small" type="button" id="tfaCopy">Copy key</button></p>
<p class="small"><a id="tfaUri" href="#">Open in authenticator app</a></p>
<form id="tfaVerify" class="row top"><input id="tfaCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required><button type="submit">Verify and turn on</button></form>
<p class="muted small">Backup codes, each usable once (keep them safe): <span id="tfaBackup"></span></p>
</div>
<p id="tfaErr" class="error" role="alert"></p>`,
  );
}

export function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
}

export default {
  fetch: app.fetch,
  /**
   * The Cron Trigger, if you add one (README): with provisioning on, deliver what's due, retries
   * included. Background work it starts runs under this event's waitUntil.
   */
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext) {
    if (!hasProvisioning(env) || !env.PUBLIC_ORIGIN) return;
    const auth = getAuth(env, env.PUBLIC_ORIGIN) as unknown as { api: { scimProvisioningRun(o: { body: object }): Promise<unknown> } };
    const run = requestWaitUntil.run(
      (p) => ctx.waitUntil(p),
      () => auth.api.scimProvisioningRun({ body: {} }),
    );
    ctx.waitUntil(run.then((r) => console.log(`[scim] scheduled run ${JSON.stringify(r)}`)));
  },
} satisfies ExportedHandler<Env>;
