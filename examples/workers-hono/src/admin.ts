// The example's admin pages for the SAML IdP, built only on the plugin's public API: the registry
// API (list/create/update/delete stored SPs), the tenant API (tenants and their signing keys),
// serviceProviderFromMetadata, and the audit table. The plugin itself ships no UI (like
// @better-auth/sso); copy and adapt these for your own app.
//
// Access: signed-in users listed in SAML_REGISTRY_ADMINS with a verified email, the same rule
// as the registry's canManage. Everything user-controlled is rendered with textContent (stored
// SP configs are data, never markup), under a CSP that allows no inline code.
import { X509Certificate } from "node:crypto";
import { serviceProviderFromMetadata, SpMetadataError } from "better-auth-saml-idp";
import type { Context, Hono } from "hono";
import { type Env, type getAuth, hasProvisioning, idpInitiatedApps, isRegistryAdmin, provisioningTargets } from "./auth";
import { card, copy, esc, head, htmlResponse, kv, page, type Viewer } from "./ui/layout";

type C = Context<{ Bindings: Env }>;
type Auth = ReturnType<typeof getAuth>;

/** The signed-in admin, or a Response to send instead (sign-in redirect, or 403). */
async function requireAdmin(c: C, auth: Auth): Promise<{ email: string } | Response> {
  const session = await auth.api.getSession({ headers: c.req.raw.headers, query: { disableCookieCache: true } });
  if (!session) return c.redirect(`/sign-in?callbackURL=${encodeURIComponent(new URL(c.req.url).pathname)}`);
  // The user as the database has it now (a demotion or ban applies at once), and never an admin
  // acting as someone else: the registry API refuses impersonated sessions too.
  const user = (await (await auth.$context).internalAdapter.findUserById(session.user.id)) as { email: string; emailVerified?: boolean; banned?: boolean } | null;
  const impersonated = Boolean((session.session as { impersonatedBy?: string | null }).impersonatedBy);
  if (!user || user.banned || impersonated || !isRegistryAdmin(c.env, user)) {
    const viewer: Viewer = { email: session.user.email, admin: false };
    return htmlResponse(
      page({
        title: "Not allowed",
        active: "",
        viewer,
        provisioning: hasProvisioning(c.env),
        content: head("Not an administrator") + card("Why", `<p>${esc(session.user.email)} isn't in <code>SAML_REGISTRY_ADMINS</code>, its email isn't verified, or this is an impersonated session.</p><p><a href="/">Back to your apps</a></p>`),
      }),
      403,
    );
  }
  return { email: user.email };
}

/** Same-origin JSON POSTs only (the page's own fetches). */
const sameOrigin = (c: C) => c.req.header("origin") === new URL(c.req.url).origin;

function certSummary(pem: string) {
  try {
    const cert = new X509Certificate(pem);
    const days = Math.floor((new Date(cert.validTo).getTime() - Date.now()) / 86_400_000);
    return { subject: cert.subject.replace(/\n/g, ", "), validTo: new Date(cert.validTo).toISOString().slice(0, 10), days, sha256: cert.fingerprint256 };
  } catch {
    return undefined;
  }
}

export function registerAdmin(app: Hono<{ Bindings: Env }>, authFor: (c: C) => Auth, withCf: <T>(c: C, fn: () => T) => T) {
  // The IdP's public certificate, as a file for SP setup forms (it's in the metadata anyway).
  app.get("/admin/idp.crt", (c: C) =>
    new Response(c.env.SAML_IDP_CERT, { headers: { "content-type": "application/x-pem-file", "content-disposition": 'attachment; filename="idp.crt"' } }),
  );

  // The same metadata, as a named .xml file for SP setup forms that want an upload (Salesforce,
  // AWS). The plugin's own URL stays extension-less: SPs fetch it, and its content type says XML.
  app.get("/admin/idp-metadata.xml", (c: C) =>
    withCf(c, async () => {
      const res = await authFor(c).handler(new Request(new URL("/api/auth/saml2/idp/metadata", c.req.url)));
      if (!res.ok) return res;
      return new Response(await res.text(), {
        headers: { "content-type": "application/samlmetadata+xml; charset=utf-8", "content-disposition": 'attachment; filename="idp-metadata.xml"' },
      });
    }),
  );

  // Turn an SP's metadata XML into a config the page can review and save.
  app.post("/admin/api/from-metadata", (c: C) =>
    withCf(c, async () => {
      const admin = await requireAdmin(c, authFor(c));
      if (admin instanceof Response) return c.json({ error: "not allowed" }, 403);
      if (!sameOrigin(c)) return c.json({ error: "cross-origin" }, 403);
      if (Number(c.req.header("content-length") ?? 0) > 1_100_000) return c.json({ error: "metadata too large" }, 413);
      const body = (await c.req.json().catch(() => null)) as { xml?: unknown; id?: unknown } | null;
      if (!body || typeof body.xml !== "string" || typeof body.id !== "string" || body.xml.length > 1_000_000) return c.json({ error: "send { id, xml }" }, 400);
      try {
        const r = await serviceProviderFromMetadata(body.xml, { id: body.id });
        return c.json({ serviceProvider: r.serviceProvider, encryptionCertificates: r.encryptionCertificates, warnings: r.warnings });
      } catch (e) {
        return c.json({ error: e instanceof SpMetadataError ? e.message : "could not read the metadata" }, 400);
      }
    }),
  );

  // One-time step after upgrading a registry that already had stored SPs to tenants (migration
  // 0008): gives those rows their lookup key, or they aren't found. Safe to run again.
  app.post("/admin/api/backfill", (c: C) =>
    withCf(c, async () => {
      const auth = authFor(c);
      const admin = await requireAdmin(c, auth);
      if (admin instanceof Response) return c.json({ error: "not allowed" }, 403);
      if (!sameOrigin(c)) return c.json({ error: "cross-origin" }, 403);
      // Mounted only with tenants on (they are, in this example).
      const backfill = auth.api.samlIdpBackfillServiceProviderKeys;
      if (!backfill) return c.json({ error: "tenants aren't enabled" }, 404);
      return c.json(await backfill());
    }),
  );

  // Organization names for the tenant list (tenant records carry the organization id only).
  app.get("/admin/api/organizations", (c: C) =>
    withCf(c, async () => {
      const auth = authFor(c);
      const admin = await requireAdmin(c, auth);
      if (admin instanceof Response) return c.json({ error: "not allowed" }, 403);
      const ctx = await auth.$context;
      const rows = (await ctx.adapter.findMany({ model: "organization", sortBy: { field: "name", direction: "asc" }, limit: 500 })) as { id: string; name: string; slug: string }[];
      return c.json({ organizations: rows.map(({ id, name, slug }) => ({ id, name, slug })) });
    }),
  );

  // Recent audit events (auditLog is on in this example).
  app.get("/admin/api/audit", (c: C) =>
    withCf(c, async () => {
      const auth = authFor(c);
      const admin = await requireAdmin(c, auth);
      if (admin instanceof Response) return c.json({ error: "not allowed" }, 403);
      const ctx = await auth.$context;
      const rows = (await ctx.adapter.findMany({ model: "samlIdpAuditEvent", sortBy: { field: "at", direction: "desc" }, limit: 50 })) as Record<string, unknown>[];
      // Emails for the users named (one query; 50 ids at most, within D1's 100 bound parameters).
      const ids = [...new Set(rows.map((r) => r.userId).filter((v): v is string => typeof v === "string"))];
      const users = ids.length ? ((await ctx.adapter.findMany({ model: "user", where: [{ field: "id", value: ids, operator: "in" }], limit: ids.length })) as { id: string; email: string }[]) : [];
      const emails = new Map(users.map((u) => [u.id, u.email]));
      return c.json({ events: rows.map(({ type, at, spId, userId, code, details, tenantId }) => ({ type, at, spId, userId, email: typeof userId === "string" ? emails.get(userId) : undefined, code, details, tenantId })) });
    }),
  );

  registerPages(app, authFor, withCf);
}

const table = (cols: string[], tbodyId: string, loading = "Loading…") =>
  `<table class="table"><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody id="${tbodyId}"><tr><td colspan="${cols.length}" class="empty">${esc(loading)}</td></tr></tbody></table>`;

function registerPages(app: Hono<{ Bindings: Env }>, authFor: (c: C) => Auth, withCf: <T>(c: C, fn: () => T) => T) {
  /** An admin page: the guard, then the layout around `content`. */
  const adminPage = (path: string, title: string, script: string, content: (c: C, auth: Auth) => Promise<string> | string, data?: (c: C) => unknown) =>
    app.get(path, (c: C) =>
      withCf(c, async () => {
        const auth = authFor(c);
        const admin = await requireAdmin(c, auth);
        if (admin instanceof Response) return admin;
        return htmlResponse(page({ title, active: path, viewer: { email: admin.email, admin: true }, script, content: await content(c, auth), data: data?.(c), provisioning: hasProvisioning(c.env) }));
      }),
    );

  adminPage("/admin", "Overview", "overview", async (c, auth) => {
    const idp = `${new URL(c.req.url).origin}/api/auth/saml2/idp`;
    const cert = certSummary(c.env.SAML_IDP_CERT);
    // Sign-ins and refusals in the last day, counted in the audit log (not just the recent page).
    const ctx = await auth.$context;
    const since = new Date(Date.now() - 86_400_000);
    const count = (type: string) => ctx.adapter.count({ model: "samlIdpAuditEvent", where: [{ field: "type", value: type }, { field: "at", value: since, operator: "gt" }] }).catch(() => 0);
    const [signIns, denied] = await Promise.all([count("assertion.issued"), count("denied")]);
    const tile = (label: string, value: string, id?: string, note?: string) =>
      `<div class="tile"><span class="muted small">${esc(label)}</span><span class="stat"${id ? ` id="${id}"` : ""}>${esc(value)}</span>${note ? `<span class="muted small">${note}</span>` : ""}</div>`;
    const certNote = cert ? (cert.days < 30 ? `<span class="note bad">expires in ${cert.days} days</span>` : `<span class="muted">expires ${esc(cert.validTo)} (${cert.days} days)</span>`) : "";
    return (
      head("Overview", "This identity provider: what service providers need to trust it, and what it's been doing.") +
      `<div class="tiles">${tile("Active service providers", "…", "countSps", '<a href="/admin/sps">Manage</a>')}${tile("Tenants", "…", "countTenants", '<a href="/admin/tenants">Manage</a>')}${tile("Sign-ins, last 24 hours", String(signIns))}${tile("Refused, last 24 hours", String(denied), undefined, denied ? '<a href="/admin/activity">See why</a>' : "")}</div>` +
      `<div class="top"></div>` +
      card(
        "This identity provider",
        kv([
          ["Entity ID (Issuer)", copy(idp)],
          ["Single sign-on URL", copy(`${idp}/sso`)],
          ["Single logout URL", copy(`${idp}/slo`)],
          ["Metadata URL", copy(`${idp}/metadata`, true)],
          ...(cert ? ([["Certificate", `${esc(cert.subject)}<div class="small">${certNote}</div>`], ["SHA-256 fingerprint", `<code class="break">${esc(cert.sha256)}</code>`]] as [string, string][]) : []),
        ]) +
          `<div class="row top"><a class="button" href="/admin/idp-metadata.xml">Download metadata (.xml)</a><a class="button ghost" href="/admin/idp.crt">Download certificate (.crt)</a></div>`,
        { subtitle: "What service providers ask for when you set them up. Most take the metadata URL; the downloads are for forms that want a file." },
      ) +
      card("Recent activity", table(["When", "Event", "Service provider", "User", "Detail"], "recent"), { actions: '<a class="button ghost small" href="/admin/activity">All activity</a>' })
    );
  });

  adminPage(
    "/admin/sps",
    "Service providers",
    "sps",
    () =>
      head("Service providers", "The apps this IdP signs people in to. From code (<code>SAML_SERVICE_PROVIDERS</code>, read-only here) and from the database registry (editable).") +
      card("Service providers", table(["Service provider", "Entity ID", "Tenant", "Status", ""], "sps")) +
      `<section class="card" id="editor" hidden><div class="card-head"><h2 id="editorTitle">Edit</h2></div>
<label class="field"><span>Configuration</span><textarea id="cfg" class="code" spellcheck="false"></textarea><small class="muted">JSON, the same shape as a <code>serviceProviders</code> entry, without functions.</small></label>
<label class="check"><input id="enabled" type="checkbox"> Enabled (used for sign-in)</label>
<div class="row"><button id="save" type="button">Save</button><button id="cancel" type="button" class="ghost">Cancel</button></div></section>` +
      card(
        "Add a service provider",
        `<div class="inline"><label class="field"><span>ID</span><input id="newId" placeholder="salesforce"><small class="muted">Letters, digits, <code>-</code> and <code>_</code>.</small></label></div>
<label class="field"><span>The SP's metadata XML</span><textarea id="xml" class="code short" spellcheck="false" placeholder="&lt;md:EntityDescriptor …"></textarea><small class="muted">Most SPs offer a "download metadata" link. It's converted into a configuration you review before saving.</small></label>
<div class="row"><button id="convert" type="button">Convert to a configuration</button><button id="blank" type="button" class="ghost">Start from empty JSON</button></div>
<ul id="convertWarnings" class="issues"></ul>`,
        { subtitle: 'Step-by-step guides for <a href="https://github.com/mmcintosh/better-auth-saml-idp/blob/main/docs/guide/README.md#sp-guides" target="_blank" rel="noopener">real service providers</a>.' },
      ),
    (c) => ({ codeLaunchable: idpInitiatedApps(c.env) }),
  );

  adminPage(
    "/admin/tenants",
    "Tenants",
    "tenants",
    () =>
      head("Tenants", "An organization made a tenant gets its own IdP: its own entity ID, metadata, sign-in and logout URLs, and signing key. Its SPs are stored SPs with <code>\"tenant\": \"&lt;organization id&gt;\"</code> in their configuration.") +
      card("Tenants", table(["Organization", "Entity ID", "Signing keys", "Status", ""], "tenants"), {
        subtitle: "Keys rotate in three steps: <b>Rotate</b> publishes a next key, <b>Activate</b> makes it sign (after 24 hours, so SPs have fetched it; <i>force</i> for a leaked key), <b>Retire</b> stops publishing the old one.",
      }) +
      card(
        "New tenant",
        `<div class="inline"><label class="field"><span>Organization name</span><input id="orgName" placeholder="Acme Corp"></label><label class="field"><span>Slug (also the tenant key)</span><input id="orgSlug" placeholder="acme"></label><button id="createTenant" type="button">Create tenant</button></div>`,
        { subtitle: "Creates an organization (you become its owner) and makes it a tenant with a new key. The tenant key is in its URLs and entity ID, which SPs pin: it never changes." },
      ) +
      card("Upgrading an older registry", `<p class="muted">If this deployment's registry had stored SPs before tenants existed (migration 0008), run this once, or those SPs aren't found.</p><button id="backfill" type="button" class="ghost">Backfill SP lookup keys</button>`),
  );

  adminPage(
    "/admin/activity",
    "Activity",
    "activity",
    () =>
      head("Activity", "From the audit log: sign-ins, refusals, logouts and ended sessions, newest first. Refusals before anyone signs in aren't stored (anyone can cause them); they're logged as warnings instead.") +
      card("The last 50 events", table(["When", "Event", "Service provider", "User", "Detail"], "audit")),
  );

  // ---- Provisioning (better-auth-scim-provisioning), when a target is configured ----

  // The page's earlier address (the SCIM field test's /admin/scim) keeps working.
  app.get("/admin/scim", (c: C) => c.redirect("/admin/provisioning", 301));

  adminPage(
    "/admin/provisioning",
    "Users and apps",
    "provisioning",
    (c) => {
      if (!hasProvisioning(c.env))
        return head("Provisioning", "Provisioning is off.") + card("Turn it on", `<p>Set a target (<code>SCIM_URL</code> and <code>SCIM_TOKEN</code>, or the <code>GOOGLE_*</code> settings), apply migration 0011, and list who may be provisioned. See the example's README.</p>`);
      return (
        head("Users and apps", "Accounts at the apps, kept in step by better-auth-scim-provisioning: created before the first sign-in, updated, and switched off when someone leaves.") +
        `<div class="tiles" id="targets"></div><div class="top"></div>` +
        card("Users", `<div class="table-wrap">${table(["User", "Status", "At each app", ""], "users")}</div><div class="row between top"><span class="muted small" id="usersNote"></span><div class="row"><button type="button" class="ghost small" id="prev">Previous</button><button type="button" class="ghost small" id="next">Next</button></div></div>`, {
          subtitle: "Changes here go to the apps at once; anything that fails is retried by the scheduled run.",
          actions: '<button type="button" class="ghost small" id="refresh">Refresh</button>',
        }) +
        card(
          "Add a test user",
          `<div class="inline"><label class="field"><span>Email</span><input id="newEmail" type="email" placeholder="ada@example.com"></label><label class="field"><span>Name</span><input id="newName" placeholder="Ada Lovelace"></label><button type="button" id="create">Create verified user</button></div><p class="muted small">Only addresses in a target's allowed list are provisioned there.</p>`,
        ) +
        card("Queue", `<p class="muted" id="queueNote">…</p><div class="inline"><button type="button" id="run">Run the queue now</button><label class="field"><span>Reconcile from (cursor)</span><input id="cursor" placeholder="start"></label><button type="button" class="ghost" id="reconcile">Reconcile a page</button></div>`, {
          subtitle: "The scheduled run delivers what's due every minute. Reconcile queues every user (and group) again, a page at a time: after adding or fixing a target.",
        }) +
        card("Groups", table(["Group", "App", "Kind", "Id at the app"], "groups"), { subtitle: "Organizations (and roles) as groups at the apps, with the provisioned members." })
      );
    },
    (c) => ({ targets: provisioningTargets(c.env).map((t) => ({ id: t.id, type: t.type ?? "scim", groups: !!t.groups, where: t.type === "google-workspace" ? "Google Workspace" : (() => { try { return new URL(t.url ?? "").host; } catch { return ""; } })() })) }),
  );

  app.get("/admin/api/provisioning", (c: C) =>
    withCf(c, async () => {
      const auth = authFor(c);
      const admin = await requireAdmin(c, auth);
      if (admin instanceof Response) return c.json({ error: "not allowed" }, 403);
      if (!hasProvisioning(c.env)) return c.json({ error: "provisioning is off" }, 404);
      const ctx = await auth.$context;
      const offset = Math.max(0, Number(c.req.query("offset") ?? 0) || 0);
      const users = (await ctx.adapter.findMany({ model: "user", sortBy: { field: "email", direction: "asc" }, limit: 26, offset })) as { id: string; email: string; name: string; emailVerified?: boolean; banned?: boolean; banExpires?: Date | null }[];
      const page = users.slice(0, 25);
      const ids = page.map((u) => u.id);
      const [links, jobs] = ids.length
        ? await Promise.all([
            ctx.adapter.findMany({ model: "scimProvisioningLink", where: [{ field: "userId", value: ids, operator: "in" }], limit: 200 }) as Promise<{ userId: string; targetId: string; remoteId: string; active: boolean }[]>,
            ctx.adapter.findMany({ model: "scimProvisioningJob", where: [{ field: "userId", value: ids, operator: "in" }], limit: 200 }) as Promise<{ userId: string; targetId: string; kind?: string | null; attempts: number; failed: boolean; lastError?: string | null; nextAttemptAt: Date }[]>,
          ])
        : [[], []];
      const groups = (await ctx.adapter.findMany({ model: "scimProvisioningGroupLink", limit: 100 })) as { key: string; targetId: string; displayName: string; remoteId: string }[];
      const count = (failed: boolean) => ctx.adapter.count({ model: "scimProvisioningJob", where: [{ field: "failed", value: failed }] }).catch(() => 0);
      const [queued, failed] = await Promise.all([count(false), count(true)]);
      return c.json({
        offset,
        more: users.length > 25,
        users: page.map((u) => ({
          id: u.id,
          email: u.email,
          name: u.name,
          verified: u.emailVerified === true,
          banned: u.banned === true && (!u.banExpires || new Date(u.banExpires).getTime() > Date.now()),
          you: u.email === admin.email,
          links: Object.fromEntries(links.filter((l) => l.userId === u.id).map((l) => [l.targetId, { remoteId: l.remoteId, active: l.active, pending: !l.remoteId }])),
          jobs: Object.fromEntries(jobs.filter((j) => j.userId === u.id && !j.kind).map((j) => [j.targetId, { attempts: j.attempts, failed: j.failed, lastError: j.lastError ?? null, next: j.nextAttemptAt }])),
        })),
        groups: groups.map((g) => ({ targetId: g.targetId, displayName: g.displayName, remoteId: g.remoteId, kind: g.key.slice(g.targetId.length + 1).split(":")[0] })),
        queue: { queued, failed },
      });
    }),
  );

  app.post("/admin/api/provisioning", (c: C) =>
    withCf(c, async () => {
      const auth = authFor(c);
      const admin = await requireAdmin(c, auth);
      if (admin instanceof Response) return c.json({ error: "not allowed" }, 403);
      if (!sameOrigin(c)) return c.json({ error: "cross-origin" }, 403);
      if (!hasProvisioning(c.env)) return c.json({ error: "provisioning is off" }, 404);
      const body = (await c.req.json().catch(() => null)) as Record<string, unknown> | null;
      const str = (k: string) => (typeof body?.[k] === "string" ? (body[k] as string).trim() : "");
      const ctx = await auth.$context;
      const action = str("action");
      const userId = str("userId");
      const user = userId ? ((await ctx.internalAdapter.findUserById(userId)) as { id: string; email: string } | null) : null;
      if (["rename", "email", "ban", "unban", "delete", "password", "resync"].includes(action)) {
        if (!user) return c.json({ error: "no such user" }, 404);
        // Never lock the admin out: no banning or deleting yourself here.
        if ((action === "ban" || action === "delete") && user.email === admin.email) return c.json({ error: "that's your own account" }, 400);
      }
      switch (action) {
        case "create": {
          const email = str("email").toLowerCase();
          if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return c.json({ error: "enter an email address" }, 400);
          if (await ctx.internalAdapter.findUserByEmail(email)) return c.json({ error: "a user with that email exists" }, 409);
          await ctx.internalAdapter.createUser({ email, name: str("name") || email, emailVerified: true }, { method: "admin" } as never);
          return c.json({ ok: `Created ${email}.` });
        }
        case "rename":
          if (!str("name")) return c.json({ error: "enter a name" }, 400);
          await ctx.internalAdapter.updateUser(userId, { name: str("name") });
          return c.json({ ok: "Renamed." });
        case "email": {
          const email = str("email").toLowerCase();
          if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return c.json({ error: "enter an email address" }, 400);
          await ctx.internalAdapter.updateUser(userId, { email, emailVerified: true });
          return c.json({ ok: `Email changed to ${email}.` });
        }
        case "ban":
          await ctx.internalAdapter.updateUser(userId, { banned: true, banReason: "banned on /admin/provisioning", banExpires: null });
          return c.json({ ok: "Banned: deactivated at the apps." });
        case "unban":
          await ctx.internalAdapter.updateUser(userId, { banned: false, banReason: null, banExpires: null });
          return c.json({ ok: "Unbanned: active at the apps again." });
        case "delete":
          await ctx.internalAdapter.deleteUser(userId);
          return c.json({ ok: "Deleted: deprovisioned at the apps." });
        case "password": {
          // So a test user can sign in through the IdP (users made here have no password).
          const password = str("password");
          if (password.length < 12) return c.json({ error: "at least 12 characters" }, 400);
          const hash = await ctx.password.hash(password);
          const accounts = (await ctx.internalAdapter.findAccounts(userId)) as { id: string; providerId: string }[];
          const credential = accounts.find((a) => a.providerId === "credential");
          if (credential) await ctx.internalAdapter.updateAccount(credential.id, { password: hash });
          else await ctx.internalAdapter.createAccount({ userId, providerId: "credential", accountId: userId, password: hash });
          return c.json({ ok: "Password set." });
        }
        case "resync":
          // Any change queues the user for every target: the plugin's hooks do the rest.
          await ctx.internalAdapter.updateUser(userId, { updatedAt: new Date() });
          return c.json({ ok: "Queued for every app." });
        case "run": {
          const r = await auth.api.scimProvisioningRun({ body: {} });
          return c.json({ ok: `Delivered: ${r.done} done, ${r.retry} to retry, ${r.failed} failed, ${r.busy} busy.` });
        }
        case "reconcile": {
          const r = await auth.api.scimProvisioningReconcile({ body: { limit: 200, ...(str("after") ? { after: str("after") } : {}) } });
          return c.json({ ok: `Queued ${r.queued}.${r.next ? " More to go: run it again from the cursor below." : " All done."}`, next: r.next });
        }
        default:
          return c.json({ error: "unknown action" }, 400);
      }
    }),
  );
}
