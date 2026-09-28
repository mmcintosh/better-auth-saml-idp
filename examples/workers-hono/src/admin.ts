// A reference admin page for the SAML IdP, built only on the plugin's public API: the registry
// API (list/create/update/delete stored SPs), serviceProviderFromMetadata, and the audit table.
// The plugin itself ships no UI (like @better-auth/sso); copy and adapt this for your own app.
//
// Access: signed-in users listed in SAML_REGISTRY_ADMINS with a verified email, the same rule
// as the registry's canManage. Everything user-controlled is rendered with textContent (stored
// SP configs are data, never markup), under a nonce CSP with no inline handlers.
import { X509Certificate } from "node:crypto";
import { serviceProviderFromMetadata, SpMetadataError } from "better-auth-saml-idp";
import type { Context, Hono } from "hono";
import { type Env, type getAuth, idpInitiatedApps, isRegistryAdmin } from "./auth";

type C = Context<{ Bindings: Env }>;
type Auth = ReturnType<typeof getAuth>;

const html = (body: string, nonce: string, status = 200) =>
  new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
      "x-frame-options": "DENY",
      "cache-control": "no-store",
    },
  });
const esc = (s: string) => s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
const newNonce = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));

/** The signed-in admin, or a Response to send instead (sign-in redirect, or 403). */
async function requireAdmin(c: C, auth: Auth): Promise<{ email: string } | Response> {
  const session = await auth.api.getSession({ headers: c.req.raw.headers, query: { disableCookieCache: true } });
  if (!session) return c.redirect(`/sign-in?callbackURL=${encodeURIComponent("/admin")}`);
  // The user as the database has it now (a demotion or ban applies at once), and never an admin
  // acting as someone else: the registry API refuses impersonated sessions too.
  const user = (await (await auth.$context).internalAdapter.findUserById(session.user.id)) as { email: string; emailVerified?: boolean; banned?: boolean } | null;
  const impersonated = Boolean((session.session as { impersonatedBy?: string | null }).impersonatedBy);
  if (!user || user.banned || impersonated || !isRegistryAdmin(c.env, user)) {
    const nonce = newNonce();
    return html(
      `<!doctype html><meta charset="utf-8"><title>Not allowed</title><style nonce="${nonce}">body{font:16px system-ui;margin:2rem}</style>` +
        `<h1>Not an administrator</h1><p>${esc(session.user.email)} isn't in <code>SAML_REGISTRY_ADMINS</code>, its email isn't verified, or this is an impersonated session.</p><p><a href="/">Home</a></p>`,
      nonce,
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

  // Recent audit events (auditLog is on in this example).
  app.get("/admin/api/audit", (c: C) =>
    withCf(c, async () => {
      const auth = authFor(c);
      const admin = await requireAdmin(c, auth);
      if (admin instanceof Response) return c.json({ error: "not allowed" }, 403);
      const ctx = await auth.$context;
      const rows = (await ctx.adapter.findMany({ model: "samlIdpAuditEvent", sortBy: { field: "at", direction: "desc" }, limit: 50 })) as Record<string, unknown>[];
      return c.json({ events: rows.map(({ type, at, spId, userId, code, details }) => ({ type, at, spId, userId, code, details })) });
    }),
  );

  app.get("/admin", (c: C) =>
    withCf(c, async () => {
      const auth = authFor(c);
      const admin = await requireAdmin(c, auth);
      if (admin instanceof Response) return admin;
      const origin = new URL(c.req.url).origin;
      const idp = `${origin}/api/auth/saml2/idp`;
      const cert = certSummary(c.env.SAML_IDP_CERT);
      const nonce = newNonce();
      const row = (k: string, v: string) => `<tr><th>${esc(k)}</th><td><code>${esc(v)}</code></td></tr>`;
      return html(PAGE(nonce, {
        who: admin.email,
        idpRows:
          row("Entity ID (Issuer)", idp) +
          row("Single sign-on URL", `${idp}/sso`) +
          row("Single logout URL", `${idp}/slo`) +
          row("Metadata", `${idp}/metadata`) +
          (cert ? row("Certificate", `${cert.subject} · expires ${cert.validTo} (${cert.days} days)`) + row("SHA-256", cert.sha256) : ""),
        codeLaunchable: idpInitiatedApps(c.env),
      }), nonce);
    }),
  );
}

const PAGE = (nonce: string, d: { who: string; idpRows: string; codeLaunchable: string[] }) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>SAML IdP admin</title>
<style nonce="${nonce}">
body{font:15px system-ui;margin:0;color:#1d1d1f;background:#f6f7f9}header{background:#1d2939;color:#fff;padding:.9rem 1.5rem;display:flex;justify-content:space-between;align-items:center}
header a{color:#cfd8e3}main{max-width:72rem;margin:0 auto;padding:1rem 1.5rem 3rem}section{background:#fff;border:1px solid #e3e6ea;border-radius:8px;padding:1rem 1.25rem;margin:1rem 0}
h1{font-size:1.1rem;margin:0}h2{font-size:1.05rem;margin:.2rem 0 .8rem}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.45rem .5rem;border-top:1px solid #eef0f3;vertical-align:top}
th{font-weight:600;white-space:nowrap}code{font-size:.85em;word-break:break-all}.muted{color:#667085}.ok{color:#067647}.bad{color:#b42318}.warn{color:#b54708}
button,.btn{font:inherit;padding:.3rem .7rem;border:1px solid #c9ced6;border-radius:6px;background:#fff;cursor:pointer;text-decoration:none;color:inherit;display:inline-block;margin:0 .2rem .2rem 0}
button.primary{background:#1d4ed8;color:#fff;border-color:#1d4ed8}button.danger{color:#b42318}textarea,input{font:13px ui-monospace,monospace;width:100%;box-sizing:border-box;padding:.5rem;border:1px solid #c9ced6;border-radius:6px}
textarea{min-height:10rem}label{display:block;margin:.6rem 0 .25rem;font-weight:600}#msg{position:sticky;top:0;padding:.5rem 1rem;display:none}#msg.show{display:block}#msg.err{background:#fee4e2}#msg.info{background:#d1fadf}
ul.issues{margin:.2rem 0;padding-left:1.1rem}input.check{width:auto}.pill{font-size:.8em;border-radius:99px;padding:.05rem .5rem;border:1px solid #d0d5dd}
</style></head><body>
<header><h1>SAML IdP admin</h1><span>${esc(d.who)} · <a href="/">Home</a></span></header>
<div id="msg" role="status"></div>
<main>
<section><h2>This identity provider</h2><p class="muted">What service providers ask for when you set them up.</p>
<table>${d.idpRows}</table>
<p><a class="btn" href="/admin/idp-metadata.xml">Download metadata (.xml)</a> <a class="btn" href="/admin/idp.crt">Download certificate (.crt)</a> <a class="btn" href="/api/auth/saml2/idp/metadata" target="_blank" rel="noopener">View metadata</a></p>
<p class="muted">SPs that fetch metadata by URL use the Metadata address above; the download is for SP forms that want a file.</p></section>

<section><h2>Service providers</h2>
<p class="muted">From code (<code>SAML_SERVICE_PROVIDERS</code>, read-only here) and from the database registry (editable).</p>
<table><thead><tr><th>ID</th><th>Entity ID</th><th>Source</th><th>Status</th><th></th></tr></thead><tbody id="sps"><tr><td colspan="5" class="muted">Loading…</td></tr></tbody></table></section>

<section id="editor" hidden><h2 id="editorTitle">Edit</h2>
<label for="cfg">Configuration (JSON, the same shape as a <code>serviceProviders</code> entry, without functions)</label>
<textarea id="cfg" spellcheck="false"></textarea>
<label><input id="enabled" type="checkbox" class="check"> Enabled (used for sign-in)</label>
<p><button id="save" class="primary">Save</button> <button id="cancel">Cancel</button></p></section>

<section><h2>Add a service provider</h2>
<p class="muted">Paste the SP's metadata XML (most SPs offer a “download metadata” link). It is converted into a configuration you can review before saving. Or write the JSON yourself.</p>
<label for="newId">ID (letters, digits, <code>-</code> and <code>_</code>)</label><input id="newId" placeholder="salesforce">
<label for="xml">SP metadata XML</label><textarea id="xml" spellcheck="false" placeholder="&lt;md:EntityDescriptor …"></textarea>
<p><button id="convert">Convert to configuration</button> <button id="blank">Start from empty JSON</button></p>
<ul id="convertWarnings" class="issues warn"></ul></section>

<section><h2>Recent activity</h2><p class="muted">From the audit log: sign-ins, denials, logouts, sessions ended.</p>
<table><thead><tr><th>When</th><th>Event</th><th>SP</th><th>User</th><th>Detail</th></tr></thead><tbody id="audit"><tr><td colspan="5" class="muted">Loading…</td></tr></tbody></table></section>
</main>
<script nonce="${nonce}">
const CODE_LAUNCHABLE = ${JSON.stringify(d.codeLaunchable).replace(/</g, "\\u003c")};
const API = "/api/auth/saml-idp/service-providers";
const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...kids) => { const e = document.createElement(tag); Object.assign(e, props); for (const k of kids) e.append(k); return e; };
let editing = null; // { mode: "create" | "update", id }

function say(text, kind = "info") { const m = $("msg"); m.textContent = text; m.className = "show " + kind; clearTimeout(say.t); say.t = setTimeout(() => (m.className = ""), 6000); }
async function call(path, body) {
  const r = await fetch(path, body === undefined ? { credentials: "include" } : { method: "POST", credentials: "include", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error([j.message || j.error || "HTTP " + r.status, ...(j.issues || [])].join(" — "));
  return j;
}

async function loadSps() {
  const tbody = $("sps");
  try {
    const { serviceProviders } = await call(API);
    tbody.replaceChildren(...serviceProviders.map(row));
    if (!serviceProviders.length) tbody.replaceChildren(el("tr", {}, el("td", { colSpan: 5, className: "muted", textContent: "None yet." })));
  } catch (e) { tbody.replaceChildren(el("tr", {}, el("td", { colSpan: 5, className: "bad", textContent: e.message }))); }
}

function row(sp) {
  const status = el("td");
  status.append(el("span", { className: "pill " + (sp.valid ? (sp.enabled ? "ok" : "muted") : "bad"), textContent: sp.valid ? (sp.enabled ? "active" : "disabled") : "invalid" }));
  const notes = [...sp.issues.map((t) => ["bad", t]), ...sp.warnings.map((t) => ["warn", t])];
  if (notes.length) status.append(el("ul", { className: "issues" }, ...notes.map(([k, t]) => el("li", { className: k, textContent: t }))));
  const actions = el("td");
  const launchable = sp.source === "code" ? CODE_LAUNCHABLE.includes(sp.id) : sp.config && sp.config.allowIdpInitiated === true;
  if (launchable && sp.enabled && sp.valid) actions.append(el("a", { className: "btn", href: "/api/auth/saml2/idp/init?sp=" + encodeURIComponent(sp.id), textContent: "Test sign-in", target: "_blank", rel: "noopener" }));
  if (sp.source === "database") {
    actions.append(el("button", { textContent: "Edit", onclick: () => openEditor("update", sp.id, sp.config, sp.enabled) }));
    // Only the switch: no config sent, so an invalid row can still be disabled.
    actions.append(el("button", { textContent: sp.enabled ? "Disable" : "Enable", onclick: () => toggle(sp.id, !sp.enabled) }));
    actions.append(el("button", { className: "danger", textContent: "Delete", onclick: () => remove(sp.id) }));
  } else actions.append(el("span", { className: "muted", textContent: "defined in code" }));
  const meta = sp.updatedAt ? el("div", { className: "muted", textContent: "updated " + new Date(sp.updatedAt).toLocaleString() }) : "";
  return el("tr", {}, el("td", {}, el("code", { textContent: sp.id }), meta), el("td", {}, el("code", { textContent: sp.entityId })), el("td", { textContent: sp.source }), status, actions);
}

function openEditor(mode, id, config, enabled) {
  editing = { mode, id };
  $("editorTitle").textContent = mode === "create" ? "New service provider: " + id : "Edit " + id;
  $("cfg").value = JSON.stringify(config, null, 2);
  $("enabled").checked = enabled;
  $("editor").hidden = false;
  $("editor").scrollIntoView({ behavior: "smooth" });
}

async function save(id, config, enabled, mode) {
  try {
    if (mode === "create") await call(API + "/create", { serviceProvider: config, enabled });
    else await call(API + "/update", { id, serviceProvider: config, enabled });
    say("Saved " + id + ".");
    $("editor").hidden = true; editing = null;
    await loadSps();
  } catch (e) { say(e.message, "err"); }
}

async function toggle(id, enabled) {
  try { await call(API + "/update", { id, enabled }); say((enabled ? "Enabled " : "Disabled ") + id + "."); await loadSps(); } catch (e) { say(e.message, "err"); }
}

async function remove(id) {
  if (!confirm("Delete service provider " + id + "? Sign-ins to it stop immediately.")) return;
  try { await call(API + "/delete", { id }); say("Deleted " + id + "."); await loadSps(); } catch (e) { say(e.message, "err"); }
}

$("save").onclick = () => {
  let config;
  try { config = JSON.parse($("cfg").value); } catch (e) { return say("The configuration isn't valid JSON: " + e.message, "err"); }
  save(editing.id, config, $("enabled").checked, editing.mode);
};
$("cancel").onclick = () => { $("editor").hidden = true; editing = null; };
$("blank").onclick = () => {
  const id = $("newId").value.trim();
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) return say("Enter an ID first.", "err");
  openEditor("create", id, { id, entityId: "", acsUrls: [""], attributes: { email: "email" } }, true);
};
$("convert").onclick = async () => {
  const id = $("newId").value.trim(), xml = $("xml").value.trim();
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) return say("Enter an ID first.", "err");
  if (!xml) return say("Paste the SP's metadata XML.", "err");
  try {
    const r = await call("/admin/api/from-metadata", { id, xml });
    const config = { ...r.serviceProvider, attributes: r.serviceProvider.attributes || { email: "email" } };
    if (r.encryptionCertificates && r.encryptionCertificates[0]) config.encryption = { certificate: r.encryptionCertificates[0] };
    $("convertWarnings").replaceChildren(...(r.warnings || []).map((w) => el("li", { textContent: w })));
    openEditor("create", id, config, true);
    say("Converted. Review the configuration, then Save.");
  } catch (e) { say(e.message, "err"); }
};

async function loadAudit() {
  const tbody = $("audit");
  try {
    const { events } = await call("/admin/api/audit");
    if (!events.length) return tbody.replaceChildren(el("tr", {}, el("td", { colSpan: 5, className: "muted", textContent: "No events yet." })));
    tbody.replaceChildren(...events.map((e) => {
      let detail = e.code || "";
      try { const d = JSON.parse(e.details || "{}"); detail = [e.code, d.reason, d.detail, d.participants && d.participants.length + " SP(s) not told"].filter(Boolean).join(" · "); } catch {}
      return el("tr", {}, el("td", { textContent: new Date(e.at).toLocaleString() }), el("td", { textContent: e.type }), el("td", { textContent: e.spId || "" }), el("td", {}, el("code", { textContent: e.userId || "" })), el("td", { textContent: detail }));
    }));
  } catch (e) { tbody.replaceChildren(el("tr", {}, el("td", { colSpan: 5, className: "bad", textContent: e.message }))); }
}

loadSps();
loadAudit();
</script></body></html>`;
