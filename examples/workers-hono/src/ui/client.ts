// The pages' code, served as /assets/app.js. Each page names its part in <body data-page>, and
// gets its data from <script type="application/json" id="page-data">. Everything user-controlled
// (stored SP configs, names, audit details) goes into the page with textContent: data, never markup.
// Written without template literals, so it can live in this TypeScript string as it is.
export const JS = String.raw`"use strict";
const $ = (id) => document.getElementById(id);
const el = (tag, props, ...kids) => { const e = document.createElement(tag); Object.assign(e, props || {}); for (const k of kids) if (k !== null && k !== undefined && k !== "") e.append(k); return e; };
const pageData = () => { const s = $("page-data"); return s ? JSON.parse(s.textContent || "null") : null; };

function toast(text, kind) {
  const t = $("toast"); if (!t) return;
  t.textContent = text; t.className = "toast" + (kind === "err" ? " err" : ""); t.hidden = false;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => { t.hidden = true; }, kind === "err" ? 9000 : 4500);
}
async function call(path, body) {
  const init = body === undefined ? { credentials: "include" } : { method: "POST", credentials: "include", headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
  const r = await fetch(path, init);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error([j.message || j.error || "HTTP " + r.status].concat(j.issues || []).join(" — "));
  return j;
}
const when = (v) => (v ? new Date(v).toLocaleString() : "");
const pill = (text, tone) => el("span", { className: "pill " + (tone || ""), textContent: text });
const emptyRow = (cols, text, cls) => el("tr", {}, el("td", { colSpan: cols, className: cls || "empty", textContent: text }));

// Everywhere: copy buttons and sign-out.
document.addEventListener("click", async (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  if (b.dataset.copy !== undefined) {
    await navigator.clipboard.writeText(b.dataset.copy);
    const was = b.textContent; b.textContent = "Copied"; setTimeout(() => { b.textContent = was; }, 1200);
  }
  if (b.hasAttribute("data-sign-out")) {
    await fetch("/api/auth/sign-out", { method: "POST", credentials: "include", headers: { "content-type": "application/json" }, body: "{}" });
    location.assign("/");
  }
});

const pages = {};

// ---- Sign in ----
pages["sign-in"] = () => {
  const f = $("signin"), err = $("err"), name = $("nameField");
  let signUp = false;
  const safeCallback = () => { const raw = new URLSearchParams(location.search).get("callbackURL") || "/"; try { const u = new URL(raw, location.origin); return u.origin === location.origin ? u.href : "/"; } catch { return "/"; } };
  $("toggle").onclick = () => {
    signUp = !signUp; name.hidden = !signUp; $("name").required = signUp;
    $("submit").textContent = signUp ? "Create account" : "Sign in";
    $("toggle").textContent = signUp ? "I already have an account" : "Create an account instead";
    $("title").textContent = signUp ? "Create an account" : "Sign in";
    $("passkey").hidden = signUp;
  };
  // Passkey sign-in: the browser's own WebAuthn JSON helpers (Chrome 129+, Firefox 119+, Safari 18+).
  $("passkey").onclick = async () => {
    err.textContent = "";
    if (!window.PublicKeyCredential || !PublicKeyCredential.parseRequestOptionsFromJSON) { err.textContent = "This browser can't use passkeys here. Sign in with your password."; return; }
    try {
      const opts = await call("/api/auth/passkey/generate-authenticate-options");
      const cred = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(opts) });
      await call("/api/auth/passkey/verify-authentication", { response: cred.toJSON() });
      location.assign(safeCallback());
    } catch (x) { err.textContent = x.name === "NotAllowedError" ? "Passkey sign-in was cancelled." : x.message; }
  };
  f.onsubmit = async (e) => {
    e.preventDefault(); err.textContent = ""; $("submit").disabled = true;
    const body = { email: f.email.value, password: f.password.value, callbackURL: safeCallback() };
    if (signUp) body.name = f.name.value || f.email.value;
    const r = await fetch("/api/auth/" + (signUp ? "sign-up" : "sign-in") + "/email", { method: "POST", headers: { "content-type": "application/json" }, credentials: "include", body: JSON.stringify(body) });
    $("submit").disabled = false;
    if (r.ok && signUp) { f.hidden = true; $("sent").hidden = false; return; }
    const j = await r.json().catch(() => ({}));
    // Two-step sign-in: the password was right; now the authenticator-app code.
    if (r.ok && j.twoFactorRedirect) { f.hidden = true; $("code").hidden = false; $("title").textContent = "Two-step sign-in"; $("otp").focus(); return; }
    if (r.ok) { location.assign(safeCallback()); return; }
    err.textContent = j.message || ("Failed (" + r.status + ")");
  };
  $("code").onsubmit = async (e) => {
    e.preventDefault(); $("codeErr").textContent = ""; $("verify").disabled = true;
    const r = await fetch("/api/auth/two-factor/verify-totp", { method: "POST", headers: { "content-type": "application/json" }, credentials: "include", body: JSON.stringify({ code: $("otp").value.trim() }) });
    $("verify").disabled = false;
    if (r.ok) { location.assign(safeCallback()); return; }
    const j = await r.json().catch(() => ({})); $("codeErr").textContent = j.message || ("That code didn't work (" + r.status + ")");
  };
};

// ---- Home: two-step sign-in ----
pages.home = () => {
  const err = $("tfaErr");
  const fail = (e) => { err.textContent = e.message; };
  const on = $("tfaOn");
  if (on) on.onsubmit = async (e) => {
    e.preventDefault(); err.textContent = "";
    try {
      const j = await call("/api/auth/two-factor/enable", { password: $("tfaPw").value });
      const secret = new URL(j.totpURI).searchParams.get("secret") || "";
      $("tfaSecret").textContent = secret; $("tfaCopy").dataset.copy = secret; $("tfaUri").href = j.totpURI;
      $("tfaBackup").textContent = (j.backupCodes || []).join("  ");
      const qr = await fetch("/two-step/qr", { method: "POST", credentials: "include", headers: { "content-type": "application/json" }, body: JSON.stringify({ uri: j.totpURI }) });
      if (qr.ok) { $("tfaQr").src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(await qr.text()); $("tfaQr").hidden = false; }
      on.hidden = true; $("tfaSetup").hidden = false; $("tfaCode").focus();
    } catch (x) { fail(x); }
  };
  const verify = $("tfaVerify");
  if (verify) verify.onsubmit = async (e) => {
    e.preventDefault(); err.textContent = "";
    try {
      await call("/api/auth/two-factor/verify-totp", { code: $("tfaCode").value.trim() });
      // Sign out everywhere, so every session from now on passed the second step.
      await call("/api/auth/revoke-sessions", {});
      location.assign("/sign-in");
    } catch (x) { fail(x); }
  };
  // Passkeys: add one (the browser asks for a fingerprint, face, PIN or security key), or remove one.
  const pk = $("pkAdd"), pkErr = $("pkErr");
  if (pk) pk.onsubmit = async (e) => {
    e.preventDefault(); pkErr.textContent = "";
    if (!window.PublicKeyCredential || !PublicKeyCredential.parseCreationOptionsFromJSON) { pkErr.textContent = "This browser can't create passkeys here."; return; }
    try {
      const opts = await call("/api/auth/passkey/generate-register-options");
      const cred = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(opts) });
      await call("/api/auth/passkey/verify-registration", { response: cred.toJSON(), name: $("pkName").value.trim() || undefined });
      location.reload();
    } catch (x) { pkErr.textContent = x.name === "NotAllowedError" ? "Cancelled." : x.name === "InvalidStateError" ? "This device already has a passkey for this account." : x.message; }
  };
  document.querySelectorAll("[data-pk-delete]").forEach((b) => { b.onclick = async () => {
    pkErr.textContent = "";
    try { await call("/api/auth/passkey/delete-passkey", { id: b.dataset.pkDelete }); location.reload(); } catch (x) { pkErr.textContent = x.message; }
  }; });
  const off = $("tfaOff");
  if (off) off.onsubmit = async (e) => {
    e.preventDefault(); err.textContent = "";
    try { await call("/api/auth/two-factor/disable", { password: $("tfaOffPw").value }); location.reload(); } catch (x) { fail(x); }
  };
};

// ---- Service providers ----
const REGISTRY = "/api/auth/saml-idp/service-providers";
const TENANTS = "/api/auth/saml-idp/tenants";
let tenantNames = new Map();
async function loadTenantNames() {
  try {
    const [t, o] = await Promise.all([call(TENANTS), call("/admin/api/organizations")]);
    tenantNames = new Map(o.organizations.map((x) => [x.id, x.name]));
    return t.tenants;
  } catch { return []; }
}

pages.sps = () => {
  const { codeLaunchable } = pageData();
  let editing = null;
  async function load() {
    const tbody = $("sps");
    try {
      const { serviceProviders } = await call(REGISTRY);
      tbody.replaceChildren(...(serviceProviders.length ? serviceProviders.map(row) : [emptyRow(5, "No service providers yet. Add one below.")]));
    } catch (e) { tbody.replaceChildren(emptyRow(5, e.message, "bad")); }
  }
  function row(sp) {
    const status = el("td", {}, pill(sp.valid ? (sp.enabled ? "active" : "disabled") : "invalid", sp.valid ? (sp.enabled ? "ok" : "") : "bad"));
    const notes = sp.issues.map((t) => ["bad", t]).concat(sp.warnings.map((t) => ["warn", t]));
    if (notes.length) status.append(el("ul", { className: "issues" }, ...notes.map(([k, t]) => el("li", { className: k, textContent: t }))));
    const actions = el("div", { className: "actions" });
    const launchable = sp.source === "code" ? codeLaunchable.includes(sp.id) : sp.config && sp.config.allowIdpInitiated === true;
    if (launchable && sp.enabled && sp.valid) actions.append(el("a", { className: "button ghost small", href: "/api/auth/saml2/idp/init?sp=" + encodeURIComponent(sp.id), textContent: "Test sign-in", target: "_blank", rel: "noopener" }));
    if (sp.source === "database") {
      actions.append(el("button", { className: "ghost small", textContent: "Edit", onclick: () => openEditor("update", sp.id, sp.config, sp.enabled) }));
      actions.append(el("button", { className: "ghost small", textContent: sp.enabled ? "Disable" : "Enable", onclick: () => toggle(sp.id, !sp.enabled) }));
      actions.append(el("button", { className: "danger small", textContent: "Delete", onclick: () => remove(sp.id) }));
    } else actions.append(el("span", { className: "muted small", textContent: "defined in code" }));
    const tenant = sp.tenantId ? tenantNames.get(sp.tenantId) || sp.tenantId : "root";
    return el("tr", {},
      el("td", {}, el("strong", { textContent: sp.id }), el("div", { className: "muted small", textContent: sp.source + (sp.updatedAt ? " · updated " + when(sp.updatedAt) : "") })),
      el("td", { className: "break" }, el("code", { textContent: sp.entityId })),
      el("td", { className: sp.tenantId ? "" : "muted", textContent: tenant }),
      status,
      el("td", {}, actions));
  }
  function openEditor(mode, id, config, enabled) {
    editing = { mode, id };
    $("editorTitle").textContent = mode === "create" ? "New service provider: " + id : "Edit " + id;
    $("cfg").value = JSON.stringify(config, null, 2); $("enabled").checked = enabled;
    $("editor").hidden = false; $("editor").scrollIntoView({ behavior: "smooth" });
  }
  async function save() {
    let config;
    try { config = JSON.parse($("cfg").value); } catch (e) { return toast("The configuration isn't valid JSON: " + e.message, "err"); }
    try {
      if (editing.mode === "create") await call(REGISTRY + "/create", { serviceProvider: config, enabled: $("enabled").checked });
      else await call(REGISTRY + "/update", { id: editing.id, serviceProvider: config, enabled: $("enabled").checked });
      toast("Saved " + editing.id + "."); $("editor").hidden = true; editing = null; await load();
    } catch (e) { toast(e.message, "err"); }
  }
  async function toggle(id, enabled) {
    try { await call(REGISTRY + "/update", { id, enabled }); toast((enabled ? "Enabled " : "Disabled ") + id + "."); await load(); } catch (e) { toast(e.message, "err"); }
  }
  async function remove(id) {
    if (!confirm("Delete service provider " + id + "? Sign-ins to it stop immediately.")) return;
    try { await call(REGISTRY + "/delete", { id }); toast("Deleted " + id + "."); await load(); } catch (e) { toast(e.message, "err"); }
  }
  const idOk = () => { const id = $("newId").value.trim(); if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) { toast("Enter an ID first: 1-64 letters, digits, - and _.", "err"); return null; } return id; };
  $("save").onclick = save;
  $("cancel").onclick = () => { $("editor").hidden = true; editing = null; };
  $("blank").onclick = () => { const id = idOk(); if (id) openEditor("create", id, { id, entityId: "", acsUrls: [""], attributes: { email: "email" } }, true); };
  $("convert").onclick = async () => {
    const id = idOk(); if (!id) return;
    const xml = $("xml").value.trim(); if (!xml) return toast("Paste the SP's metadata XML.", "err");
    try {
      const r = await call("/admin/api/from-metadata", { id, xml });
      const config = Object.assign({}, r.serviceProvider, { attributes: r.serviceProvider.attributes || { email: "email" } });
      if (r.encryptionCertificates && r.encryptionCertificates[0]) config.encryption = { certificate: r.encryptionCertificates[0] };
      $("convertWarnings").replaceChildren(...(r.warnings || []).map((w) => el("li", { className: "warn", textContent: w })));
      openEditor("create", id, config, true); toast("Converted. Review the configuration, then save.");
    } catch (e) { toast(e.message, "err"); }
  };
  loadTenantNames().then(load);
};

// ---- Tenants ----
pages.tenants = () => {
  async function load() {
    const tbody = $("tenants");
    try {
      const tenants = await loadTenantNames();
      tbody.replaceChildren(...(tenants.length ? tenants.map(row) : [emptyRow(5, "No tenants yet.")]));
    } catch (e) { tbody.replaceChildren(emptyRow(5, e.message, "bad")); }
  }
  function row(t) {
    const id = t.organizationId;
    const has = (s) => (t.keys || []).some((k) => k.state === s);
    const keys = el("td", {}, el("div", { className: "muted small", textContent: t.signing === "own" ? "its own key" : "the shared key" }),
      el("ul", { className: "issues" }, ...(t.keys || []).filter((k) => k.state !== "retired").map((k) =>
        el("li", {}, pill(k.state, k.state === "active" ? "ok" : ""), " ", el("code", { textContent: k.kid }), el("span", { className: "muted small", textContent: k.state === "next" ? " · activatable " + when(k.activatableAt) : " · expires " + String(k.notAfter).slice(0, 10) })))));
    if (t.warnings && t.warnings.length) keys.append(el("ul", { className: "issues" }, ...t.warnings.map((w) => el("li", { className: "warn", textContent: w }))));
    const actions = el("div", { className: "actions" });
    const act = (label, fn, cls) => actions.append(el("button", { className: (cls || "ghost") + " small", textContent: label, onclick: fn }));
    if (!has("next")) act("Rotate key", () => tenantCall("/keys/rotate", { organizationId: id }, "Published a next key. SPs pick it up from the metadata; activate it once they have."));
    else {
      act("Activate next key", () => tenantCall("/keys/activate", { organizationId: id }, "The next key signs now."));
      act("Activate now (force)", () => confirm("Activate before SPs have had 24 hours to fetch the new certificate? SPs that haven't will reject sign-ins until they do. Meant for a leaked key.") && tenantCall("/keys/activate", { organizationId: id, force: true }, "The next key signs now (forced)."), "danger");
    }
    if (has("previous")) act("Retire previous key", () => tenantCall("/keys/retire", { organizationId: id }, "The previous key is no longer published, and its private key is erased."));
    act(t.enabled ? "Disable" : "Enable", () => tenantCall("/update", { organizationId: id, enabled: !t.enabled }, (t.enabled ? "Disabled " : "Enabled ") + t.tenantKey + "."));
    act("Delete", () => confirm("Delete tenant " + t.tenantKey + "? Its key is retired for good: no tenant can have its URLs again. Its SPs must be deleted first.") && tenantCall("/delete", { organizationId: id }, "Deleted " + t.tenantKey + "."), "danger");
    return el("tr", {},
      el("td", {}, el("strong", { textContent: tenantNames.get(id) || id }), el("div", {}, el("code", { textContent: t.tenantKey }))),
      el("td", { className: "break" }, el("code", { textContent: t.entityId }), el("div", {}, el("a", { href: t.metadataUrl, target: "_blank", rel: "noopener", textContent: "metadata" }))),
      keys,
      el("td", {}, pill(t.enabled ? "enabled" : "disabled", t.enabled ? "ok" : "")),
      el("td", {}, actions));
  }
  async function tenantCall(path, body, done) {
    try { await call(TENANTS + path, body); toast(done); await load(); } catch (e) { toast(e.message, "err"); }
  }
  $("createTenant").onclick = async () => {
    const name = $("orgName").value.trim(), slug = $("orgSlug").value.trim();
    if (!name) return toast("Enter the organization's name.", "err");
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(slug)) return toast("The slug: 1-64 letters, digits, - and _ (it's also the tenant key in URLs).", "err");
    try {
      const org = await call("/api/auth/organization/create", { name, slug, keepCurrentActiveOrganization: true });
      await call(TENANTS + "/create", { organizationId: org.id, tenantKey: slug });
      $("orgName").value = ""; $("orgSlug").value = "";
      toast("Created tenant " + slug + " with its own signing key."); await load();
    } catch (e) { toast(e.message, "err"); }
  };
  $("backfill").onclick = async () => {
    try {
      const r = await call("/admin/api/backfill", {});
      toast("Backfill: " + r.updated + " SP(s) updated" + (r.skipped.length ? "; skipped: " + r.skipped.join(", ") : "") + (r.failed.length ? "; failed: " + r.failed.join(", ") : "") + ".", r.failed.length ? "err" : "ok");
    } catch (e) { toast(e.message, "err"); }
  };
  load();
};

// ---- Activity (and the overview's recent part) ----
function auditRow(e) {
  let detail = e.code || "";
  try { const d = JSON.parse(e.details || "{}"); detail = [e.code, d.reason, d.detail, d.participants && d.participants.length + " SP(s) not told"].filter(Boolean).join(" · "); } catch {}
  const tone = e.type === "denied" ? "bad" : e.type === "assertion.issued" ? "ok" : "info";
  return el("tr", {}, el("td", { className: "nowrap", textContent: when(e.at) }), el("td", {}, pill(e.type, tone)), el("td", { textContent: e.spId || "" }), el("td", {}, e.email ? el("span", { textContent: e.email, title: e.userId }) : el("code", { textContent: e.userId || "" })), el("td", { textContent: detail }));
}
async function loadAudit(tbodyId, limit) {
  const tbody = $(tbodyId);
  try {
    const { events } = await call("/admin/api/audit");
    const shown = events.slice(0, limit);
    tbody.replaceChildren(...(shown.length ? shown.map(auditRow) : [emptyRow(5, "No events yet.")]));
    return events;
  } catch (e) { tbody.replaceChildren(emptyRow(5, e.message, "bad")); return []; }
}
pages.activity = () => { loadAudit("audit", 50); };

pages.overview = async () => {
  const [events, sps, tenants] = await Promise.all([
    loadAudit("recent", 8),
    call(REGISTRY).then((r) => r.serviceProviders).catch(() => []),
    call(TENANTS).then((r) => r.tenants).catch(() => []),
  ]);
  void events; // the day's sign-ins and refusals are counted on the server, from the whole audit log
  $("countSps").textContent = String(sps.filter((s) => s.enabled && s.valid).length);
  $("countTenants").textContent = String(tenants.length);
};

// ---- Provisioning (better-auth-scim-provisioning) ----
pages.provisioning = () => {
  const { targets } = pageData();
  const API = "/admin/api/provisioning";
  let offset = 0;
  $("targets").replaceChildren(...targets.map((t) => el("div", { className: "tile" },
    el("span", { className: "muted small", textContent: t.type === "google-workspace" ? "Google Workspace" : "SCIM app" }),
    el("strong", { textContent: t.id }),
    el("span", { className: "muted small", textContent: t.where }),
    el("span", {}, pill(t.groups ? "groups on" : "users only", t.groups ? "info" : "")))));

  async function act(body, after) {
    try { const r = await call(API, body); toast(r.ok || "Done."); if (after) after(r); setTimeout(load, 800); } catch (e) { toast(e.message, "err"); }
  }
  function appState(u, t) {
    const link = u.links[t.id], job = u.jobs[t.id];
    const cell = el("div", { className: "targets-cell" });
    const state = !link ? pill("not provisioned", "") : link.pending ? pill("pending", "info") : link.active ? pill("provisioned", "ok") : pill("deactivated", "warn");
    cell.append(el("span", {}, el("span", { className: "muted small", textContent: t.id + " " }), state));
    if (job) {
      cell.append(job.failed ? pill("failed", "bad") : pill(job.attempts ? "retrying (attempt " + job.attempts + ")" : "queued", "info"));
      if (job.lastError) cell.append(el("span", { className: "err", textContent: job.lastError }));
    }
    return cell;
  }
  function row(u) {
    const status = el("td", {}, u.verified ? pill("verified", "ok") : pill("unverified", "warn"), " ", u.banned ? pill("banned", "bad") : "", " ", u.you ? pill("you", "info") : "");
    const apps = el("td", {}, el("div", { className: "stack" }, ...targets.map((t) => appState(u, t))));
    const actions = el("div", { className: "actions" });
    const btn = (label, fn, cls) => actions.append(el("button", { type: "button", className: (cls || "ghost") + " small", textContent: label, onclick: fn }));
    btn("Rename", () => { const name = prompt("New name for " + u.email, u.name); if (name) act({ action: "rename", userId: u.id, name }); });
    btn("Email", () => { const email = prompt("New email for " + u.name, u.email); if (email && email !== u.email) act({ action: "email", userId: u.id, email }); });
    if (!u.you) btn(u.banned ? "Unban" : "Ban", () => act({ action: u.banned ? "unban" : "ban", userId: u.id }), u.banned ? "ghost" : "danger");
    btn("Set password", () => { const password = prompt("A password for " + u.email + " (12 characters or more), so they can sign in through the IdP"); if (password) act({ action: "password", userId: u.id, password }); });
    btn("Re-sync", () => act({ action: "resync", userId: u.id }));
    if (!u.you) btn("Delete", () => confirm("Delete " + u.email + "? They're deprovisioned at every app.") && act({ action: "delete", userId: u.id }), "danger");
    return el("tr", {}, el("td", {}, el("strong", { textContent: u.name }), el("div", { className: "muted small", textContent: u.email })), status, apps, el("td", {}, actions));
  }
  async function load() {
    try {
      const d = await call(API + "?offset=" + offset);
      $("users").replaceChildren(...(d.users.length ? d.users.map(row) : [emptyRow(4, "No users yet. Add a test user below.")]));
      $("usersNote").textContent = d.users.length ? "Users " + (d.offset + 1) + "–" + (d.offset + d.users.length) : "";
      $("prev").disabled = d.offset === 0; $("next").disabled = !d.more;
      $("queueNote").textContent = d.queue.queued + " queued, " + d.queue.failed + " failed" + (d.queue.failed ? ": failed jobs wait for the user's next change, a Re-sync, or a reconcile." : ".");
      $("groups").replaceChildren(...(d.groups.length ? d.groups.map((g) => el("tr", {}, el("td", { textContent: g.displayName }), el("td", { textContent: g.targetId }), el("td", {}, pill(g.kind === "group" ? "organization" : g.kind, "info")), el("td", {}, el("code", { textContent: g.remoteId || "pending" })))) : [emptyRow(4, "No groups yet.")]));
    } catch (e) { $("users").replaceChildren(emptyRow(4, e.message, "bad")); }
  }
  $("refresh").onclick = load;
  $("prev").onclick = () => { offset = Math.max(0, offset - 25); load(); };
  $("next").onclick = () => { offset += 25; load(); };
  $("create").onclick = () => act({ action: "create", email: $("newEmail").value, name: $("newName").value }, () => { $("newEmail").value = ""; $("newName").value = ""; });
  $("run").onclick = () => act({ action: "run" });
  $("reconcile").onclick = () => act({ action: "reconcile", after: $("cursor").value.trim() }, (r) => { $("cursor").value = r.next || ""; });
  load();
};

const run = pages[document.body.dataset.page];
if (run) run();
`;
