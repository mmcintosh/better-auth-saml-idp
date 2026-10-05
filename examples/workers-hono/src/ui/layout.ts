// The example's page shell: a sidebar with the IdP's name, navigation (what the viewer may see)
// and who's signed in, around each page's content. Styles and scripts are same-origin files
// (/assets/app.css, /assets/app.js), so the CSP allows no inline code at all.

export const esc = (s: string) => s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);

const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

export function htmlResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", "content-security-policy": CSP, "x-frame-options": "DENY", "cache-control": "no-store", "referrer-policy": "no-referrer" },
  });
}

export type Viewer = { email: string; admin: boolean } | null;

/** A sidebar entry: [path, label]. Sections a viewer can't use aren't shown. */
type NavItem = readonly [string, string];
function nav(viewer: Viewer, active: string, extra: { provisioning: boolean }): string {
  const link = ([href, label]: NavItem) => `<a href="${href}"${href === active ? ' class="active" aria-current="page"' : ""}>${esc(label)}</a>`;
  const groups: [string, NavItem[]][] = [["", [["/", viewer ? "My apps" : "Home"]]]];
  if (viewer?.admin) {
    groups.push([
      "Identity provider",
      [
        ["/admin", "Overview"],
        ["/admin/sps", "Service providers"],
        ["/admin/tenants", "Tenants"],
        ["/admin/activity", "Activity"],
      ],
    ]);
    if (extra.provisioning) groups.push(["Provisioning", [["/admin/provisioning", "Users and apps"]]]);
  }
  return groups.map(([label, items]) => `${label ? `<div class="nav-label">${esc(label)}</div>` : ""}${items.map(link).join("")}`).join("");
}

export function page(o: {
  title: string;
  active: string;
  viewer: Viewer;
  /** The page's content (already escaped). */
  content: string;
  /** Picks the page's code in /assets/app.js. */
  script?: string;
  /** Data for the page's code, as JSON in a non-executable script element. */
  data?: unknown;
  provisioning?: boolean;
}): string {
  const who = o.viewer
    ? `<div class="whoami"><span class="muted small">Signed in as</span><span class="email">${esc(o.viewer.email)}</span><button type="button" class="ghost small" data-sign-out>Sign out</button></div>`
    : `<div class="whoami"><a class="button small" href="/sign-in">Sign in</a></div>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(o.title)} · Better Auth IdP</title><link rel="stylesheet" href="/assets/app.css"></head>
<body${o.script ? ` data-page="${esc(o.script)}"` : ""}>
<div class="layout">
<aside class="sidebar">
<a class="brand" href="/"><span class="logo" aria-hidden="true">◆</span><span><strong>Better Auth IdP</strong><small class="muted">SAML sign-in${o.provisioning ? " and provisioning" : ""}</small></span></a>
<nav aria-label="Main">${nav(o.viewer, o.active, { provisioning: o.provisioning === true })}</nav>
${who}
</aside>
<main class="content">${o.content}</main>
</div>
<div class="toast" id="toast" role="status" hidden></div>
${o.data === undefined ? "" : `<script type="application/json" id="page-data">${JSON.stringify(o.data).replace(/</g, "\\u003c")}</script>`}
<script src="/assets/app.js" defer></script>
</body></html>`;
}

/** A page heading with its intro. */
export const head = (title: string, intro?: string) => `<div class="page-head"><h1>${esc(title)}</h1>${intro ? `<p class="muted">${intro}</p>` : ""}</div>`;

/** A card: title, optional subtitle and actions, then content (all already escaped). */
export const card = (title: string, body: string, o: { subtitle?: string; actions?: string; id?: string } = {}) =>
  `<section class="card"${o.id ? ` id="${o.id}"` : ""}><div class="card-head"><div><h2>${esc(title)}</h2>${o.subtitle ? `<p class="muted">${o.subtitle}</p>` : ""}</div>${o.actions ? `<div class="row">${o.actions}</div>` : ""}</div>${body}</section>`;

/** A key/value list; values are already escaped. */
export const kv = (rows: [string, string][]) => `<dl class="kv">${rows.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${v}</dd></div>`).join("")}</dl>`;

/** A value with a copy button (the button's code is in /assets/app.js). */
export const copy = (value: string, href = false) =>
  `<span class="copy">${href ? `<a href="${esc(value)}" target="_blank" rel="noopener"><code>${esc(value)}</code></a>` : `<code>${esc(value)}</code>`}<button type="button" class="ghost small" data-copy="${esc(value)}">Copy</button></span>`;
