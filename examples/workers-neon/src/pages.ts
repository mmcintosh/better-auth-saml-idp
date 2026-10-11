// The example's two pages and their script. Pages take no user input on the server: the sign-in
// page reads callbackURL in the browser and only follows it to this origin.

const esc = (s: string) => s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);

const layout = (title: string, body: string) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; color: #1a1a1a; }
  code { font-size: 0.9em; overflow-wrap: anywhere; }
  label { display: block; margin-top: 0.75rem; }
  input { width: 100%; padding: 0.5rem; font: inherit; box-sizing: border-box; }
  button { margin-top: 1rem; padding: 0.5rem 1rem; font: inherit; }
  .muted { color: #666; }
  [hidden] { display: none; }
</style>
</head>
<body>
${body}
<script src="/app.js"></script>
</body>
</html>`;

export function homePage(origin: string, sps: string[]): string {
  const idp = `${origin}/api/auth/saml2/idp`;
  return layout(
    "Better Auth SAML IdP on Neon",
    `<h1>Better Auth SAML IdP</h1>
<p class="muted">Cloudflare Workers, Postgres on Neon through Hyperdrive.</p>
<p>Entity ID: <code>${esc(idp)}</code><br>
Metadata: <a href="${esc(`${idp}/metadata`)}"><code>${esc(`${idp}/metadata`)}</code></a><br>
Single sign-on: <code>${esc(`${idp}/sso`)}</code></p>
<p>Service providers: ${sps.length ? sps.map((id) => `<code>${esc(id)}</code>`).join(", ") : "none configured"}</p>
<p id="session" class="muted">Checking your session…</p>
<p><a id="signIn" href="/sign-in" hidden>Sign in</a> <button id="signOut" type="button" hidden>Sign out</button></p>`,
  );
}

export function signInPage(): string {
  return layout(
    "Sign in",
    `<h1 id="heading">Sign in</h1>
<form id="form">
  <label id="nameLabel" hidden>Name <input id="name" autocomplete="name"></label>
  <label>Email <input id="email" type="email" autocomplete="username" required></label>
  <label>Password <input id="password" type="password" autocomplete="current-password" minlength="8" required></label>
  <button id="submit" type="submit">Sign in</button>
</form>
<p><a id="toggle" href="#">Create an account instead</a></p>
<p id="message" role="status"></p>`,
  );
}

/** The pages' script (served as /app.js, so the pages need no inline script). */
export const APP_JS = `"use strict";
const $ = (id) => document.getElementById(id);
const post = (path, body) =>
  fetch("/api/auth" + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

// Only ever follow callbackURL to this origin (the IdP's resume link is one).
function next() {
  const raw = new URLSearchParams(location.search).get("callbackURL");
  if (!raw) return "/";
  try {
    const url = new URL(raw, location.origin);
    return url.origin === location.origin ? url.href : "/";
  } catch {
    return "/";
  }
}

async function home() {
  const res = await fetch("/api/auth/get-session");
  const data = res.ok ? await res.json() : null;
  $("session").textContent = data ? "Signed in as " + data.user.email + "." : "Not signed in.";
  $(data ? "signOut" : "signIn").hidden = false;
  $("signOut").addEventListener("click", async () => {
    await post("/sign-out", {});
    location.reload();
  });
}

function signIn() {
  let creating = false;
  $("toggle").addEventListener("click", (e) => {
    e.preventDefault();
    creating = !creating;
    $("heading").textContent = $("submit").textContent = creating ? "Create an account" : "Sign in";
    $("toggle").textContent = creating ? "Sign in instead" : "Create an account instead";
    $("nameLabel").hidden = !creating;
    $("name").required = creating;
    $("password").autocomplete = creating ? "new-password" : "current-password";
  });
  $("form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const email = $("email").value;
    const password = $("password").value;
    const res = creating
      ? await post("/sign-up/email", { name: $("name").value, email, password, callbackURL: next() })
      : await post("/sign-in/email", { email, password });
    if (res.ok && creating) $("message").textContent = "Check your email for the verification link. It signs you in and continues.";
    else if (res.ok) location.href = next();
    else $("message").textContent = ((await res.json().catch(() => null)) || {}).message || "Sign-in failed (" + res.status + ").";
  });
}

if ($("form")) signIn();
else if ($("session")) home();
`;
