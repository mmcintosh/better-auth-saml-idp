// The sign-in page, in the example's style. After success it follows `callbackURL` only if it
// points back to this origin (the SAML plugin passes its absolute /saml2/idp/resume URL). Its code
// is the "sign-in" part of /assets/app.js.
import { esc, htmlResponse } from "./ui/layout";

export function signInPage(url: string): Response {
  // Signing in to continue to an SP: say so.
  const continuing = new URL(url).searchParams.get("callbackURL")?.includes("/saml2/idp/") ?? false;
  return htmlResponse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in · Better Auth IdP</title><link rel="stylesheet" href="/assets/app.css"></head>
<body data-page="sign-in"><main class="auth"><div class="auth-card">
<div class="brand"><span class="logo" aria-hidden="true">◆</span><span><strong>Better Auth IdP</strong><small class="muted">${continuing ? esc("Sign in to continue to the app") : "SAML sign-in"}</small></span></div>
<h1 id="title">Sign in</h1>
<form id="signin" class="stack">
<label class="field"><span>Email</span><input id="email" name="email" type="email" autocomplete="username" required></label>
<label class="field"><span>Password</span><input id="password" name="password" type="password" autocomplete="current-password" minlength="8" required></label>
<label class="field" id="nameField" hidden><span>Name</span><input id="name" name="name" autocomplete="name"></label>
<button id="submit" type="submit">Sign in</button>
<button id="toggle" type="button" class="link">Create an account instead</button>
<p id="err" class="error" role="alert"></p>
</form>
<div id="sent" class="notice" hidden><strong>Check your email</strong><span>We sent a verification link. Open it to finish signing in.</span></div>
<p class="muted small"><a href="/">Back</a></p>
</div></main><script src="/assets/app.js" defer></script></body></html>`);
}
