import { escapeXml as escapeHtml } from "./response";

/**
 * Headers for every HTML page the plugin returns (auto-POST form and error page).
 * The CSP allows exactly one inline script (by nonce).
 *
 * The auto-POST page deliberately has NO form-action directive: browsers enforce form-action
 * on every redirect that follows the submission, and real SPs (Cloudflare Access, AWS,
 * HubSpot) redirect to another origin after consuming the Response, which any form-action
 * source list short of `*` would block (review finding #5; reproduced in Chromium). The page
 * has no injection point — every value is escaped and scripts need the nonce — and the form's
 * action is an allow-listed ACS URL.
 */
function pageHeaders(nonce: string, kind: "autopost" | "error"): Headers {
  const csp = [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    `style-src 'nonce-${nonce}'`,
    ...(kind === "error" ? ["form-action 'none'"] : []),
    "base-uri 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
  return new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": csp,
    "Cache-Control": "no-store",
    Pragma: "no-cache",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
  });
}

function newNonce(): string {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...b));
}

/** The HTTP-POST binding page: auto-submits SAMLResponse (+ RelayState) to the ACS URL. */
export function autoPostResponse(acsUrl: string, samlResponse: string, relayState: string | undefined): Response {
  const nonce = newNonce();
  const html =
    `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer">` +
    `<title>Signing in…</title><style nonce="${nonce}">body{font:16px system-ui,sans-serif;margin:2rem}</style></head>` +
    `<body><form method="post" action="${escapeHtml(acsUrl)}">` +
    `<input type="hidden" name="SAMLResponse" value="${escapeHtml(samlResponse)}">` +
    (relayState !== undefined ? `<input type="hidden" name="RelayState" value="${escapeHtml(relayState)}">` : "") +
    `<noscript><p>JavaScript is disabled. Continue to finish signing in.</p><button type="submit">Continue</button></noscript>` +
    `</form><script nonce="${nonce}">document.forms[0].submit()</script></body></html>`;
  return new Response(html, { status: 200, headers: pageHeaders(nonce, "autopost") });
}

/** A plain error page. Never includes request payloads, only the fixed message. */
export function errorPage(status: number, code: string, message: string): Response {
  const nonce = newNonce();
  const html =
    `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Sign-in error</title>` +
    `<style nonce="${nonce}">body{font:16px system-ui,sans-serif;margin:2rem}code{color:#666}</style></head>` +
    `<body><h1>Sign-in could not be completed</h1><p>${escapeHtml(message)}</p><p><code>${escapeHtml(code)}</code></p></body></html>`;
  return new Response(html, { status, headers: pageHeaders(nonce, "error") });
}

/**
 * IdP-initiated SSO reached by a cross-site navigation without user activation (a drive-by
 * redirect from another site): the user confirms on this origin before being signed in to the
 * SP (login-CSRF mitigation, docs/security.md). `href` is the same init URL; following it is a
 * same-origin, user-activated navigation. Framing is denied, so the link can't be clickjacked.
 */
export function confirmPage(href: string, appLabel: string): Response {
  const nonce = newNonce();
  const html =
    `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Continue sign-in</title>` +
    `<style nonce="${nonce}">body{font:16px system-ui,sans-serif;margin:2rem}</style></head>` +
    `<body><h1>Continue to ${escapeHtml(appLabel)}?</h1><p>Another site sent you here to sign in to this application.</p>` +
    `<p><a href="${escapeHtml(href)}">Continue</a></p></body></html>`;
  return new Response(html, { status: 200, headers: pageHeaders(nonce, "error") });
}
