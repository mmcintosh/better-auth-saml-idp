import { escapeXml as escapeHtml } from "./response";

/**
 * Headers for every HTML page the plugin returns (auto-POST form and error page).
 * The CSP allows exactly one inline script (by nonce) and form posts to one target.
 */
function pageHeaders(nonce: string, formAction: string | undefined): Headers {
  const csp = [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    `style-src 'nonce-${nonce}'`,
    formAction ? `form-action ${formAction}` : "form-action 'none'",
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

/** CSP source expressions cannot contain `;`, `,` or whitespace; ACS URLs are validated https URLs. */
function cspUrl(url: string): string {
  const u = new URL(url);
  return `${u.origin}${u.pathname}`.replace(/[;,\s]/g, encodeURIComponent);
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
  return new Response(html, { status: 200, headers: pageHeaders(nonce, cspUrl(acsUrl)) });
}

/** A plain error page. Never includes request payloads, only the fixed message. */
export function errorPage(status: number, code: string, message: string): Response {
  const nonce = newNonce();
  const html =
    `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Sign-in error</title>` +
    `<style nonce="${nonce}">body{font:16px system-ui,sans-serif;margin:2rem}code{color:#666}</style></head>` +
    `<body><h1>Sign-in could not be completed</h1><p>${escapeHtml(message)}</p><p><code>${escapeHtml(code)}</code></p></body></html>`;
  return new Response(html, { status, headers: pageHeaders(nonce, undefined) });
}
