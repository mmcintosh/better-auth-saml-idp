// Test service provider: builds AuthnRequests (Redirect/POST, optionally signed), drives a
// cookie-carrying "browser" through the IdP, and verifies Responses with a strict samlify SP.
import { createPrivateKey, sign as cryptoSign } from "node:crypto";
import * as samlify from "samlify";
import { inject } from "vitest";
import { libxml2Validator } from "../../src/saml/validator";
import { AUTH_BASE, BASE_URL } from "./host";

const testValidator = libxml2Validator();
import { SP_ACS, SP_ENTITY_ID } from "./config";

export const SSO_URL = `${AUTH_BASE}/saml2/idp/sso`;
const keys = () => inject("keys");

const instant = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");
let counter = 0;
export const newRequestId = () => `_req${Date.now().toString(36)}${(counter++).toString(36)}${Math.random().toString(36).slice(2)}`;

export interface AuthnRequestSpec {
  id?: string;
  issuer?: string;
  acsUrl?: string | null;
  issueInstant?: Date;
  destination?: string | null;
  forceAuthn?: boolean;
  isPassive?: boolean;
  nameIdFormat?: string;
  extraAttrs?: string;
  inner?: string;
}

export function authnRequestXml(spec: AuthnRequestSpec = {}) {
  const id = spec.id ?? newRequestId();
  const attrs = [
    `ID="${id}"`,
    `Version="2.0"`,
    `IssueInstant="${instant(spec.issueInstant ?? new Date())}"`,
    spec.destination === null ? "" : `Destination="${spec.destination ?? SSO_URL}"`,
    spec.acsUrl === null ? "" : `AssertionConsumerServiceURL="${spec.acsUrl ?? SP_ACS}"`,
    `ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`,
    spec.forceAuthn ? `ForceAuthn="true"` : "",
    spec.isPassive ? `IsPassive="true"` : "",
    spec.extraAttrs ?? "",
  ].filter(Boolean);
  const policy = spec.nameIdFormat ? `<samlp:NameIDPolicy Format="${spec.nameIdFormat}" AllowCreate="true"/>` : "";
  const xml =
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ${attrs.join(" ")}>` +
    `<saml:Issuer>${spec.issuer ?? SP_ENTITY_ID}</saml:Issuer>${policy}${spec.inner ?? ""}</samlp:AuthnRequest>`;
  return { id, xml };
}

async function deflateRaw(text: string): Promise<Uint8Array> {
  const stream = new Blob([new TextEncoder().encode(text)]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export function b64(bytes: Uint8Array | string): string {
  const b = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  let bin = "";
  for (let i = 0; i < b.length; i += 0x8000) bin += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(bin);
}

export interface RedirectOptions {
  relayState?: string;
  /** Sign the query with the test SP key (SAML Bindings §3.4.4.1). */
  sign?: boolean;
  sigAlg?: string;
  deflated?: Uint8Array;
}

export async function redirectUrl(xml: string, opts: RedirectOptions = {}): Promise<string> {
  const enc = encodeURIComponent;
  let q = `SAMLRequest=${enc(b64(opts.deflated ?? (await deflateRaw(xml))))}`;
  if (opts.relayState !== undefined) q += `&RelayState=${enc(opts.relayState)}`;
  if (opts.sign) {
    const sigAlg = opts.sigAlg ?? "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    q += `&SigAlg=${enc(sigAlg)}`;
    const hash = sigAlg.endsWith("sha1") ? "sha1" : sigAlg.endsWith("sha512") ? "sha512" : "sha256";
    const sig = cryptoSign(hash, new TextEncoder().encode(q), createPrivateKey(keys().sp.privateKey));
    q += `&Signature=${enc(b64(new Uint8Array(sig)))}`;
  }
  return `${SSO_URL}?${q}`;
}

export { deflateRaw };

type AuthLike = { handler(r: Request): Promise<Response>; $context: Promise<any> };

/**
 * A minimal browser: carries cookies between requests and, like Chromium, withholds
 * SameSite=Lax/Strict cookies on cross-site POSTs (`crossSite: true`), which is what the SP's
 * HTTP-POST binding form submission is. (Review finding #6 hid behind a jar that sent every
 * cookie everywhere.) Real-browser behaviour is covered end to end by `pnpm e2e` (Playwright).
 */
export class Browser {
  private jar = new Map<string, { value: string; sameSite: "lax" | "strict" | "none" }>();
  /**
   * Each simulated browser is a distinct client IP. Rate limiting stays ON (ADDENDUM-01 R5);
   * distinct IPs keep unrelated tests from sharing a sign-up budget.
   */
  private readonly clientIp = `10.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}.${1 + Math.floor(Math.random() * 250)}`;
  constructor(public auth: AuthLike) {}

  cookieHeader(opts: { crossSite?: boolean } = {}) {
    return [...this.jar]
      .filter(([, c]) => !opts.crossSite || c.sameSite === "none")
      .map(([k, c]) => `${k}=${c.value}`)
      .join("; ");
  }

  async fetch(url: string, init: RequestInit & { crossSite?: boolean } = {}): Promise<Response> {
    const { crossSite, ...rest } = init;
    const headers = new Headers(rest.headers);
    const cookie = this.cookieHeader({ crossSite });
    if (cookie) headers.set("cookie", cookie);
    if (!headers.has("origin") && rest.method && rest.method !== "GET") headers.set("origin", BASE_URL);
    if (!headers.has("cf-connecting-ip")) headers.set("cf-connecting-ip", this.clientIp);
    const res = await this.auth.handler(new Request(url, { ...rest, headers, redirect: "manual" }));
    for (const c of res.headers.getSetCookie()) {
      const [pair, ...attrs] = c.split(";");
      const i = pair!.indexOf("=");
      const name = pair!.slice(0, i).trim();
      const value = pair!.slice(i + 1).trim();
      const ss = attrs.map((a) => a.trim().toLowerCase()).find((a) => a.startsWith("samesite="))?.slice(9);
      if (/max-age=0/i.test(c) || value === "") this.jar.delete(name);
      else this.jar.set(name, { value, sameSite: ss === "none" || ss === "strict" ? ss : "lax" });
    }
    return res;
  }

  /** Follow same-site GET redirects (e.g. the POST binding's 303 re-entry) until a non-redirect. */
  async follow(res: Response, max = 5): Promise<Response> {
    for (let i = 0; i < max && res.status >= 300 && res.status < 400; i++) {
      const loc = res.headers.get("location")!;
      if (!loc.startsWith(BASE_URL)) return res; // leaving the IdP (e.g. to the login page)
      if (new URL(loc).pathname.endsWith("/sign-in")) return res;
      res = await this.fetch(loc);
    }
    return res;
  }

  /** Sign up; by default also mark the email verified, as the plugin requires (finding #1). */
  async signUp(email = `u${Date.now()}${Math.random().toString(36).slice(2)}@example.com`, opts: { verified?: boolean } = {}) {
    const res = await this.fetch(`${AUTH_BASE}/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "correct-horse-battery", name: "Alice Example" }),
    });
    if (res.status !== 200) throw new Error(`sign-up failed: ${res.status} ${await res.text()}`);
    const user = ((await res.json()) as { user: { id: string; email: string } }).user;
    if (opts.verified !== false) {
      const ctx = await this.auth.$context;
      await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { emailVerified: true } });
    }
    return user;
  }

  async signIn(email: string) {
    const res = await this.fetch(`${AUTH_BASE}/sign-in/email`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "correct-horse-battery" }),
    });
    if (res.status !== 200) throw new Error(`sign-in failed: ${res.status} ${await res.text()}`);
  }

  clone(): Browser {
    const b = new Browser(this.auth);
    b.jar = new Map(this.jar);
    (b as any).clientIp = this.clientIp;
    return b;
  }
}

/** Submit an AuthnRequest with the HTTP-POST binding, as the SP's cross-site form would. */
export async function postBinding(browser: Browser, xml: string, relayState?: string): Promise<Response> {
  const res = await browser.fetch(SSO_URL, {
    method: "POST",
    crossSite: true,
    headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://sp.test" },
    body: new URLSearchParams({ SAMLRequest: b64(xml), ...(relayState !== undefined ? { RelayState: relayState } : {}) }).toString(),
  });
  return browser.follow(res);
}

export interface PostedForm {
  action: string;
  samlResponse: string;
  relayState: string | undefined;
  xml: string;
  html: string;
}

const unescapeHtml = (s: string) =>
  s.replace(/&(amp|lt|gt|quot|apos);/g, (_, e) => ({ amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" })[e as "amp"]);

export async function readAutoPost(res: Response): Promise<PostedForm> {
  const html = await res.text();
  const action = /<form method="post" action="([^"]*)">/.exec(html)?.[1];
  const samlResponse = /name="SAMLResponse" value="([^"]*)"/.exec(html)?.[1];
  const relayState = /name="RelayState" value="([^"]*)"/.exec(html)?.[1];
  if (!action || !samlResponse) throw new Error(`not an auto-POST page (status ${res.status}): ${html.slice(0, 300)}`);
  const decoded = unescapeHtml(samlResponse);
  const bin = atob(decoded);
  const xml = new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  return { action: unescapeHtml(action), samlResponse: decoded, relayState: relayState && unescapeHtml(relayState), xml, html };
}

/** The strict test SP: message AND assertion signatures required. */
export async function strictSp(auth: { handler(r: Request): Promise<Response> }, want = { message: true, assertion: true }) {
  // A samlify SP app must install samlify's (process-global) schema validator itself; the IdP
  // plugin no longer touches that global.
  samlify.setSchemaValidator({
    validate: async (xml: string) => {
      const r = await testValidator.validate(xml, "protocol");
      if (!r.valid) throw new Error(`ERR_SCHEMA: ${r.errors.join("; ")}`);
      return "SUCCESS_VALIDATE_XML";
    },
  });
  const metadata = await (await auth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata`))).text();
  const idp = samlify.IdentityProvider({ metadata });
  const sp = samlify.ServiceProvider({
    entityID: SP_ENTITY_ID,
    wantAssertionsSigned: want.assertion,
    wantMessageSigned: want.message,
    authnRequestsSigned: false,
    assertionConsumerService: [{ Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: SP_ACS }],
    clockDrifts: [-60_000, 60_000],
  });
  return {
    idp,
    sp,
    /** samlify verifies signatures, issuer, and time conditions. */
    verify: (samlResponse: string) => sp.parseLoginResponse(idp, "post", { body: { SAMLResponse: samlResponse } }),
  };
}

export const spKeys = () => keys().sp;
