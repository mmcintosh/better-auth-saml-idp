// Test service provider: builds AuthnRequests (Redirect/POST, optionally signed), drives a
// cookie-carrying "browser" through the IdP, and verifies Responses with a strict samlify SP.
import { createPrivateKey, sign as cryptoSign } from "node:crypto";
import * as samlify from "samlify";
import { inject } from "vitest";
import { AUTH_BASE, BASE_URL } from "./host";
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

/** A minimal browser: follows nothing automatically, but carries cookies between requests. */
export class Browser {
  private jar = new Map<string, string>();
  /**
   * Each simulated browser is a distinct client IP. Rate limiting stays ON (ADDENDUM-01 R5);
   * distinct IPs keep unrelated tests from sharing a sign-up budget.
   */
  private readonly clientIp = `10.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}.${1 + Math.floor(Math.random() * 250)}`;
  constructor(private auth: { handler(r: Request): Promise<Response> }) {}

  cookieHeader() {
    return [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  async fetch(url: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    if (this.jar.size) headers.set("cookie", this.cookieHeader());
    if (!headers.has("origin") && init.method && init.method !== "GET") headers.set("origin", BASE_URL);
    if (!headers.has("cf-connecting-ip")) headers.set("cf-connecting-ip", this.clientIp);
    const res = await this.auth.handler(new Request(url, { ...init, headers, redirect: "manual" }));
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      const i = pair!.indexOf("=");
      const name = pair!.slice(0, i).trim();
      const value = pair!.slice(i + 1).trim();
      if (/max-age=0/i.test(c) || value === "") this.jar.delete(name);
      else this.jar.set(name, value);
    }
    return res;
  }

  async signUp(email = `u${Date.now()}${Math.random().toString(36).slice(2)}@example.com`) {
    const res = await this.fetch(`${AUTH_BASE}/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "correct-horse-battery", name: "Alice Example" }),
    });
    if (res.status !== 200) throw new Error(`sign-up failed: ${res.status} ${await res.text()}`);
    return ((await res.json()) as { user: { id: string; email: string } }).user;
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
export async function strictSp(auth: { handler(r: Request): Promise<Response> }) {
  const metadata = await (await auth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata`))).text();
  const idp = samlify.IdentityProvider({ metadata });
  const sp = samlify.ServiceProvider({
    entityID: SP_ENTITY_ID,
    wantAssertionsSigned: true,
    wantMessageSigned: true,
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
