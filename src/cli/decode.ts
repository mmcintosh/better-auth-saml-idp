// `decode`: explain a captured SAMLRequest / SAMLResponse (URL, form body, base64 or XML).
import { inflateRawSync } from "node:zlib";
import { checkRequestSignature, decodeAuthnRequest, parseAuthnRequest, parseRedirectQuery, type RawAuthnRequest } from "../saml/request";
import { defaultSchemaValidator } from "../saml/validator";
import type { ResolvedServiceProvider } from "../types";
import {
  child,
  children,
  decryptAssertion,
  encryptionInfo,
  MAX_DOC_BYTES,
  metadataUrl,
  NS,
  parseDoc,
  readIdpMetadata,
  type SignatureResult,
  text,
  verifyEnveloped,
} from "./saml";
import { fetchText, httpsOnly, pemCertificates, readFileArg, readInput, Report, since, UsageError } from "./util";

export interface DecodeOptions {
  cert: string[];
  idp?: string;
  key?: string;
  sp?: string;
  acs?: string;
  requestId?: string;
  sso?: string;
  basePath: string;
  showXml: boolean;
  allowHttp: boolean;
}

interface Message {
  xml: string;
  source: "xml" | "redirect" | "post" | "base64";
  raw?: RawAuthnRequest;
  relayState?: string;
}

const looksLikeXml = (b: Buffer) => /^\s*</.test(b.subarray(0, 64).toString("utf8").replace(/^﻿/, ""));

function fromBase64(b64: string): string {
  const bytes = Buffer.from(b64.replace(/\s+/g, ""), "base64");
  if (bytes.length === 0) throw new UsageError("empty or invalid base64");
  if (looksLikeXml(bytes)) return bytes.toString("utf8");
  try {
    return inflateRawSync(bytes, { maxOutputLength: MAX_DOC_BYTES }).toString("utf8");
  } catch {
    throw new UsageError("input is neither XML, base64 XML, nor base64 DEFLATE");
  }
}

/** Form decoding turns "+" into " ", and base64 never contains spaces: undo it. */
const b64Param = (p: URLSearchParams, name: string) => (p.get(name) ?? "").replace(/ /g, "+");

/** Accept whatever a developer copies out of the browser. */
export async function normalize(input: string): Promise<Message> {
  const t = input.trim();
  if (t.startsWith("<")) return { xml: t, source: "xml" };
  if (/(^|[?&\s])SAML(Request|Response)=/.test(t)) {
    const isUrl = /^https?:\/\//i.test(t);
    const query = isUrl ? (t.split("?")[1] ?? "").split("#")[0] ?? "" : t.replace(/\s+/g, "");
    if (/(^|&)SAMLRequest=/.test(query)) {
      const binding = isUrl ? "redirect" : "post";
      let raw: RawAuthnRequest;
      try {
        const form = new URLSearchParams(query);
        raw = isUrl ? parseRedirectQuery(query) : { binding, samlRequest: b64Param(form, "SAMLRequest"), relayState: form.get("RelayState") ?? undefined };
        return { xml: await decodeAuthnRequest(raw), source: binding, raw, relayState: raw.relayState };
      } catch (e) {
        throw new UsageError(`cannot decode SAMLRequest: ${(e as Error).message}`);
      }
    }
    const params = new URLSearchParams(query);
    return { xml: fromBase64(b64Param(params, "SAMLResponse")), source: isUrl ? "redirect" : "post", relayState: params.get("RelayState") ?? undefined };
  }
  return { xml: fromBase64(t.includes("%") ? decodeURIComponent(t) : t), source: "base64" };
}

/** Indent XML for reading. Display only: never feed the result back into verification. */
export function prettyXml(xml: string): string {
  let depth = 0;
  return xml
    .replace(/>\s*</g, ">\n<")
    .split("\n")
    .map((line) => {
      if (/^<\//.test(line)) depth = Math.max(0, depth - 1);
      const out = `${"  ".repeat(depth)}${line}`;
      if (/^<[^!?/][^>]*[^/]>$/.test(line) && !/<\/[^>]+>$/.test(line)) depth++;
      return out;
    })
    .join("\n");
}

async function certificates(opts: DecodeOptions, report: Report): Promise<{ certs: string[]; idpEntityId?: string }> {
  const certs = opts.cert.flatMap((f) => {
    const found = pemCertificates(readFileArg(f, "certificate"));
    if (found.length === 0) throw new UsageError(`${f}: no PEM certificate found`);
    return found;
  });
  if (!opts.idp) return { certs };
  const url = metadataUrl(httpsOnly(opts.idp, opts.allowHttp).href, opts.basePath);
  const { res, text: xml } = await fetchText(url);
  if (!res.ok) throw new UsageError(`${url}: HTTP ${res.status}`);
  const md = readIdpMetadata(xml);
  report.info(`certificates from ${url} (${md.signingCertificates.length})`);
  return { certs: [...certs, ...md.signingCertificates], idpEntityId: md.entityId };
}

function describeSignature(what: string, r: SignatureResult, report: Report, certCount: number): void {
  if (!r.present) return;
  const alg = `${r.algorithm}/${r.digest}`;
  if (r.valid === true) report.pass(`${what} signature is valid (${alg}${certCount > 1 ? `, certificate #${(r.certIndex ?? 0) + 1}` : ""})`);
  else if (r.valid === false) report.fail(`${what} signature is INVALID: ${r.problem}`);
  else if (r.problem) report.fail(`${what} signature: ${r.problem}`);
  else report.warn(`${what} is signed (${alg}) but not verified: pass --cert <idp.crt> or --idp <url>`);
  if (/sha1/i.test(alg)) report.warn(`${what} signature uses SHA-1`);
}

const status = (el: any): string => {
  const top = child(child(el, NS.samlp, "Status"), NS.samlp, "StatusCode");
  const codes: string[] = [];
  for (let c = top; c; c = child(c, NS.samlp, "StatusCode")) codes.push((c.getAttribute("Value") ?? "").split(":").pop() ?? "");
  return codes.join(" / ");
};

function time(v: string | null | undefined, now: Date): string | undefined {
  if (!v) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? `${v} (unparseable)` : `${v} (${since(d, now)})`;
}

/**
 * `a` is the Assertion element; `verify` checks its signature in the right context (the whole
 * Response for a plain assertion, the decrypted document for an encrypted one).
 */
function assertionReport(a: any, verify: () => SignatureResult, report: Report, ctx: { certCount: number; opts: DecodeOptions; response: any; now: Date; title: string }) {
  if (!a || a.namespaceURI !== NS.saml || a.localName !== "Assertion") {
    report.fail(`${ctx.title}: not a saml:Assertion`);
    return;
  }
  const { opts, now, response } = ctx;
  const subject = child(a, NS.saml, "Subject");
  const nameId = child(subject, NS.saml, "NameID");
  const conf = child(subject, NS.saml, "SubjectConfirmation");
  const scd = child(conf, NS.saml, "SubjectConfirmationData");
  const cond = child(a, NS.saml, "Conditions");
  const audiences = children(child(cond, NS.saml, "AudienceRestriction"), NS.saml, "Audience").map((x) => text(x) ?? "");
  const authn = child(a, NS.saml, "AuthnStatement");
  const attrs = children(child(a, NS.saml, "AttributeStatement"), NS.saml, "Attribute").map(
    (at) => `${at.getAttribute("Name")} = ${children(at, NS.saml, "AttributeValue").map((v) => JSON.stringify(text(v))).join(", ")}`,
  );
  report.section(ctx.title, {
    ID: a.getAttribute("ID"),
    Issuer: text(child(a, NS.saml, "Issuer")),
    IssueInstant: time(a.getAttribute("IssueInstant"), now),
    NameID: nameId ? `${text(nameId)}  (${(nameId.getAttribute("Format") ?? "no format").split(":").pop()})` : undefined,
    "Confirmation": conf?.getAttribute("Method")?.split(":").pop(),
    Recipient: scd?.getAttribute("Recipient"),
    "Confirm until": time(scd?.getAttribute("NotOnOrAfter"), now),
    "Confirm InResponseTo": scd?.getAttribute("InResponseTo"),
    NotBefore: time(cond?.getAttribute("NotBefore"), now),
    NotOnOrAfter: time(cond?.getAttribute("NotOnOrAfter"), now),
    Audience: audiences.join("\n"),
    AuthnInstant: time(authn?.getAttribute("AuthnInstant"), now),
    SessionIndex: authn?.getAttribute("SessionIndex"),
    AuthnContext: text(child(child(authn, NS.saml, "AuthnContext"), NS.saml, "AuthnContextClassRef")),
    Attributes: attrs.join("\n"),
  });

  describeSignature("Assertion", verify(), report, ctx.certCount);

  const respIssuer = text(child(response, NS.saml, "Issuer"));
  const aIssuer = text(child(a, NS.saml, "Issuer"));
  if (respIssuer && aIssuer && respIssuer !== aIssuer) report.fail(`Assertion Issuer ${aIssuer} differs from the Response Issuer ${respIssuer}`);
  if (conf?.getAttribute("Method") !== "urn:oasis:names:tc:SAML:2.0:cm:bearer") report.warn("SubjectConfirmation is not bearer");
  const destination = response.getAttribute("Destination");
  if (destination && scd?.getAttribute("Recipient") && scd.getAttribute("Recipient") !== destination)
    report.fail(`Recipient ${scd.getAttribute("Recipient")} differs from the Response Destination ${destination}`);
  const irt = response.getAttribute("InResponseTo");
  if ((irt ?? null) !== (scd?.getAttribute("InResponseTo") || null)) report.fail("InResponseTo differs between the Response and SubjectConfirmationData");
  if (opts.sp) {
    if (audiences.includes(opts.sp)) report.pass(`Audience includes ${opts.sp}`);
    else report.fail(`Audience does not include ${opts.sp} (has: ${audiences.join(", ") || "none"})`);
  }
  if (opts.acs && scd?.getAttribute("Recipient") !== opts.acs) report.fail(`Recipient is not ${opts.acs}`);
  const until = cond?.getAttribute("NotOnOrAfter");
  const from = cond?.getAttribute("NotBefore");
  if (until && new Date(until) <= now)
    report.warn(`expired ${since(new Date(until), now)}: normal for a captured Response, but an SP would reject it now`);
  else if (until) report.pass(`within its validity window (until ${since(new Date(until), now)})`);
  if (from && new Date(from).getTime() > now.getTime() + 60_000) report.fail(`NotBefore is ${since(new Date(from), now)}: clocks out of sync?`);
  if (from && until && new Date(until).getTime() - new Date(from).getTime() > 600_000)
    report.warn(`validity window is ${Math.round((new Date(until).getTime() - new Date(from).getTime()) / 60_000)} minutes (5 is typical)`);
}

async function responseReport(msg: Message, doc: any, opts: DecodeOptions, report: Report) {
  const r = doc.documentElement;
  const now = new Date();
  const { certs, idpEntityId } = await certificates(opts, report);
  const issuer = text(child(r, NS.saml, "Issuer"));
  report.section("Response", {
    Binding: msg.source === "xml" || msg.source === "base64" ? undefined : msg.source === "post" ? "HTTP-POST" : "HTTP-Redirect",
    ID: r.getAttribute("ID"),
    Issuer: issuer,
    Destination: r.getAttribute("Destination"),
    InResponseTo: r.getAttribute("InResponseTo") ?? "(none: unsolicited, IdP-initiated)",
    IssueInstant: time(r.getAttribute("IssueInstant"), now),
    Status: status(r),
    StatusMessage: text(child(child(r, NS.samlp, "Status"), NS.samlp, "StatusMessage")),
    RelayState: msg.relayState,
  });

  const schema = await defaultSchemaValidator().validate(msg.xml, "protocol");
  if (schema.valid) report.pass("valid against the SAML 2.0 protocol schema");
  else report.fail(`schema: ${schema.errors.slice(0, 3).join("; ")}`);
  if (status(r).startsWith("Success")) report.pass("Status is Success");
  else report.warn(`Status is ${status(r)}: the SP will not sign the user in`);
  if (idpEntityId && issuer !== idpEntityId) report.fail(`Issuer ${issuer} is not the IdP's entity ID ${idpEntityId}`);
  if (opts.acs) {
    if (r.getAttribute("Destination") === opts.acs) report.pass(`Destination is ${opts.acs}`);
    else report.fail(`Destination is ${r.getAttribute("Destination")}, not ${opts.acs}`);
  }
  if (opts.requestId) {
    if (r.getAttribute("InResponseTo") === opts.requestId) report.pass(`InResponseTo matches ${opts.requestId}`);
    else report.fail(`InResponseTo is ${r.getAttribute("InResponseTo") ?? "missing"}, not ${opts.requestId}`);
  }

  const responseSig = verifyEnveloped(msg.xml, doc, r, certs);
  describeSignature("Response", responseSig, report, certs.length);

  const plain = children(r, NS.saml, "Assertion");
  const encrypted = children(r, NS.saml, "EncryptedAssertion");
  if (plain.length + encrypted.length > 1) report.fail(`${plain.length + encrypted.length} assertions: SPs expect exactly one`);
  const signed: boolean[] = [responseSig.present];
  for (const a of plain) {
    signed.push(child(a, NS.ds, "Signature") !== undefined);
    // Verified in the context of the whole document, as an SP does.
    assertionReport(a, () => verifyEnveloped(msg.xml, doc, a, certs), report, { certCount: certs.length, opts, response: r, now, title: "Assertion" });
  }
  for (const e of encrypted) {
    const info = encryptionInfo(e);
    report.section("EncryptedAssertion", {
      "Data algorithm": info.dataAlgorithm,
      "Key transport": info.keyAlgorithm + (info.keyDigest ? ` (${info.keyDigest})` : ""),
      Recipient: info.recipient,
    });
    if (/rsa-1_5/.test(info.keyAlgorithm)) report.fail("key transport is RSA PKCS#1 v1.5 (insecure)");
    if (/cbc/.test(info.dataAlgorithm)) report.warn(`${info.dataAlgorithm}: AES-CBC is weaker than AES-GCM`);
    if (!opts.key) {
      report.info("assertion is encrypted: pass --key <sp.key> to decrypt it");
      signed.push(true); // can't tell; don't claim "unsigned"
      continue;
    }
    const assertionXml = decryptAssertion(e, readFileArg(opts.key, "private key"));
    report.pass("decrypted the assertion");
    signed.push(/<(\w+:)?Signature[\s>]/.test(assertionXml));
    const aDoc = parseDoc(assertionXml);
    const a = aDoc.documentElement;
    assertionReport(a, () => verifyEnveloped(assertionXml, aDoc, a, certs), report, { certCount: certs.length, opts, response: r, now, title: "Assertion (decrypted)" });
    if (opts.showXml) report.data.decryptedAssertion = assertionXml;
  }
  if (status(r).startsWith("Success") && !signed.some(Boolean)) report.fail("neither the Response nor the Assertion is signed");
}

async function requestReport(msg: Message, doc: any, opts: DecodeOptions, report: Report) {
  const r = doc.documentElement;
  const now = new Date();
  const policy = child(r, NS.samlp, "NameIDPolicy");
  const rac = child(r, NS.samlp, "RequestedAuthnContext");
  const issueInstant = new Date(r.getAttribute("IssueInstant") ?? "");
  report.section("AuthnRequest", {
    Binding: msg.source === "redirect" ? "HTTP-Redirect" : msg.source === "post" ? "HTTP-POST" : undefined,
    ID: r.getAttribute("ID"),
    Issuer: text(child(r, NS.saml, "Issuer")),
    IssueInstant: time(r.getAttribute("IssueInstant"), now),
    Destination: r.getAttribute("Destination"),
    "ACS URL": r.getAttribute("AssertionConsumerServiceURL"),
    "ACS index": r.getAttribute("AssertionConsumerServiceIndex"),
    ProtocolBinding: r.getAttribute("ProtocolBinding")?.split(":").pop(),
    ForceAuthn: r.getAttribute("ForceAuthn"),
    IsPassive: r.getAttribute("IsPassive"),
    NameIDPolicy: policy ? `${(policy.getAttribute("Format") ?? "any").split(":").pop()}, AllowCreate=${policy.getAttribute("AllowCreate") ?? "unset"}` : undefined,
    RequestedAuthnContext: rac
      ? `${rac.getAttribute("Comparison") ?? "exact"}: ${children(rac, NS.saml, "AuthnContextClassRef").map((c) => text(c)).join(", ")}`
      : undefined,
    Subject: text(child(child(r, NS.saml, "Subject"), NS.saml, "NameID")),
    RelayState: msg.relayState !== undefined ? `${msg.relayState.length} bytes` : undefined,
    SigAlg: msg.raw?.signed?.sigAlg,
  });

  try {
    await parseAuthnRequest(msg.xml, defaultSchemaValidator(), {
      now: Number.isNaN(issueInstant.getTime()) ? now : issueInstant,
      clockSkewSeconds: 60,
      ssoUrl: opts.sso ?? r.getAttribute("Destination") ?? "",
    });
    report.pass("valid AuthnRequest (schema, structure and Destination)");
  } catch (e) {
    report.fail(`the IdP would reject it: ${(e as Error).message}`);
  }
  if (!Number.isNaN(issueInstant.getTime()) && now.getTime() - issueInstant.getTime() > 300_000)
    report.info(`IssueInstant is ${since(issueInstant, now)}: the IdP only accepts requests up to 5 minutes old`);
  if (msg.relayState && Buffer.byteLength(msg.relayState) > 80)
    report.info(`RelayState is ${Buffer.byteLength(msg.relayState)} bytes: over the spec's 80, within the IdP's default 1024`);

  const certs = opts.cert.flatMap((f) => pemCertificates(readFileArg(f, "certificate")));
  if (msg.raw?.signed) {
    if (/sha1/i.test(msg.raw.signed.sigAlg)) report.warn("signed with SHA-1: the IdP rejects it unless allowInsecureSha1 is set");
    if (certs.length === 0) report.warn("signed but not verified: pass --cert <sp.crt>");
    else {
      const sp = { requireSignedAuthnRequests: true, spCertificates: certs } as unknown as ResolvedServiceProvider;
      try {
        checkRequestSignature(msg.raw, sp, { allowInsecureSha1: true });
        report.pass("Redirect-binding signature is valid");
      } catch (e) {
        report.fail(`signature: ${(e as Error).message}`);
      }
    }
  } else if (child(r, NS.ds, "Signature")) report.info("embedded XML signature (POST binding): not verified here, and the IdP only verifies Redirect-binding signatures");
  else report.info("unsigned");
}

export async function decode(arg: string | undefined, opts: DecodeOptions): Promise<Report> {
  const report = new Report();
  const msg = await normalize(await readInput(arg));
  const doc = parseDoc(msg.xml);
  const root = doc.documentElement as any;
  if (root.namespaceURI === NS.samlp && root.localName === "Response") await responseReport(msg, doc, opts, report);
  else if (root.namespaceURI === NS.samlp && root.localName === "AuthnRequest") await requestReport(msg, doc, opts, report);
  else throw new UsageError(`don't know how to explain {${root.namespaceURI}}${root.localName}`);
  if (opts.showXml) {
    report.data.xml = msg.xml;
    report.output = prettyXml(msg.xml) + (report.data.decryptedAssertion ? `\n\n${prettyXml(String(report.data.decryptedAssertion))}` : "");
  }
  return report;
}
