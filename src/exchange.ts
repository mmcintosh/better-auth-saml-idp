/**
 * Assertion exchange (D-071): an OAuth authorization server on the same Better Auth instance
 * (an ID-JAG issuer) asks "did this IdP issue this Assertion, to the SP this client
 * stands for, and has it not been exchanged before?" (draft-ietf-oauth-identity-assertion-authz-
 * grant §4.5, RFC 8693 with a SAML 2.0 subject token). Only the IdP can answer: it holds the
 * signing keys, its SPs and tenants, and the record written when the assertion was issued.
 *
 * The capability is published on Better Auth's context as `samlIdpExchange` (version 1), only when
 * exchange is on; `getSamlIdpExchange(ctx)` reads it. Verification never fetches anything.
 */
import type { GenericEndpointContext } from "better-auth";
import { emit } from "./events";
import { isBanned, lookupLog, routeIdentity, tenantOf, type PluginState } from "./endpoints/issue";
import { hasOrganizationPlugin, loadMemberships, matchOrganization } from "./organizations";
import type { IdpIdentity } from "./saml/identity";
import { idpBaseURL, METADATA_PATH } from "./saml/idp";
import { checkMessageShape, logSafe, MAX_SAML_ID_LENGTH } from "./saml/request";
import { TenantKeyError } from "./saml/tenant-keys";
import { precheckXml } from "./saml/validator";
import { parseXmlStrict } from "./saml/xml";
import { verifyEnvelopedSignature } from "./saml/xmldsig";
import { consumeExchangeable } from "./storage/exchange-record";
import { trimSlashes } from "./url";

/** What `verifyIssuedAssertion` vouches for. */
export interface VerifiedAssertion {
  assertionId: string;
  /** The Assertion's Issuer: the root IdP's entity ID, or a tenant's. */
  issuer: string;
  /** The tenant's organization id (D-052); null for the root IdP. */
  tenantId: string | null;
  serviceProvider: { id: string; entityId: string };
  userId: string;
  /** The IdP session the assertion was issued in. */
  sessionId?: string;
  nameId: string;
  nameIdFormat: string;
  authnInstant: Date;
  authnContextClassRef?: string;
  notOnOrAfter: Date;
}

export type AssertionExchangeErrorCode =
  | "MALFORMED"
  | "NOT_OURS"
  | "BAD_SIGNATURE"
  | "NOT_YET_VALID"
  | "EXPIRED"
  | "NOT_EXCHANGEABLE"
  | "WRONG_CLIENT"
  | "ALREADY_EXCHANGED"
  | "ACCOUNT_INACTIVE";

/** Why an assertion can't be exchanged. The message is for logs, never for the client. */
export class AssertionExchangeError extends Error {
  constructor(
    readonly code: AssertionExchangeErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "AssertionExchangeError";
  }
}

export interface SamlIdpExchange {
  version: 1;
  /**
   * Verify an Assertion this IdP issued, presented by OAuth client `expected.clientId`, and consume
   * it: a second call with the same assertion fails with `ALREADY_EXCHANGED`. Throws
   * `AssertionExchangeError`. `assertionXml` is the decrypted `<saml:Assertion>` element alone.
   */
  verifyIssuedAssertion(ctx: GenericEndpointContext, assertionXml: string, expected: { clientId: string; now?: Date }): Promise<VerifiedAssertion>;
}

/** The capability, from any endpoint or hook context of the same Better Auth instance; undefined when exchange is off. */
export function getSamlIdpExchange(ctx: { context: unknown }): SamlIdpExchange | undefined {
  const x = (ctx?.context as { samlIdpExchange?: Partial<SamlIdpExchange> } | null | undefined)?.samlIdpExchange;
  return x && x.version === 1 && typeof x.verifyIssuedAssertion === "function" ? (x as SamlIdpExchange) : undefined;
}

const SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const DS = "http://www.w3.org/2000/09/xmldsig#";
const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
/** The largest assertion accepted (the AuthnRequest cap): ours are a few KiB. */
export const MAX_ASSERTION_BYTES = 64 * 1024;
const NCNAME = /^[A-Za-z_][A-Za-z0-9_.-]*$/;
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;

const refuse = (code: AssertionExchangeErrorCode, detail: string) => new AssertionExchangeError(code, logSafe(detail, 300));
const malformed = (detail: string) => refuse("MALFORMED", detail);

/** Element children; any non-whitespace text between them is refused (none of ours carry mixed content). */
function elements(el: any): any[] {
  const out: any[] = [];
  for (let c = el.firstChild; c; c = c.nextSibling) {
    if (c.nodeType === 1) out.push(c);
    else if ((c.nodeType === 3 || c.nodeType === 4) && /\S/.test(c.data ?? "")) throw malformed(`text inside ${el.localName}`);
    else if (c.nodeType !== 3 && c.nodeType !== 8) throw malformed(`unexpected node inside ${el.localName}`);
  }
  return out;
}

/** Exactly these children, in this order (`?` marks an optional last one). */
function expectChildren(el: any, names: readonly string[]): any[] {
  const kids = elements(el);
  const required = names.filter((n) => !n.endsWith("?"));
  const fits =
    kids.length >= required.length &&
    kids.length <= names.length &&
    kids.every((k, i) => {
      const want = names[i]?.replace(/\?$/, "");
      const [ns, local] = want?.startsWith("ds:") ? [DS, want.slice(3)] : [SAML, want];
      return k.namespaceURI === ns && k.localName === local;
    });
  if (!fits) throw malformed(`${el.localName} has children ${kids.map((k) => k.localName).join(",") || "(none)"}; expected ${names.join(",")}`);
  return kids;
}

/** Only these attributes (namespace declarations aside). */
function expectAttributes(el: any, allowed: readonly string[]): void {
  for (const a of Array.from(el.attributes as ArrayLike<any>)) {
    if (a.name === "xmlns" || a.prefix === "xmlns") continue;
    if (a.namespaceURI || !allowed.includes(a.localName)) throw malformed(`${el.localName} has attribute ${a.name}`);
  }
}

function instantAttr(el: any, name: string): Date {
  const v = el.getAttribute(name);
  const t = typeof v === "string" && INSTANT.test(v) ? new Date(v) : undefined;
  if (!t || Number.isNaN(t.getTime())) throw malformed(`${el.localName}/@${name} is not an instant`);
  return t;
}

const text = (el: any): string => String(el.textContent ?? "");

/** The identity the Issuer names: the root, or an enabled tenant (its own key under per-tenant keys). */
async function issuerIdentity(ctx: GenericEndpointContext, state: PluginState, issuer: string): Promise<IdpIdentity | undefined> {
  const root = await routeIdentity(ctx, state, undefined);
  if (root && issuer === root.entityId) return root;
  if (!state.tenants) return undefined;
  const prefix = `${trimSlashes(idpBaseURL(state.options, ctx.context.baseURL))}${METADATA_PATH}/`;
  if (!issuer.startsWith(prefix)) return undefined;
  try {
    const identity = await routeIdentity(ctx, state, issuer.slice(prefix.length));
    return identity?.entityId === issuer ? identity : undefined;
  } catch (e) {
    // The tenant's own key can't be used (D-058): nothing it signed is recognised.
    if (e instanceof TenantKeyError) return undefined;
    throw e;
  }
}

/** Truthy like Better Auth's admin plugin (some adapters return 1 for a boolean column). */
const truthy = (v: unknown) => v === true || v === 1 || v === "1" || v === "true";

export function createExchange(state: PluginState): SamlIdpExchange {
  return {
    version: 1,
    async verifyIssuedAssertion(ctx, assertionXml, expected) {
      try {
        return await verify(ctx, state, assertionXml, expected);
      } catch (e) {
        if (e instanceof AssertionExchangeError) ctx.context.logger.debug(`[saml-idp] assertion exchange refused: ${e.code}: ${e.message}`);
        throw e;
      }
    },
  };
}

async function verify(ctx: GenericEndpointContext, state: PluginState, xml: string, expected: { clientId: string; now?: Date }): Promise<VerifiedAssertion> {
  const options = state.options;
  if (typeof expected?.clientId !== "string" || expected.clientId === "") throw refuse("WRONG_CLIENT", "no client id");
  const now = expected.now ?? new Date();
  const skewMs = options.clockSkewSeconds * 1000;

  // 1. Strict input. The client presents the Assertion alone, decrypted: never a Response.
  if (typeof xml !== "string" || xml === "") throw malformed("empty");
  const pre = precheckXml(xml, MAX_ASSERTION_BYTES);
  if (pre.length) throw malformed(pre.join("; "));
  let doc: any;
  try {
    doc = parseXmlStrict(xml);
    checkMessageShape(doc);
  } catch (e) {
    throw malformed((e as Error).message);
  }
  const root = doc.documentElement;
  if (root.namespaceURI !== SAML || root.localName !== "Assertion") throw malformed(`root is ${root.localName}, not saml:Assertion`);
  if (root.getAttribute("Version") !== "2.0") throw malformed("Version is not 2.0");
  const assertionId = root.getAttribute("ID");
  if (!assertionId || assertionId.length > MAX_SAML_ID_LENGTH || !NCNAME.test(assertionId)) throw malformed("missing or invalid ID");

  // 2. The SAML schema.
  const schema = await options.schemaValidator.validate(xml, "protocol");
  if (!schema.valid) throw malformed(`schema: ${schema.errors.slice(0, 3).join("; ")}`);

  // 3. Whose assertion: the Issuer must be the root IdP or an enabled tenant.
  // An unsigned assertion is a signature failure (step 4), not a shape one.
  const second = elements(root)[1];
  const signed = second?.namespaceURI === DS && second.localName === "Signature";
  const kids = expectChildren(root, ["Issuer", ...(signed ? ["ds:Signature"] : []), "Subject", "Conditions", "AuthnStatement", "AttributeStatement?"]);
  const [issuerEl, subject, conditions, authn] = signed ? [kids[0], ...kids.slice(2)] : kids;
  expectAttributes(issuerEl, ["Format"]);
  const issuerFormat = issuerEl.getAttribute("Format");
  if (issuerFormat && issuerFormat !== ENTITY) throw refuse("NOT_OURS", "Issuer has another Format");
  const issuer = text(issuerEl);
  const identity = await issuerIdentity(ctx, state, issuer);
  if (!identity) throw refuse("NOT_OURS", `Issuer ${issuer} is not this IdP or an enabled tenant`);

  // 4. Our signature, on the Assertion itself, with that identity's key only (KeyInfo is ignored).
  const sig = verifyEnvelopedSignature(xml, doc, root, [identity.signing.certificate], { allowSha1: options.signing.allowInsecureSha1 });
  if (!signed || !sig.present) throw refuse("BAD_SIGNATURE", "the Assertion is not signed");
  if (sig.valid !== true) throw refuse("BAD_SIGNATURE", sig.problem ?? "signature does not verify");

  // 5. Exactly the shape this IdP issues (buildResponseXml).
  expectAttributes(root, ["ID", "Version", "IssueInstant"]);
  const [nameIdEl, confirmation] = expectChildren(subject, ["NameID", "SubjectConfirmation"]);
  expectAttributes(nameIdEl, ["Format"]);
  const nameIdFormat = nameIdEl.getAttribute("Format");
  if (!nameIdFormat) throw malformed("NameID has no Format");
  const nameId = text(nameIdEl);
  if (confirmation.getAttribute("Method") !== BEARER) throw malformed("SubjectConfirmation is not bearer");
  const [confirmationData] = expectChildren(confirmation, ["SubjectConfirmationData"]);
  expectChildren(confirmationData, []);
  expectAttributes(confirmationData, ["NotOnOrAfter", "Recipient", "InResponseTo"]);
  expectAttributes(conditions, ["NotBefore", "NotOnOrAfter"]);
  const [restriction] = expectChildren(conditions, ["AudienceRestriction"]);
  const [audienceEl] = expectChildren(restriction, ["Audience"]);
  const audience = text(audienceEl);
  expectAttributes(authn, ["AuthnInstant", "SessionIndex", "SessionNotOnOrAfter"]);
  const [authnContext] = expectChildren(authn, ["AuthnContext"]);
  const [classRef] = expectChildren(authnContext, ["AuthnContextClassRef"]);
  const authnContextClassRef = text(classRef);
  const authnInstant = instantAttr(authn, "AuthnInstant");

  // 6. Validity window, with clock skew and no grace beyond it.
  const notBefore = instantAttr(conditions, "NotBefore");
  const notOnOrAfter = instantAttr(conditions, "NotOnOrAfter");
  const confirmationEnd = instantAttr(confirmationData, "NotOnOrAfter");
  if (now.getTime() < notBefore.getTime() - skewMs) throw refuse("NOT_YET_VALID", "before Conditions/@NotBefore");
  if (now.getTime() >= notOnOrAfter.getTime() + skewMs || now.getTime() >= confirmationEnd.getTime() + skewMs) throw refuse("EXPIRED", "past NotOnOrAfter");

  // 7. The audience's SP, in the issuing identity's tenant: it must have opted in, for this client.
  // Never prepareSp: no metadata fetch.
  const sp = await state.directory.byEntityId(ctx.context.adapter as any, audience, lookupLog(ctx), identity.tenantId ?? "");
  if (!sp || (sp.tenantId ?? null) !== identity.tenantId) throw refuse("NOT_EXCHANGEABLE", `no enabled SP ${audience} in this identity`);
  if (!sp.tokenExchange || !options.tokenExchange) throw refuse("NOT_EXCHANGEABLE", `SP ${sp.id} has no tokenExchange`);
  if (sp.tokenExchange.clientId !== expected.clientId) throw refuse("WRONG_CLIENT", `SP ${sp.id} is exchanged by another client`);

  // 8. Single use. Consumed only after the signature, so made-up IDs can't burn records; before
  // the principal check, so it is used up whatever the outcome.
  const record = await consumeExchangeable(ctx.context.internalAdapter, assertionId);
  if (!record) throw refuse("ALREADY_EXCHANGED", `assertion ${assertionId} has no record (exchanged, expired, or issued before the SP opted in)`);
  const mismatch = (
    [
      ["spId", record.spId, sp.id],
      ["tenantId", record.tenantId, identity.tenantId],
      ["issuer", record.issuer, issuer],
      ["nameId", record.nameId, nameId],
      ["nameIdFormat", record.nameIdFormat, nameIdFormat],
      ["notOnOrAfter", record.notOnOrAfter, notOnOrAfter.toISOString().replace(/\.\d{3}Z$/, "Z")],
      ["authnInstant", record.authnInstant, authnInstant.toISOString().replace(/\.\d{3}Z$/, "Z")],
      ["acr", record.acr, authnContextClassRef],
    ] as const
  ).find(([, a, b]) => a !== b);
  if (mismatch) {
    ctx.context.logger.error(`[saml-idp] assertion ${assertionId}: its ${mismatch[0]} differs from what was recorded at issuance; refused`);
    throw refuse("NOT_OURS", `recorded ${mismatch[0]} differs`);
  }

  // 9. The principal, now (authorize() isn't re-run: it ran at issuance, minutes ago).
  const inactive = (detail: string) => refuse("ACCOUNT_INACTIVE", detail);
  const user = (await ctx.context.internalAdapter.findUserById(record.userId)) as (Record<string, unknown> & { id: string }) | null;
  if (!user) throw inactive("user no longer exists");
  if (isBanned(user, now)) throw inactive("user is banned");
  const policy = options.accountPolicy;
  if (policy.requireEmailVerified && !truthy(user.emailVerified)) throw inactive("email not verified");
  if (!policy.allowAnonymousUsers && truthy(user.isAnonymous)) throw inactive("anonymous user");
  const opts = ctx.context.options as { secondaryStorage?: unknown; session?: { storeSessionInDatabase?: boolean } };
  if (!opts.secondaryStorage || opts.session?.storeSessionInDatabase === true) {
    const session = (await ctx.context.adapter.findOne({ model: "session", where: [{ field: "id", value: record.sessionId }] })) as {
      userId?: unknown;
      expiresAt?: Date | string;
      impersonatedBy?: unknown;
    } | null;
    if (!session || String(session.userId) !== record.userId) throw inactive("session no longer exists");
    if (!session.expiresAt || new Date(session.expiresAt).getTime() <= now.getTime()) throw inactive("session expired");
    if (!policy.allowImpersonatedSessions && session.impersonatedBy) throw inactive("impersonated session");
  }
  if (identity.tenantId !== null && sp.organization?.id !== identity.tenantId) {
    ctx.context.logger.error(`[saml-idp] SP ${sp.id} is in tenant ${identity.tenantId} without its membership rule; not exchanging`);
    throw inactive("tenant SP without its membership rule");
  }
  if (sp.organization) {
    if (!hasOrganizationPlugin(ctx.context.options.plugins as { id: string }[] | undefined)) throw inactive("the organization plugin isn't installed");
    if (!matchOrganization(await loadMemberships(ctx.context.adapter as any, user.id), sp.organization)) throw inactive("no longer a member of the SP's organization");
  }

  // 10. Audit.
  emit(ctx, options, {
    type: "assertion.exchanged",
    spId: sp.id,
    entityId: sp.entityId,
    userId: user.id,
    assertionId,
    clientId: expected.clientId,
    ...tenantOf(sp),
  });
  return {
    assertionId,
    issuer,
    tenantId: identity.tenantId,
    serviceProvider: { id: sp.id, entityId: sp.entityId },
    userId: user.id,
    sessionId: record.sessionId,
    nameId,
    nameIdFormat,
    authnInstant,
    authnContextClassRef,
    notOnOrAfter,
  };
}
