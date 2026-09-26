/**
 * Observability (D-038): callbacks for what the IdP did, and an optional audit-log table.
 *
 * Handlers are observers. They run in the background (Better Auth's `runInBackground`, which is
 * `waitUntil` on Workers), so they never delay a response. A handler that throws or rejects is
 * logged, and the flow it observed is unaffected.
 */
import type { GenericEndpointContext } from "better-auth";
import type { SamlIdpErrorCode } from "./errors";
import { logSafe } from "./saml/request";

interface EventBase {
  at: Date;
  /** The client's IP, read like Better Auth reads it (`advanced.ipAddress`); absent when disabled. */
  ipAddress?: string;
  userAgent?: string;
}

/** An assertion was signed and handed to the browser for the SP's ACS. */
export interface AssertionIssuedEvent extends EventBase {
  type: "assertion.issued";
  spId: string;
  entityId: string;
  userId: string;
  sessionId: string;
  assertionId: string;
  /** "sp" for a Response to an AuthnRequest, "idp" for IdP-initiated SSO. */
  initiatedBy: "sp" | "idp";
  /** The AuthnRequest's ID (SP-initiated only). */
  inResponseTo?: string;
  acsUrl: string;
  nameIdFormat: string;
  /** The NameID as sent. It may be personal data (an email address). */
  nameId: string;
  /** Names of the attributes sent (not their values). */
  attributes: string[];
  encrypted: boolean;
}

/**
 * The IdP refused something: an error page (`code`), or a SAML error Response to the SP
 * (`code: "SAML_STATUS"` with `status`). Includes unauthenticated protocol errors, which is
 * what a SIEM wants to see, and what an attacker can generate at will.
 */
export interface DeniedEvent extends EventBase {
  type: "denied";
  code: SamlIdpErrorCode | "SAML_STATUS";
  status?: { code: string; subCode?: string };
  /** The SP concerned, when the request identified one. */
  spId?: string;
  /** The signed-in user, when there was one. */
  userId?: string;
  /** Why, as in the debug log (log-safe, at most 300 characters). */
  detail?: string;
}

/** An IdP session was ended by Single Logout. */
export interface LogoutEvent extends EventBase {
  type: "logout";
  /** "sp": an SP's LogoutRequest; "idp": the app's sign-out-everywhere. */
  initiatedBy: "sp" | "idp";
  /** The SP whose LogoutRequest started it (SP-initiated only). */
  spId?: string;
  userId: string;
  sessionId: string;
  /** The other SPs that will be sent a LogoutRequest, in order. */
  notifying: string[];
}

export type SamlIdpEvent = AssertionIssuedEvent | DeniedEvent | LogoutEvent;

export interface SamlIdpEventHandlers {
  onAssertionIssued?: (event: AssertionIssuedEvent) => void | Promise<void>;
  onDenied?: (event: DeniedEvent) => void | Promise<void>;
  onLogout?: (event: LogoutEvent) => void | Promise<void>;
}

export interface AuditLogOptions {
  enabled: boolean;
  /** Days to keep rows; expired rows are swept. Default 90. */
  retentionDays?: number;
}

export const AUDIT_MODEL = "samlIdpAuditEvent";

type Emitter = { events?: SamlIdpEventHandlers; auditLog?: { retentionDays: number } };

/** The request's client IP, as Better Auth reads it. */
function clientIp(ctx: GenericEndpointContext): string | undefined {
  const opts = ctx.context.options as { advanced?: { ipAddress?: { disableIpTracking?: boolean; ipAddressHeaders?: string[] } } };
  const ip = opts.advanced?.ipAddress;
  if (ip?.disableIpTracking) return undefined;
  const headers = ctx.request?.headers ?? ctx.headers;
  for (const name of ip?.ipAddressHeaders ?? ["x-forwarded-for"]) {
    const value = headers?.get(name)?.split(",")[0]?.trim();
    if (value) return logSafe(value, 64);
  }
  return undefined;
}

/** Fill in the request fields and hand the event to its handler and the audit log, in the background. */
export function emit(ctx: GenericEndpointContext, options: Emitter, event: Omit<AssertionIssuedEvent, keyof EventBase> | Omit<DeniedEvent, keyof EventBase> | Omit<LogoutEvent, keyof EventBase>): void {
  const handler =
    event.type === "assertion.issued" ? options.events?.onAssertionIssued : event.type === "denied" ? options.events?.onDenied : options.events?.onLogout;
  // Unauthenticated denials (no SP identified, no user) go to the handler but not the table:
  // anyone can generate them, and the table shouldn't grow at an attacker's pace.
  const audit = options.auditLog && !(event.type === "denied" && !event.spId && !event.userId);
  if (!handler && !audit) return;
  const userAgent = (ctx.request?.headers ?? ctx.headers)?.get("user-agent");
  const full = { ...event, at: new Date(), ipAddress: clientIp(ctx), userAgent: userAgent ? logSafe(userAgent, 300) : undefined } as SamlIdpEvent;
  const run = async () => {
    if (handler) {
      try {
        await (handler as (e: SamlIdpEvent) => unknown)(full);
      } catch (e) {
        ctx.context.logger.error(`[saml-idp] events.on${full.type === "assertion.issued" ? "AssertionIssued" : full.type === "denied" ? "Denied" : "Logout"} threw`, e);
      }
    }
    if (audit && options.auditLog) {
      try {
        await ctx.context.adapter.create({ model: AUDIT_MODEL, data: auditRow(full, options.auditLog.retentionDays) });
      } catch (e) {
        ctx.context.logger.error(`[saml-idp] could not write the audit log (${full.type})`, e);
      }
    }
  };
  ctx.context.runInBackground(run());
}

/** The table row: indexed columns for querying, the rest of the event as JSON. */
export function auditRow(event: SamlIdpEvent, retentionDays: number) {
  const { type, at, ipAddress, userAgent, ...rest } = event;
  const spId = "spId" in rest ? rest.spId : undefined;
  const userId = "userId" in rest ? rest.userId : undefined;
  const code = event.type === "denied" ? event.code : undefined;
  return {
    type,
    at,
    spId: spId ?? null,
    userId: userId ?? null,
    code: code ?? null,
    ipAddress: ipAddress ?? null,
    userAgent: userAgent ?? null,
    details: JSON.stringify(rest),
    expiresAt: new Date(at.getTime() + retentionDays * 86_400_000),
  };
}
