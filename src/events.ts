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
  /** The SP's tenant (an organization id, D-052); absent for the root IdP. */
  tenantId?: string;
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
  /** The tenant (an organization id, D-052) of the SP concerned, when it has one. */
  tenantId?: string;
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
  /** The tenant (D-052) of the SP whose LogoutRequest started it, when it has one. */
  tenantId?: string;
}

/**
 * An IdP session ended *without* Single Logout (D-043): an admin revoked or disabled it, the user
 * signed out through Better Auth's own `/sign-out`, a factor change ended it, or it expired. The
 * SPs listed received assertions in that session and were **not** sent a LogoutRequest; their
 * own sessions carry on until they end them. Act on them yourself (SCIM, an SP's session API),
 * or record them. The same list stays available from `auth.api.samlIdpListSessionParticipants`
 * until the rows expire.
 */
export interface SessionEndedEvent extends EventBase {
  type: "session.ended";
  userId: string;
  sessionId: string;
  /**
   * "signed-out": Better Auth's `/sign-out`. "expired": the session had passed its expiry.
   * "revoked": anything else (admin actions, revoke-sessions, a factor change, a direct delete).
   */
  reason: "revoked" | "signed-out" | "expired";
  participants: {
    spId: string;
    /** The SP's entity ID, if it is still configured. */
    entityId?: string;
    nameId: string;
    nameIdFormat: string;
    sessionIndex: string;
    /** The SP's tenant (D-052), when it has one and is still configured. */
    tenantId?: string;
  }[];
  /** More SPs took part than the event lists (the cap is 200); all of them were marked ended. */
  truncated: boolean;
}

export type SamlIdpEvent = AssertionIssuedEvent | DeniedEvent | LogoutEvent | SessionEndedEvent;

export interface SamlIdpEventHandlers {
  onAssertionIssued?: (event: AssertionIssuedEvent) => void | Promise<void>;
  onDenied?: (event: DeniedEvent) => void | Promise<void>;
  onLogout?: (event: LogoutEvent) => void | Promise<void>;
  /**
   * A session ended without Single Logout (D-043). Setting it also turns on the participant
   * tracking it needs (the `samlIdpSessionParticipant` table), even without `singleLogout`.
   */
  onSessionEnded?: (event: SessionEndedEvent) => void | Promise<void>;
}

export interface AuditLogOptions {
  enabled: boolean;
  /** Days to keep rows; expired rows are swept. Default 90. */
  retentionDays?: number;
}

export const AUDIT_MODEL = "samlIdpAuditEvent";

type Emitter = { events?: SamlIdpEventHandlers; auditLog?: { retentionDays: number }; tenants?: unknown };

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

type EventInput =
  | Omit<AssertionIssuedEvent, keyof EventBase>
  | Omit<DeniedEvent, keyof EventBase>
  | Omit<LogoutEvent, keyof EventBase>
  | Omit<SessionEndedEvent, keyof EventBase>;

const HANDLER = {
  "assertion.issued": "onAssertionIssued",
  denied: "onDenied",
  logout: "onLogout",
  "session.ended": "onSessionEnded",
} as const satisfies Record<SamlIdpEvent["type"], keyof SamlIdpEventHandlers>;

/** What delivery needs: the pieces of Better Auth's context, with or without a request. */
type Sink = {
  logger: { error(message: string, ...args: unknown[]): void };
  adapter: { create(a: { model: string; data: Record<string, unknown> }): Promise<unknown> };
  runInBackground(p: Promise<unknown>): void;
};

/** Fill in the request fields and hand the event to its handler and the audit log, in the background. */
export function emit(ctx: GenericEndpointContext, options: Emitter, event: EventInput): void {
  const userAgent = (ctx.request?.headers ?? ctx.headers)?.get("user-agent");
  deliver(ctx.context as unknown as Sink, options, { ...event, at: new Date(), ipAddress: clientIp(ctx), userAgent: userAgent ? logSafe(userAgent, 300) : undefined } as SamlIdpEvent);
}

/**
 * The same, outside a request: a database hook run from a host's own code (an admin page) has no
 * endpoint context, so the event has no IP or user agent (D-043).
 */
export function emitWithoutRequest(sink: Sink, options: Emitter, event: EventInput): void {
  deliver(sink, options, { ...event, at: new Date() } as SamlIdpEvent);
}

function deliver(sink: Sink, options: Emitter, full: SamlIdpEvent): void {
  const name = HANDLER[full.type];
  const handler = options.events?.[name] as ((e: SamlIdpEvent) => unknown) | undefined;
  // Denials without a signed-in user go to the handler but not the table: anyone can generate
  // them, naming any SP (its entity ID is public), and the table mustn't grow at an attacker's
  // pace (R4-3). Session ends are stored only when SPs were left signed in, and never for expiry
  // (every expired session would write a row).
  const audit =
    options.auditLog &&
    !(full.type === "denied" && !full.userId) &&
    !(full.type === "session.ended" && (full.reason === "expired" || full.participants.length === 0));
  if (!handler && !audit) return;
  const run = async () => {
    if (handler) {
      try {
        await handler(full);
      } catch (e) {
        sink.logger.error(`[saml-idp] events.${name} threw`, e);
      }
    }
    if (audit && options.auditLog) {
      try {
        await sink.adapter.create({ model: AUDIT_MODEL, data: auditRow(full, options.auditLog.retentionDays, options.tenants !== undefined) });
      } catch (e) {
        sink.logger.error(`[saml-idp] could not write the audit log (${full.type})`, e);
      }
    }
  };
  sink.runInBackground(run());
}

/** The table row: indexed columns for querying, the rest of the event as JSON. */
export function auditRow(event: SamlIdpEvent, retentionDays: number, tenants = false) {
  const { type, at, ipAddress, userAgent, ...rest } = event;
  const spId = "spId" in rest ? rest.spId : undefined;
  const userId = "userId" in rest ? rest.userId : undefined;
  const code = event.type === "denied" ? event.code : undefined;
  // The column exists only with tenants (D-052); null for the root IdP.
  const tenantId = "tenantId" in rest ? rest.tenantId : undefined;
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
    ...(tenants ? { tenantId: tenantId ?? null } : {}),
  };
}
