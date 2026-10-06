/**
 * Exchangeable assertions (D-071): one Better Auth verification value per assertion issued to an
 * SP with `tokenExchange`, written with `createVerificationValue` and read back ONLY through
 * `consumeVerificationValue` (the pending-request pattern, ADDENDUM-01 R1), so each assertion is
 * exchanged at most once, whichever instance gets it first. No row exists for any other SP.
 */
import { sha256b64url } from "./pending";

const PREFIX = "saml-idp:exchange:";

/** What issuance knew, compared field by field with the presented assertion at exchange. */
export interface ExchangeRecord {
  spId: string;
  /** The SP's tenant (D-052); null for the root IdP. */
  tenantId: string | null;
  userId: string;
  sessionId: string;
  nameId: string;
  nameIdFormat: string;
  /** The Assertion's Issuer. */
  issuer: string;
  /** As in the XML: `Conditions/@NotOnOrAfter`, `AuthnStatement/@AuthnInstant`, the class. */
  notOnOrAfter: string;
  authnInstant: string;
  acr: string;
}

type Adapter = {
  createVerificationValue(data: { identifier: string; value: string; expiresAt: Date }): Promise<unknown>;
  consumeVerificationValue(identifier: string): Promise<{ value: string; expiresAt: Date } | null>;
};

/** The assertion ID is hashed, so the table holds no value an SP has seen. */
const identifier = async (assertionId: string) => PREFIX + (await sha256b64url(assertionId));

export async function recordExchangeable(adapter: Adapter, assertionId: string, record: ExchangeRecord, skewSeconds: number): Promise<void> {
  const expiresAt = new Date(new Date(record.notOnOrAfter).getTime() + skewSeconds * 1000);
  await adapter.createVerificationValue({ identifier: await identifier(assertionId), value: JSON.stringify(record), expiresAt });
}

/** The record, removed as it is read; null when there is none (never recorded, used, or expired). */
export async function consumeExchangeable(adapter: Adapter, assertionId: string): Promise<ExchangeRecord | null> {
  const row = await adapter.consumeVerificationValue(await identifier(assertionId));
  if (!row) return null;
  try {
    const r = JSON.parse(row.value) as Partial<ExchangeRecord>;
    const str = (v: unknown) => typeof v === "string";
    if (![r.spId, r.userId, r.sessionId, r.nameId, r.nameIdFormat, r.issuer, r.notOnOrAfter, r.authnInstant, r.acr].every(str)) return null;
    if (r.tenantId !== null && !str(r.tenantId)) return null;
    return r as ExchangeRecord;
  } catch {
    return null;
  }
}
