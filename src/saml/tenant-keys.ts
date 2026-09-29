// Per-tenant signing keys (tenants.keys: "per-tenant", D-058). One `samlIdpTenantKey` row per key,
// in one of four states: `next` (published, not signing yet), `active` (signs), `previous` (the
// key it replaced, still published) and `retired` (neither; its private key is erased). A tenant
// that has never activated a key of its own signs with the shared `signing` key, which is how
// tenants made before per-tenant keys keep working until they rotate. Once it has an active key,
// nothing else ever signs for it: a key that fails to load refuses the request, never falls back.
//
// Private keys are stored encrypted with Better Auth's secret (its versioned `secrets`, or
// `tenants.keyEncryptionSecret`). The cipher has no associated data, so the plaintext names its
// purpose, tenant and key id, and they must match the row: a ciphertext copied from another row,
// or from anything else Better Auth encrypts with that secret, is refused. This protects backups,
// dumps and read-only database leaks, not a compromised Worker (the secret lives there too).
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, type KeyObject, X509Certificate } from "node:crypto";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import type { ResolvedSamlIdpOptions } from "../types";
import { selfSignedCertificate } from "./certificate";

export const TENANT_KEY_MODEL = "samlIdpTenantKey";
export type TenantKeyState = "next" | "active" | "previous" | "retired";
/** The kid of a `previous` row that records the shared key a tenant used before its own. */
export const SHARED_KID = "shared";
/** Generated keys: RSA 3072 (maintainer decision, D-058), a two-year certificate. */
export const GENERATED_KEY_BITS = 3072;
export const GENERATED_CERT_DAYS = 730;
const PURPOSE = "better-auth-saml-idp/tenant-signing-key";
const MAX_CACHE_ENTRIES = 1000;

export interface TenantKeyRow {
  id: string;
  tenantId: string;
  kid: string;
  state: TenantKeyState;
  /** UNIQUE: hash(tenantId, state) for `next` and `active`, so a tenant has at most one of each. */
  stateKey: string;
  /** Empty once retired, and for the shared key's `previous` row. */
  encryptedPrivateKey: string;
  certificate: string;
  notAfter: Date | string;
  createdAt: Date | string;
  activatedAt?: Date | string | null;
  updatedBy?: string | null;
}

/** The secret that encrypts tenant keys: `tenants.keyEncryptionSecret`, else Better Auth's. */
export type KeySecret = Parameters<typeof symmetricEncrypt>[0]["key"];

export class TenantKeyError extends Error {}

/** `next`/`active` rows collide on this; other states get a unique value. */
export function stateKeyOf(tenantId: string, state: TenantKeyState): string {
  if (state !== "next" && state !== "active") return `${state}:${randomUUID()}`;
  return createHash("sha256").update(`${tenantId}\u0000${state}`).digest("base64url");
}

export async function encryptTenantKey(secret: KeySecret, tenantId: string, kid: string, privateKeyPem: string): Promise<string> {
  return symmetricEncrypt({ key: secret, data: JSON.stringify({ purpose: PURPOSE, v: 1, tenantId, kid, privateKeyPem }) });
}

/** The row's private key, refused unless the ciphertext says it is this row's. */
export async function decryptTenantKey(secret: KeySecret, row: Pick<TenantKeyRow, "tenantId" | "kid" | "encryptedPrivateKey">): Promise<string> {
  let plain: { purpose?: unknown; v?: unknown; tenantId?: unknown; kid?: unknown; privateKeyPem?: unknown };
  try {
    plain = JSON.parse(await symmetricDecrypt({ key: secret, data: row.encryptedPrivateKey }));
  } catch (e) {
    throw new TenantKeyError(`tenant ${row.tenantId} key ${row.kid}: can't be decrypted (${(e as Error).message})`);
  }
  if (plain.purpose !== PURPOSE || plain.v !== 1 || plain.tenantId !== row.tenantId || plain.kid !== row.kid || typeof plain.privateKeyPem !== "string")
    throw new TenantKeyError(`tenant ${row.tenantId} key ${row.kid}: the stored key belongs to another row`);
  return plain.privateKeyPem;
}

/** An RSA key and certificate that belong together, as the root key is checked at startup. */
export function checkKeyPair(privateKeyPem: string, certificatePem: string): { key: KeyObject; notAfter: Date } {
  let key: KeyObject;
  let cert: X509Certificate;
  try {
    key = createPrivateKey(privateKeyPem);
    cert = new X509Certificate(certificatePem);
  } catch (e) {
    throw new TenantKeyError(`the key or certificate can't be parsed (${(e as Error).message})`);
  }
  if (key.asymmetricKeyType !== "rsa") throw new TenantKeyError(`the key must be RSA, got ${key.asymmetricKeyType}`);
  if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new TenantKeyError("the key must be at least 2048 bits");
  const spki = (k: KeyObject) => k.export({ type: "spki", format: "pem" }).toString();
  if (spki(cert.publicKey) !== spki(createPublicKey(key))) throw new TenantKeyError("the certificate doesn't match the key");
  return { key, notAfter: new Date(cert.validTo) };
}

/** A new key for a tenant: RSA 3072 and a self-signed certificate named after its key. */
export function generateTenantKey(tenantKey: string, now = new Date()): { privateKeyPem: string; certificate: string } {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: GENERATED_KEY_BITS });
  const certificate = selfSignedCertificate(privateKey, { commonName: `saml-idp tenant ${tenantKey}`, days: GENERATED_CERT_DAYS, now });
  return { privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(), certificate };
}

type Adapter = {
  findMany(args: { model: string; where: { field: string; value: unknown }[]; limit?: number }): Promise<unknown[]>;
};
type Signing = ResolvedSamlIdpOptions["signing"];

/**
 * A tenant's keys, and the signing configuration they give, per isolate. Rows are cached for
 * `cacheMs` like tenants (a rotation reaches other isolates within that time); a decrypted key
 * is cached by row, so a rotation or a re-read never reuses another row's key.
 */
export class TenantKeyStore {
  private readonly rows = new Map<string, { rows: TenantKeyRow[]; expires: number }>();
  private readonly keys = new Map<string, { key: KeyObject; pem: string }>();

  constructor(
    private readonly cacheMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  invalidate(): void {
    this.rows.clear();
  }

  /** The tenant's rows, exactly its own (a case-insensitive collation must not widen them). */
  async load(adapter: Adapter, tenantId: string): Promise<TenantKeyRow[]> {
    const hit = this.rows.get(tenantId);
    if (hit && hit.expires > this.now()) return hit.rows;
    const found = (await adapter.findMany({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: tenantId }], limit: 50 })) as TenantKeyRow[];
    const rows = found.filter((r) => r.tenantId === tenantId);
    if (this.cacheMs > 0) {
      if (this.rows.size >= MAX_CACHE_ENTRIES) this.rows.clear();
      this.rows.set(tenantId, { rows, expires: this.now() + this.cacheMs });
    }
    return rows;
  }

  /**
   * What the tenant signs with, and the certificates its metadata publishes: its active key with
   * its next and previous certificates, or, before it has one, the shared key with its next.
   * Throws TenantKeyError when its active key can't be used; the caller refuses the request.
   */
  async signing(adapter: Adapter, secret: KeySecret, tenantId: string, shared: Signing): Promise<Signing> {
    const rows = await this.load(adapter, tenantId);
    const of = (state: TenantKeyState) => rows.filter((r) => r.state === state);
    const active = of("active");
    const published = [...of("next"), ...of("previous")].map((r) => r.certificate);
    if (active.length > 1) throw new TenantKeyError(`tenant ${tenantId}: more than one active key`);
    const own = active[0];
    if (!own) {
      // Only a tenant that has never had a key of its own signs with the shared one. Once it has
      // had one (an activation mid-way, or rows left inconsistent), refuse: never fall back.
      if (rows.some((r) => r.kid !== SHARED_KID && r.state !== "next")) throw new TenantKeyError(`tenant ${tenantId}: no active signing key`);
      return { ...shared, additionalCertificates: [...shared.additionalCertificates, ...published] };
    }
    const cacheKey = `${own.id}\u0000${own.kid}\u0000${own.encryptedPrivateKey.length}`;
    let loaded = this.keys.get(cacheKey);
    if (!loaded) {
      const pem = await decryptTenantKey(secret, own);
      loaded = { key: checkKeyPair(pem, own.certificate).key, pem };
      if (this.keys.size >= MAX_CACHE_ENTRIES) this.keys.clear();
      this.keys.set(cacheKey, loaded);
    }
    return {
      ...shared,
      privateKey: loaded.pem,
      keyObject: loaded.key,
      certificate: own.certificate,
      additionalCertificates: published.filter((c) => c !== own.certificate),
    };
  }
}
