// SP metadata URL with refresh (D-026): keep an SP's certificates current without a redeploy.
//
// Only certificates come from the metadata. The entity ID must match the configured one, and
// the ACS URLs are never taken from it, so a compromised metadata endpoint can't redirect
// assertions. Per isolate: the first use waits for a fetch (bounded), later uses get the cached
// copy while a stale one refreshes in the background; failures keep the last good copy, and
// the configured certificates always remain trusted.
import { X509Certificate } from "node:crypto";
import { checkEncryptionCertificate } from "../options";
import type { ResolvedServiceProvider } from "../types";
import type { AssertionEncryption } from "./encrypt";
import { serviceProviderFromMetadata } from "./sp-metadata";
import { precheckXml, type SchemaValidator } from "./validator";
import { parseXmlStrict } from "./xml";
import { verifyEnvelopedSignature } from "./xmldsig";

const MAX_BYTES = 1024 * 1024;
const FETCH_TIMEOUT_MS = 5000;
/** First retry after a failure; doubles up to the refresh interval. */
const MIN_BACKOFF_MS = 5 * 60_000;
/** After this long, an unsettled refresh counts as abandoned. */
const STUCK_MS = 30_000;

interface Learned {
  signingCertificates: string[];
  encryption: AssertionEncryption | undefined;
  fetchedAt: number;
  fingerprints: string;
}

interface Entry {
  learned?: Learned;
  nextAttempt: number;
  backoff: number;
  inflight?: Promise<void>;
  inflightSince?: number;
  lastError?: string;
}

export interface MetadataLogger {
  info(message: string): void;
  warn(message: string): void;
}

export interface MetadataStatus {
  url: string;
  fetchedAt?: Date;
  certificates: number;
  encryptionFromMetadata: boolean;
  lastError?: string;
}

/** Read at most `max` bytes of a body (a server may omit or lie about Content-Length). */
async function readLimited(res: Response, max: number): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      throw new Error(`larger than ${max} bytes`);
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(all);
}

const fingerprint = (pem: string) => new X509Certificate(pem).fingerprint256;

/**
 * Everything the learned certificates depend on: a registry SP's URL, signature pins, entity ID
 * or encryption settings can change at runtime, and certificates learned under the old values
 * must not carry over (e.g. after re-pinning a compromised metadata key; review 2, R2-MD-1).
 */
function cacheKey(sp: ResolvedServiceProvider): string {
  const md = sp.metadata;
  return JSON.stringify([sp.id, sp.entityId, md?.url, md?.signingCertificates.map(fingerprint), sp.encryption ? [sp.encryption.dataAlgorithm, sp.encryption.keyAlgorithm] : null]);
}

export class SpMetadataCache {
  private readonly entries = new Map<string, Entry>();

  constructor(
    private readonly validator: SchemaValidator,
    private readonly now: () => number = Date.now,
  ) {}

  /**
   * The SP with certificates learned from its metadata merged in. Waits for the first fetch in
   * this isolate (at most the fetch timeout); after that, a due refresh runs in the background.
   */
  async prepare(sp: ResolvedServiceProvider, log: MetadataLogger, background: (p: Promise<unknown>) => void): Promise<ResolvedServiceProvider> {
    if (!sp.metadata) return sp;
    const key = cacheKey(sp);
    let entry = this.entries.get(key);
    if (!entry) {
      if (this.entries.size >= 1000) this.entries.clear();
      entry = { nextAttempt: 0, backoff: MIN_BACKOFF_MS };
      this.entries.set(key, entry);
    }
    // A refresh "in flight" for too long was abandoned: on Workers, background work can be
    // cancelled once a response has gone out, and its promise then never settles. Start afresh.
    if (entry.inflight && this.now() - (entry.inflightSince ?? 0) > STUCK_MS) entry.inflight = undefined;
    const due = this.now() >= entry.nextAttempt;
    if (due && !entry.inflight) {
      const run = this.refresh(sp, entry, log).finally(() => {
        if (entry.inflight === run) entry.inflight = undefined;
      });
      entry.inflight = run;
      entry.inflightSince = this.now();
    }
    if (entry.inflight) {
      if (entry.learned) background(entry.inflight);
      // First use: nothing learned yet, so wait, but never longer than the fetch timeout (plus a
      // margin), even if a fetch implementation ignores its abort signal.
      else await Promise.race([entry.inflight, new Promise<void>((r) => setTimeout(r, FETCH_TIMEOUT_MS + 1000))]);
    }
    return this.merge(sp, entry.learned);
  }

  status(sp: ResolvedServiceProvider): MetadataStatus | undefined {
    if (!sp.metadata) return undefined;
    const e = this.entries.get(cacheKey(sp));
    return {
      url: sp.metadata.url,
      fetchedAt: e?.learned ? new Date(e.learned.fetchedAt) : undefined,
      certificates: e?.learned?.signingCertificates.length ?? 0,
      encryptionFromMetadata: e?.learned?.encryption !== undefined,
      lastError: e?.lastError,
    };
  }

  private merge(sp: ResolvedServiceProvider, learned: Learned | undefined): ResolvedServiceProvider {
    if (!learned) return sp;
    const certs = [...sp.spCertificates];
    for (const c of learned.signingCertificates) if (!certs.includes(c)) certs.push(c);
    // A learned encryption key only while encryption is configured, with today's algorithms.
    const encryption = sp.encryption && learned.encryption
      ? { ...sp.encryption, publicKeyPem: learned.encryption.publicKeyPem, certificateBase64: learned.encryption.certificateBase64 }
      : sp.encryption;
    return { ...sp, spCertificates: certs, encryption };
  }

  private async refresh(sp: ResolvedServiceProvider, entry: Entry, log: MetadataLogger): Promise<void> {
    const md = sp.metadata;
    if (!md) return;
    try {
      const learned = await this.load(sp, md);
      if (learned.fingerprints !== entry.learned?.fingerprints)
        log.info(`[saml-idp] SP ${sp.id}: certificates from metadata ${entry.learned ? "changed" : "loaded"} (${learned.signingCertificates.length} signing${learned.encryption ? ", 1 encryption" : ""})`);
      entry.learned = learned;
      entry.lastError = undefined;
      entry.backoff = MIN_BACKOFF_MS;
      entry.nextAttempt = this.now() + md.refreshSeconds * 1000;
    } catch (e) {
      entry.lastError = (e as Error).message;
      entry.nextAttempt = this.now() + entry.backoff;
      entry.backoff = Math.min(entry.backoff * 2, md.refreshSeconds * 1000);
      log.warn(`[saml-idp] SP ${sp.id}: metadata refresh from ${md.url} failed (${entry.lastError}); ${entry.learned ? "keeping the last good copy" : "using the configured certificates"}`);
    }
  }

  private async load(sp: ResolvedServiceProvider, md: NonNullable<ResolvedServiceProvider["metadata"]>): Promise<Learned> {
    // Redirects are not followed: "manual" returns the 3xx, which fails the status check below.
    // (workerd rejects redirect: "error" outright; found by the live test, D-026.)
    const res = await fetch(md.url, {
      redirect: "manual",
      headers: { accept: "application/samlmetadata+xml, application/xml;q=0.9, text/xml;q=0.8" },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (res.status !== 200) throw new Error(res.status >= 300 && res.status < 400 ? `HTTP ${res.status} redirect (not followed)` : `HTTP ${res.status}`);
    const declared = Number(res.headers.get("content-length") ?? 0);
    if (declared > MAX_BYTES) throw new Error(`larger than ${MAX_BYTES} bytes`);
    const xml = await readLimited(res, MAX_BYTES);
    const pre = precheckXml(xml, MAX_BYTES);
    if (pre.length) throw new Error(pre.join("; "));

    // Schema first, then the signature: never hand an unvalidated document to the verifier.
    const schema = await this.validator.validate(xml, "metadata");
    if (!schema.valid) throw new Error(`metadata is not schema-valid: ${schema.errors.slice(0, 2).join("; ")}`);
    const doc = parseXmlStrict(xml);
    const root = doc.documentElement as any;
    if (md.signingCertificates.length) {
      const sig = verifyEnvelopedSignature(xml, doc, root, md.signingCertificates, { allowSha1: false });
      if (sig.valid !== true) throw new Error(sig.present ? `metadata signature: ${sig.problem ?? "not verified"}` : "metadata is not signed");
    }
    // validUntil on the document (or an aggregate's root) and on the SP's own entity.
    const entity =
      root.localName === "EntityDescriptor"
        ? root
        : Array.from(root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "EntityDescriptor") as ArrayLike<any>).find(
            (e) => e.getAttribute("entityID") === sp.entityId,
          );
    for (const el of [root, entity]) {
      const until = el?.getAttribute("validUntil");
      if (until && !(new Date(until).getTime() > this.now())) throw new Error(`metadata expired (validUntil ${until})`);
    }

    const result = await serviceProviderFromMetadata(xml, { id: sp.id }, { entityId: sp.entityId, schemaValidator: this.validator });
    if (result.serviceProvider.entityId !== sp.entityId)
      throw new Error(`metadata is for ${result.serviceProvider.entityId}, not the configured ${sp.entityId}`);

    const signing = [result.serviceProvider.spCertificate ?? []].flat().filter((pem) => {
      try {
        const k = new X509Certificate(pem).publicKey;
        return k.asymmetricKeyType === "rsa" && (k.asymmetricKeyDetails?.modulusLength ?? 0) >= 2048;
      } catch {
        return false;
      }
    });
    let encryption: AssertionEncryption | undefined;
    if (sp.encryption && result.encryptionCertificates[0]) {
      const issues: string[] = [];
      const cert = checkEncryptionCertificate("metadata encryption certificate", result.encryptionCertificates[0], issues, []);
      if (cert) encryption = { ...sp.encryption, ...cert };
    }
    return {
      signingCertificates: signing,
      encryption,
      fetchedAt: this.now(),
      fingerprints: [...signing.map(fingerprint), encryption ? `enc:${encryption.certificateBase64.slice(-32)}` : ""].join(","),
    };
  }
}
