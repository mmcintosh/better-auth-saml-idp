// `keygen`: an RSA signing key and a self-signed certificate for the IdP. node:crypto can't
// create certificates, so this encodes a minimal X.509 v3 certificate in DER itself.
import { createPublicKey, generateKeyPairSync, randomBytes, sign, X509Certificate, type KeyObject } from "node:crypto";
import { lstatSync, unlinkSync, writeFileSync } from "node:fs";
import { certSummary, describeCert, Report, UsageError } from "./util";

// --- DER ------------------------------------------------------------------------------

function len(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v >>= 8) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag: number, body: Buffer) => Buffer.concat([Buffer.from([tag]), len(body.length), body]);
const seq = (...items: Buffer[]) => tlv(0x30, Buffer.concat(items));
const set = (...items: Buffer[]) => tlv(0x31, Buffer.concat(items));
const explicit = (n: number, body: Buffer) => tlv(0xa0 + n, body);
const nul = () => Buffer.from([0x05, 0x00]);
const bool = (v: boolean) => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
const octets = (b: Buffer) => tlv(0x04, b);
const bits = (b: Buffer) => tlv(0x03, Buffer.concat([Buffer.from([0]), b]));
const utf8 = (s: string) => tlv(0x0c, Buffer.from(s, "utf8"));

function int(b: Buffer): Buffer {
  let v = b;
  while (v.length > 1 && v[0] === 0 && (v[1] ?? 0) < 0x80) v = v.subarray(1);
  if ((v[0] ?? 0) >= 0x80) v = Buffer.concat([Buffer.from([0]), v]);
  return tlv(0x02, v);
}

function oid(dotted: string): Buffer {
  const [a = 0, b = 0, ...rest] = dotted.split(".").map(Number);
  const out = [40 * a + b];
  for (const n of rest) {
    const chunk: number[] = [n & 0x7f];
    for (let v = n >> 7; v > 0; v >>= 7) chunk.unshift((v & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return tlv(0x06, Buffer.from(out));
}

function time(d: Date): Buffer {
  const s = d.toISOString().replace(/[-:T]/g, "").slice(0, 14); // YYYYMMDDHHMMSS
  // RFC 5280 §4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050.
  return d.getUTCFullYear() < 2050 ? tlv(0x17, Buffer.from(`${s.slice(2)}Z`)) : tlv(0x18, Buffer.from(`${s}Z`));
}

const SHA256_RSA = seq(oid("1.2.840.113549.1.1.11"), nul());

export function selfSignedCertificate(key: KeyObject, o: { commonName: string; days: number; now?: Date }): string {
  const now = o.now ?? new Date();
  const serial = randomBytes(16);
  serial[0] = ((serial[0] ?? 0) & 0x7f) | 0x40; // positive, 16 significant bytes
  const name = seq(set(seq(oid("2.5.4.3"), utf8(o.commonName))));
  const spki = createPublicKey(key).export({ type: "spki", format: "der" });
  const extensions = explicit(
    3,
    seq(
      // basicConstraints (critical): not a CA
      seq(oid("2.5.29.19"), bool(true), octets(seq())),
      // keyUsage (critical): digitalSignature
      seq(oid("2.5.29.15"), bool(true), octets(tlv(0x03, Buffer.from([0x07, 0x80])))),
    ),
  );
  const tbs = seq(
    explicit(0, int(Buffer.from([2]))), // v3
    int(serial),
    SHA256_RSA,
    name,
    seq(time(new Date(now.getTime() - 5 * 60_000)), time(new Date(now.getTime() + o.days * 86_400_000))),
    name,
    spki,
    extensions,
  );
  const cert = seq(tbs, SHA256_RSA, bits(sign("sha256", tbs, key)));
  return `-----BEGIN CERTIFICATE-----\n${(cert.toString("base64").match(/.{1,64}/g) ?? []).join("\n")}\n-----END CERTIFICATE-----\n`;
}

// --- command ----------------------------------------------------------------------------

export interface KeygenOptions {
  commonName: string;
  days: number;
  bits: number;
  certOut?: string;
  keyOut?: string;
  force: boolean;
}

/**
 * Create `path` with `mode`. With --force an existing file (or symlink) is removed first, and the
 * new file is always created exclusively ("wx"): a reused file would keep its old permissions,
 * and a symlink would redirect the key elsewhere (review 2, R2-CLI-1).
 */
function writeNew(path: string, data: string, mode: number, force: boolean) {
  let exists = false;
  try {
    lstatSync(path);
    exists = true;
  } catch {}
  if (exists && !force) throw new UsageError(`${path} exists (pass --force to overwrite)`);
  if (exists) unlinkSync(path);
  writeFileSync(path, data, { mode, flag: "wx" });
}

/**
 * The private key goes to --key-out (mode 0600) or to stdout, and stdout only when it is piped
 * (e.g. into `wrangler secret put`): a key printed to a terminal lingers in scrollback.
 */
export function keygen(opts: KeygenOptions): Report {
  if (![2048, 3072, 4096].includes(opts.bits)) throw new UsageError("--bits must be 2048, 3072 or 4096");
  if (!Number.isInteger(opts.days) || opts.days < 1 || opts.days > 3650) throw new UsageError("--days must be 1..3650");
  if (!opts.keyOut && process.stdout.isTTY)
    throw new UsageError("refusing to print a private key to the terminal: pipe it (| npx wrangler secret put SAML_IDP_PRIVATE_KEY) or pass --key-out <file>");
  if (!opts.certOut && !opts.keyOut) throw new UsageError("--cert-out <file> is required when the key goes to stdout");

  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: opts.bits });
  const certificate = selfSignedCertificate(privateKey, { commonName: opts.commonName, days: opts.days });
  const keyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  // Self-check before handing anything out.
  const x = new X509Certificate(certificate);
  if (!x.verify(x.publicKey) || !x.checkPrivateKey(privateKey)) throw new Error("generated certificate failed its self-check");

  const report = new Report();
  if (opts.certOut) writeNew(opts.certOut, certificate, 0o644, opts.force);
  if (opts.keyOut) writeNew(opts.keyOut, keyPem, 0o600, opts.force);
  report.section("Generated", {
    Certificate: `${describeCert(certSummary(certificate))}${opts.certOut ? `\nwritten to ${opts.certOut}` : ""}`,
    "Private key": opts.keyOut ? `written to ${opts.keyOut} (mode 0600)` : "written to stdout",
  });
  report.info("publish the certificate (signing.certificate) and give it to your SPs; keep the key secret (signing.privateKey)");
  if (opts.keyOut) report.info(`delete ${opts.keyOut} once it's in your secret store (shred -u ${opts.keyOut})`);
  report.data = { certificate, keyOut: opts.keyOut, certOut: opts.certOut };
  if (!opts.keyOut) report.data.privateKey = keyPem;
  return report;
}
