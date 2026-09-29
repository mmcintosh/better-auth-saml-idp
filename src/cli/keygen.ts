// `keygen`: an RSA signing key and a self-signed certificate for the IdP.
import { generateKeyPairSync, X509Certificate } from "node:crypto";
import { unlinkSync, writeFileSync } from "node:fs";
import { selfSignedCertificate } from "../saml/certificate";
import { certSummary, describeCert, Report, UsageError } from "./util";

// --- command ----------------------------------------------------------------------------

export interface KeygenOptions {
  commonName: string;
  days: number;
  bits: number;
  certOut?: string | undefined;
  keyOut?: string | undefined;
  force: boolean;
}

/**
 * Create `path` with `mode`. With --force an existing file (or symlink) is removed first, and the
 * new file is always created exclusively ("wx"): a reused file would keep its old permissions,
 * and a symlink would redirect the key elsewhere (review 2, R2-CLI-1).
 */
function writeNew(path: string, data: string, mode: number, force: boolean) {
  // No check-then-write: the exclusive create is the check, so nothing can slip in between.
  try {
    writeFileSync(path, data, { mode, flag: "wx" });
    return;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    if (!force) throw new UsageError(`${path} exists (pass --force to overwrite)`);
  }
  unlinkSync(path);
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
