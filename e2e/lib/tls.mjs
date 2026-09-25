// Throwaway local CA + one leaf certificate for every e2e host (*.test and 127.0.0.1).
// Written to e2e/.generated/tls (gitignored). Run before Playwright so NODE_EXTRA_CA_CERTS
// can point at the CA; Chromium uses ignoreHTTPSErrors for the same certificate.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { GENERATED } from "./config.mjs";

export const TLS_DIR = join(GENERATED, "tls");
export const TLS = { ca: join(TLS_DIR, "ca.pem"), cert: join(TLS_DIR, "cert.pem"), key: join(TLS_DIR, "key.pem") };

export function ensureTls() {
  if (existsSync(TLS.ca) && existsSync(TLS.cert) && existsSync(TLS.key)) return TLS;
  mkdirSync(TLS_DIR, { recursive: true });
  const o = (...args) => execFileSync("openssl", args, { cwd: TLS_DIR, stdio: "ignore" });
  o("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "30", "-subj", "/CN=better-auth-saml-idp e2e CA",
    "-keyout", "ca.key", "-out", "ca.pem", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign");
  o("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=e2e.test", "-keyout", "key.pem", "-out", "leaf.csr");
  writeFileSync(
    join(TLS_DIR, "ext.cnf"),
    "subjectAltName=DNS:idp.test,DNS:kc.test,DNS:ssp.test,DNS:sp.test,DNS:app.test,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
  );
  o("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "30", "-sha256",
    "-extfile", "ext.cnf", "-out", "cert.pem");
  return TLS;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  ensureTls();
  console.log(`[e2e] TLS material in ${TLS_DIR}`);
}
