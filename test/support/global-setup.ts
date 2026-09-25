// Generates throwaway RSA keys + self-signed certs for every test run.
// Nothing here is ever written to the repo.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TestProject } from "vitest/node";

function keypair(cn: string) {
  const dir = mkdtempSync(join(tmpdir(), "saml-idp-test-"));
  try {
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
      "-subj", `/CN=${cn}`, "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"),
    ], { stdio: "ignore" });
    return {
      privateKey: readFileSync(join(dir, "key.pem"), "utf8"),
      certificate: readFileSync(join(dir, "cert.pem"), "utf8"),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function openssl(args: string[], dir: string) {
  execFileSync("openssl", args, { cwd: dir, stdio: "ignore" });
}

/** Odd key material for negative option-validation tests. */
function badKeys() {
  const dir = mkdtempSync(join(tmpdir(), "saml-idp-test-"));
  try {
    openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ec.pem"], dir);
    openssl(["pkcs8", "-topk8", "-nocrypt", "-in", "ec.pem", "-out", "ec8.pem"], dir);
    openssl(["req", "-x509", "-key", "ec8.pem", "-sha256", "-days", "2", "-subj", "/CN=ec", "-out", "ec-cert.pem"], dir);
    openssl(["genrsa", "-out", "rsa1024.pem", "1024"], dir);
    openssl(["req", "-x509", "-key", "rsa1024.pem", "-sha256", "-days", "2", "-subj", "/CN=weak", "-out", "rsa1024-cert.pem"], dir);
    // Expired certificate: OpenSSL 3.0's `req` cannot backdate, so self-sign via `ca`.
    openssl(["genrsa", "-out", "old.pem", "2048"], dir);
    openssl(["req", "-new", "-key", "old.pem", "-subj", "/CN=expired", "-out", "old.csr"], dir);
    writeFileSync(join(dir, "index.txt"), "");
    writeFileSync(join(dir, "serial"), "01\n");
    writeFileSync(
      join(dir, "ca.cnf"),
      "[ca]\ndefault_ca=d\n[d]\ndatabase=index.txt\nserial=serial\nnew_certs_dir=.\ndefault_md=sha256\npolicy=p\n[p]\ncommonName=supplied\n",
    );
    openssl(["ca", "-batch", "-config", "ca.cnf", "-selfsign", "-keyfile", "old.pem", "-in", "old.csr", "-startdate", "20200101000000Z", "-enddate", "20200201000000Z", "-out", "old-cert.pem", "-notext"], dir);
    const r = (f: string) => readFileSync(join(dir, f), "utf8");
    return {
      ec: { privateKey: r("ec8.pem"), certificate: r("ec-cert.pem") },
      rsa1024: { privateKey: r("rsa1024.pem"), certificate: r("rsa1024-cert.pem") },
      expired: { privateKey: r("old.pem"), certificate: r("old-cert.pem") },
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export default function setup(project: TestProject) {
  project.provide("keys", {
    idp: keypair("test-idp"),
    idpNext: keypair("test-idp-next"),
    sp: keypair("test-sp"),
    ...badKeys(),
  });
}

declare module "vitest" {
  export interface ProvidedContext {
    keys: Record<"idp" | "idpNext" | "sp" | "ec" | "rsa1024" | "expired", { privateKey: string; certificate: string }>;
  }
}
