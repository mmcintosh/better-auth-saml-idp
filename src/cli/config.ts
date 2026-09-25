// `check-config`: run the plugin's startup validation on a config file, and `sp-from-metadata`.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { resolveOptions, SamlIdpConfigError } from "../options";
import { serviceProviderFromMetadata, SpMetadataError } from "../saml/sp-metadata";
import type { SamlIdpOptions } from "../types";
import { certSummary, checkCert, describeCert, fetchText, httpsOnly, readInput, Report, UsageError } from "./util";

/** JSON configs may reference PEM files as "file:./idp.key" (relative to the config file). */
function resolveFileRefs(value: unknown, base: string): unknown {
  if (typeof value === "string" && value.startsWith("file:")) {
    const path = resolve(base, value.slice(5));
    try {
      return readFileSync(path, "utf8");
    } catch (e) {
      throw new UsageError(`cannot read ${path}: ${(e as Error).message}`);
    }
  }
  if (Array.isArray(value)) return value.map((v) => resolveFileRefs(v, base));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, resolveFileRefs(v, base)]));
  return value;
}

export async function loadConfig(path: string): Promise<SamlIdpOptions> {
  const abs = resolve(path);
  if (/\.json$/i.test(abs)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(abs, "utf8"));
    } catch (e) {
      throw new UsageError(`${path}: ${(e as Error).message}`);
    }
    return resolveFileRefs(parsed, dirname(abs)) as SamlIdpOptions;
  }
  if (/\.(m?js)$/i.test(abs)) {
    // The host's own module: running it is the point (it may build the config from env vars).
    const mod = await import(pathToFileURL(abs).href);
    const cfg = mod.samlIdpOptions ?? mod.default;
    if (!cfg || typeof cfg !== "object") throw new UsageError(`${path}: export the options as \`default\` or \`samlIdpOptions\``);
    return cfg as SamlIdpOptions;
  }
  throw new UsageError(`${path}: use a .json, .js or .mjs file (compile TypeScript first)`);
}

export async function checkConfig(path: string | undefined): Promise<Report> {
  if (!path) throw new UsageError("check-config needs a config file");
  const report = new Report();
  const input = await loadConfig(path);
  let o: ReturnType<typeof resolveOptions>;
  try {
    o = resolveOptions(input);
  } catch (e) {
    if (!(e instanceof SamlIdpConfigError)) throw e;
    for (const issue of e.issues) report.fail(issue);
    return report;
  }
  report.pass("options are valid");
  for (const w of o.warnings) report.warn(w);
  report.section("IdP", {
    "Entity ID": o.entityId,
    "Base URL": o.baseURL ?? "(not pinned: follows the request's Host header)",
    "Login page": o.loginPage,
    Signing: `${o.signing.signatureAlgorithm}/${o.signing.digestAlgorithm}; Response ${o.signing.signResponse ? "signed" : "unsigned"}, Assertion ${o.signing.signAssertion ? "signed" : "unsigned"}`,
    "Signed metadata": o.signMetadata,
    "Assertion lifetime": `${o.assertionLifetimeSeconds}s`,
    "AuthnContext": o.authnContextClassRef.split(":").pop(),
    "Account policy": `verified email ${o.accountPolicy.requireEmailVerified ? "required" : "NOT required"}, impersonation ${o.accountPolicy.allowImpersonatedSessions ? "ALLOWED" : "refused"}, anonymous ${o.accountPolicy.allowAnonymousUsers ? "ALLOWED" : "refused"}`,
  });
  if (!o.baseURL) report.warn("baseURL is not set: the IdP's own URLs follow the Host header");
  if (!o.accountPolicy.requireEmailVerified) report.warn("accountPolicy.requireEmailVerified is off: unverified addresses get assertions");
  checkCert(report, "signing certificate", certSummary(o.signing.certificate));
  report.section("Signing certificate", { Active: describeCert(certSummary(o.signing.certificate)) });
  o.signing.additionalCertificates.forEach((c, i) => {
    const s = certSummary(c);
    report.section(`Additional certificate #${i + 1} (published, not signing)`, { Certificate: describeCert(s) });
    checkCert(report, `additional certificate #${i + 1}`, s);
  });

  for (const sp of o.serviceProviders) {
    report.section(`SP ${sp.id}`, {
      "Entity ID": sp.entityId,
      "ACS URLs": sp.acsUrls.join("\n"),
      NameID: sp.nameIdFormat.split(":").pop(),
      Signing: `Response ${sp.signResponse ? "signed" : "unsigned"}, Assertion ${sp.signAssertion || sp.encryption ? "signed" : "unsigned"}`,
      Encryption: sp.encryption ? `${sp.encryption.dataAlgorithm} + ${sp.encryption.keyAlgorithm}` : "off",
      "Signed requests": sp.requireSignedAuthnRequests ? `required (${sp.spCertificates.length} certificate${sp.spCertificates.length === 1 ? "" : "s"})` : "optional",
      "IdP-initiated": sp.allowIdpInitiated ? "allowed" : "off",
    });
    for (const u of sp.acsUrls) if (u.startsWith("http:")) report.warn(`SP ${sp.id}: ACS URL ${u} is not https`);
    for (const [i, c] of sp.spCertificates.entries()) checkCert(report, `SP ${sp.id} certificate #${i + 1}`, certSummary(c));
  }
  return report;
}

export interface SpFromMetadataCliOptions {
  id?: string;
  entityId?: string;
  allowHttp: boolean;
}

export async function spFromMetadata(arg: string | undefined, opts: SpFromMetadataCliOptions): Promise<Report> {
  const report = new Report();
  let xml: string;
  let id = opts.id;
  if (arg && /^https?:\/\//i.test(arg)) {
    const u = httpsOnly(arg, opts.allowHttp);
    const { res, text } = await fetchText(u.href);
    if (!res.ok) throw new UsageError(`${u.href}: HTTP ${res.status}`);
    xml = text;
    id ??= u.hostname.split(".")[0];
    report.warn(`fetched over the network: the metadata's own signature is NOT checked. Review the entry before trusting it`);
  } else xml = await readInput(arg);
  let result: Awaited<ReturnType<typeof serviceProviderFromMetadata>>;
  try {
    result = await serviceProviderFromMetadata(xml, { id: id ?? "my-sp" }, { entityId: opts.entityId });
  } catch (e) {
    if (e instanceof SpMetadataError) {
      report.fail(e.message);
      return report;
    }
    throw e;
  }
  for (const w of result.warnings) report.warn(w);
  const entry: Record<string, unknown> = { ...result.serviceProvider };
  if (result.encryptionCertificates[0]) {
    entry.encryption = { certificate: result.encryptionCertificates[0] };
    report.info("the SP publishes an encryption certificate: `encryption` is included; remove it to send plaintext assertions");
  }
  if (!id) report.info('pass --id to name the SP (used in logs and /saml2/idp/init?sp=)');
  report.pass(`service provider ${result.serviceProvider.entityId}`);
  report.data = { serviceProvider: entry, encryptionCertificates: result.encryptionCertificates, warnings: result.warnings };
  report.output = JSON.stringify(entry, null, 2);
  return report;
}
