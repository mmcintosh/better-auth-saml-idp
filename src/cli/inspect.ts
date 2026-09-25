// `inspect`: what an SP sees when it reads this IdP's metadata.
import { defaultSchemaValidator } from "../saml/validator";
import { metadataUrl, parseDoc, readIdpMetadata, verifyEnveloped } from "./saml";
import { certSummary, checkCert, describeCert, fetchText, httpsOnly, pemCertificates, readFileArg, Report, UsageError } from "./util";

export interface InspectOptions {
  basePath: string;
  /** Pin: certificates the metadata signature must verify with. */
  cert: string[];
  allowHttp: boolean;
}

export async function inspect(target: string | undefined, opts: InspectOptions): Promise<Report> {
  if (!target) throw new UsageError("inspect needs the IdP URL, e.g. https://auth.example.com");
  const report = new Report();
  const url = metadataUrl(httpsOnly(target, opts.allowHttp).href, opts.basePath);
  const { res, text: xml } = await fetchText(url);
  report.section("Metadata", {
    URL: url,
    HTTP: `${res.status} ${res.statusText}`,
    "Content-Type": res.headers.get("content-type"),
    "Cache-Control": res.headers.get("cache-control"),
    Vary: res.headers.get("vary"),
  });
  if (!res.ok) {
    report.fail(`HTTP ${res.status}: is the plugin mounted at ${opts.basePath}? (use --base-path)`);
    return report;
  }
  if (!res.headers.get("content-type")?.startsWith("application/samlmetadata+xml"))
    report.warn(`Content-Type is ${res.headers.get("content-type")}; expected application/samlmetadata+xml`);

  const schema = await defaultSchemaValidator().validate(xml, "metadata");
  if (schema.valid) report.pass("valid against the SAML 2.0 metadata schema");
  else report.fail(`schema: ${schema.errors.slice(0, 3).join("; ")}`);

  const md = readIdpMetadata(xml);
  report.data.metadata = md;
  report.section("Identity provider", {
    "Entity ID": md.entityId,
    ...Object.fromEntries(md.sso.map((s) => [`SSO (${s.binding.split(":").pop()})`, s.location])),
    "NameID formats": md.nameIdFormats.map((f) => f.split(":").pop()).join(", "),
    WantAuthnRequestsSigned: md.wantAuthnRequestsSigned,
    "Signed metadata": md.signed,
  });

  if (!md.sso.some((s) => s.binding.endsWith("HTTP-Redirect"))) report.warn("no HTTP-Redirect SingleSignOnService");
  const host = new URL(url).host;
  for (const s of md.sso)
    if (new URL(s.location).host !== host) report.warn(`SSO URL ${s.location} is on another host than the metadata: is baseURL pinned correctly?`);
  if (new URL(md.entityId, url).protocol === "http:" && !opts.allowHttp) report.warn("entity ID uses http:");

  if (md.signingCertificates.length === 0) report.fail("no signing certificate published");
  const summaries = md.signingCertificates.map((c) => certSummary(c));
  summaries.forEach((s, i) => {
    report.section(`Signing certificate #${i + 1}`, { Certificate: describeCert(s) });
    checkCert(report, `certificate #${i + 1}`, s);
  });
  if (md.signingCertificates.length > 1)
    report.info(`${md.signingCertificates.length} certificates published: a key rotation is in progress (SPs should trust all of them)`);

  if (md.signed) {
    const doc = parseDoc(xml);
    const pinned = opts.cert.flatMap((f) => pemCertificates(readFileArg(f, "certificate")));
    const self = verifyEnveloped(xml, doc, doc.documentElement, md.signingCertificates);
    if (self.valid) report.pass(`metadata signature verifies with its own certificate (${self.algorithm}/${self.digest})`);
    else report.fail(`metadata signature: ${self.problem ?? "does not verify"}`);
    if (pinned.length) {
      const r = verifyEnveloped(xml, doc, doc.documentElement, pinned);
      if (r.valid) report.pass("metadata signature verifies with the pinned certificate (--cert)");
      else report.fail(`metadata signature does not verify with the pinned certificate: ${r.problem ?? ""}`);
    } else report.info("a signature checked against the metadata's own certificate only proves integrity; pass --cert to pin");
  } else if (opts.cert.length) report.warn("--cert given, but the metadata is not signed (signMetadata: true signs it)");
  return report;
}
