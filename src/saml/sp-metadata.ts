import { NAMEID_FORMAT, type ServiceProviderConfig } from "../types";
import { defaultSchemaValidator, precheckXml, type SchemaValidator } from "./validator";
import { parseXmlStrict } from "./xml";

const NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
const NS_DS = "http://www.w3.org/2000/09/xmldsig#";
const SAML2_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
const BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const MAX_METADATA_BYTES = 512 * 1024;
const SUPPORTED_NAMEID = new Set<string>(Object.values(NAMEID_FORMAT));

export class SpMetadataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SpMetadataError";
  }
}

export interface SpFromMetadataResult {
  /** Ready for `serviceProviders`: entityId, acsUrls, nameIdFormat, signing requirements. */
  serviceProvider: ServiceProviderConfig;
  /** Certificates the SP publishes for encryption (`KeyDescriptor use="encryption"`, or no `use`). */
  encryptionCertificates: string[];
  /** Things that were present but not used, e.g. ACS endpoints on bindings the IdP doesn't send. */
  warnings: string[];
}

export interface SpFromMetadataOptions {
  /** When the document is an EntitiesDescriptor (a federation aggregate), which entity to take. */
  entityId?: string;
  /** Defaults to the plugin's default libxml2 validator. */
  schemaValidator?: SchemaValidator;
}

const children = (el: any, ns: string, name: string): any[] =>
  Array.from(el.childNodes as ArrayLike<any>).filter((n: any) => n.nodeType === 1 && n.namespaceURI === ns && n.localName === name);
const descendants = (el: any, ns: string, name: string): any[] => Array.from(el.getElementsByTagNameNS(ns, name) as ArrayLike<any>);

function toPem(b64: string): string {
  const body = b64.replace(/\s+/g, "");
  if (!body) throw new SpMetadataError("empty X509Certificate");
  return `-----BEGIN CERTIFICATE-----\n${(body.match(/.{1,64}/g) ?? []).join("\n")}\n-----END CERTIFICATE-----\n`;
}

/**
 * Build a `serviceProviders` entry from an SP's SAML metadata document.
 *
 * The document is size-checked, DOCTYPE-free and XSD-validated against the OASIS metadata schema
 * before anything is read. The metadata's own XML signature is NOT verified here: obtain metadata
 * over an authenticated channel (or pin it in your repo) and review the result — anything in this
 * document decides where assertions are sent.
 *
 * `overrides` is merged last, so you can set `id`, `attributes`, `authorize`, or override any
 * extracted value.
 */
export async function serviceProviderFromMetadata(
  xml: string,
  overrides: Partial<ServiceProviderConfig> & { id: string },
  options: SpFromMetadataOptions = {},
): Promise<SpFromMetadataResult> {
  const pre = precheckXml(xml, MAX_METADATA_BYTES);
  if (pre.length) throw new SpMetadataError(pre.join("; "));
  const schema = await (options.schemaValidator ?? defaultSchemaValidator()).validate(xml, "metadata");
  if (!schema.valid) throw new SpMetadataError(`metadata is not schema-valid: ${schema.errors.slice(0, 3).join("; ")}`);

  const doc = parseXmlStrict(xml);
  const root = doc.documentElement as any;
  let entity: any;
  if (root.namespaceURI === NS_MD && root.localName === "EntityDescriptor") entity = root;
  else if (root.namespaceURI === NS_MD && root.localName === "EntitiesDescriptor") {
    const all = descendants(root, NS_MD, "EntityDescriptor");
    if (!options.entityId) throw new SpMetadataError(`EntitiesDescriptor with ${all.length} entities: pass options.entityId`);
    entity = all.find((e) => e.getAttribute("entityID") === options.entityId);
    if (!entity) throw new SpMetadataError(`entity ${options.entityId} not found in EntitiesDescriptor`);
  } else throw new SpMetadataError("root element is not md:EntityDescriptor or md:EntitiesDescriptor");

  const entityId = entity.getAttribute("entityID");
  const sp = children(entity, NS_MD, "SPSSODescriptor").find((d) =>
    (d.getAttribute("protocolSupportEnumeration") ?? "").split(/\s+/).includes(SAML2_PROTOCOL),
  );
  if (!sp) throw new SpMetadataError("no SPSSODescriptor supporting SAML 2.0");

  const warnings: string[] = [];
  const acs = children(sp, NS_MD, "AssertionConsumerService");
  const post = acs.filter((a) => a.getAttribute("Binding") === BINDING_POST);
  for (const a of acs)
    if (a.getAttribute("Binding") !== BINDING_POST)
      warnings.push(`ignored AssertionConsumerService on ${a.getAttribute("Binding")} (the IdP responds with HTTP-POST)`);
  if (post.length === 0) throw new SpMetadataError("no HTTP-POST AssertionConsumerService");
  // Default endpoint first (isDefault="true"), then by index (SAML Metadata §2.2.3).
  post.sort((a, b) => {
    const d = Number(b.getAttribute("isDefault") === "true") - Number(a.getAttribute("isDefault") === "true");
    return d || Number(a.getAttribute("index") ?? 0) - Number(b.getAttribute("index") ?? 0);
  });
  const acsUrls = [...new Set(post.map((a) => a.getAttribute("Location") as string))] as [string, ...string[]];

  const formats = children(sp, NS_MD, "NameIDFormat").map((n) => (n.textContent ?? "").trim());
  const usable = formats.filter((f) => SUPPORTED_NAMEID.has(f) && f !== NAMEID_FORMAT.unspecified);
  for (const f of formats) if (!SUPPORTED_NAMEID.has(f)) warnings.push(`ignored unsupported NameIDFormat ${f}`);

  const certsFor = (use: "signing" | "encryption") =>
    children(sp, NS_MD, "KeyDescriptor")
      .filter((k) => !k.getAttribute("use") || k.getAttribute("use") === use)
      .flatMap((k) => descendants(k, NS_DS, "X509Certificate").map((c) => toPem(c.textContent ?? "")));
  const signingCerts = certsFor("signing");

  // Single Logout endpoint (D-028): HTTP-Redirect preferred, else HTTP-POST.
  const slo = children(sp, NS_MD, "SingleLogoutService");
  const sloRedirect = slo.find((s) => s.getAttribute("Binding") === "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
  const sloPost = slo.find((s) => s.getAttribute("Binding") === BINDING_POST);
  const sloChoice = sloRedirect ?? sloPost;
  const singleLogoutService = sloChoice
    ? { url: (sloChoice.getAttribute("ResponseLocation") || sloChoice.getAttribute("Location")) as string, binding: sloChoice === sloRedirect ? ("redirect" as const) : ("post" as const) }
    : undefined;

  const serviceProvider: ServiceProviderConfig = {
    entityId,
    acsUrls,
    ...(singleLogoutService ? { singleLogoutService } : {}),
    ...(usable[0] ? { nameIdFormat: usable[0] } : {}),
    ...(sp.getAttribute("AuthnRequestsSigned") === "true" && signingCerts.length
      ? { requireSignedAuthnRequests: true, spCertificate: signingCerts }
      : signingCerts.length
        ? { spCertificate: signingCerts }
        : {}),
    ...overrides,
  };
  if (sp.getAttribute("AuthnRequestsSigned") === "true" && !signingCerts.length)
    warnings.push("AuthnRequestsSigned is true but no signing certificate is published");
  return { serviceProvider, encryptionCertificates: certsFor("encryption"), warnings };
}
