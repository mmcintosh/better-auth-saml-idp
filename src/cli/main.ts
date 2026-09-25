// better-auth-saml-idp CLI: inspect, debug and smoke-test a deployed IdP from the terminal.
// Exit codes: 0 all checks passed, 1 a check failed, 2 usage or input error.
import { parseArgs } from "node:util";
import { checkConfig, spFromMetadata } from "./config";
import { decode } from "./decode";
import { inspect } from "./inspect";
import { keygen } from "./keygen";
import { request } from "./request";
import { smoke } from "./smoke";
import { render, type Report, UsageError } from "./util";

const HELP = `better-auth-saml-idp: inspect, debug and test a Better Auth SAML IdP

Usage: better-auth-saml-idp <command> [options]

Commands
  inspect <idp-url>            What SPs see in the IdP's metadata: entity ID, SSO URLs,
                               certificates and their expiry, schema and signature checks
  decode [input|-]             Explain a captured SAMLRequest or SAMLResponse: a URL, a form
                               body (SAMLResponse=...), base64 or XML, from an argument, a
                               file or stdin. Verifies signatures and time windows.
      --cert <file>            IdP certificate for Responses, SP certificate for requests (repeatable)
      --idp <idp-url>          Take the IdP certificates from its metadata
      --key <file>             SP private key, to decrypt an EncryptedAssertion
      --sp <entity-id>         Check the Audience
      --acs <url>              Check Destination and Recipient
      --request-id <id>        Check InResponseTo
      --sso <url>              Check an AuthnRequest's Destination
      --xml                    Also print the XML (and the decrypted assertion)
  request <idp-url>            Build an AuthnRequest URL to open in a browser
      --sp <entity-id>         Issuer: a registered SP (required)
      --acs <url>              AssertionConsumerServiceURL
      --binding redirect|post  Default redirect; post prints an HTML form
      --relay-state <value>    --force-authn  --passive
      --name-id-format <f>     email | persistent | transient | <URI>
      --authn-context <uri>    RequestedAuthnContext (exact)
      --sign-key <file>        Sign it (Redirect binding) with the SP's key; --sig-alg rsa-sha256|rsa-sha512
  smoke <idp-url>              Security smoke test against a deployed IdP (no user needed)
      --sp <entity-id>         A registered SP (required); --acs if its first ACS URL differs
  sp-from-metadata [file|url|-]  Print a serviceProviders entry from an SP's metadata
      --id <id>                The SP's id; --entity-id <id> to pick one from an aggregate
  check-config <file>          Validate plugin options (.json with "file:./x.pem" references,
                               or a .js/.mjs module exporting them) and report certificates
  keygen                       Create an RSA key and self-signed certificate for the IdP
      --cert-out <file>        Certificate (public)
      --key-out <file>         Private key (mode 0600); without it the key goes to stdout,
                               which must be a pipe: ... | npx wrangler secret put SAML_IDP_PRIVATE_KEY
      --cn <name>              Default "better-auth-saml-idp"; --days 730; --bits 3072; --force

Common options
  --base-path <path>           Where Better Auth is mounted (default /api/auth)
  --allow-http                 Allow http:// URLs (local development)
  --json                       Machine-readable output
  -h, --help                   This help
`;

const options = {
  help: { type: "boolean", short: "h" },
  json: { type: "boolean" },
  "allow-http": { type: "boolean" },
  "base-path": { type: "string", default: "/api/auth" },
  cert: { type: "string", multiple: true },
  idp: { type: "string" },
  key: { type: "string" },
  sp: { type: "string" },
  acs: { type: "string" },
  "request-id": { type: "string" },
  sso: { type: "string" },
  xml: { type: "boolean" },
  binding: { type: "string", default: "redirect" },
  "relay-state": { type: "string" },
  "force-authn": { type: "boolean" },
  passive: { type: "boolean" },
  "name-id-format": { type: "string" },
  "authn-context": { type: "string" },
  "sign-key": { type: "string" },
  "sig-alg": { type: "string", default: "rsa-sha256" },
  id: { type: "string" },
  "entity-id": { type: "string" },
  "cert-out": { type: "string" },
  "key-out": { type: "string" },
  cn: { type: "string", default: "better-auth-saml-idp" },
  days: { type: "string", default: "730" },
  bits: { type: "string", default: "3072" },
  force: { type: "boolean" },
} as const;

const parse = (args: string[]) => parseArgs({ args, options, allowPositionals: true });

export async function run(argv: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  let parsed: ReturnType<typeof parse>;
  try {
    parsed = parse(argv);
  } catch (e) {
    return { code: 2, stdout: "", stderr: `${(e as Error).message}\n\nRun with --help for usage.\n` };
  }
  const { values: v, positionals } = parsed;
  const [command, target, ...extra] = positionals;
  if (v.help || !command) return { code: command || v.help ? 0 : 2, stdout: HELP, stderr: "" };
  if (extra.length) return { code: 2, stdout: "", stderr: `unexpected arguments: ${extra.join(" ")}\n` };
  const common = { basePath: v["base-path"], allowHttp: v["allow-http"] === true };

  let report: Report;
  /** Commands whose `output` is meant for a pipe print the report to stderr. */
  let pipeOutput = false;
  try {
    switch (command) {
      case "inspect":
        report = await inspect(target, { ...common, cert: v.cert ?? [] });
        break;
      case "decode":
        report = await decode(target, {
          ...common,
          cert: v.cert ?? [],
          idp: v.idp,
          key: v.key,
          sp: v.sp,
          acs: v.acs,
          requestId: v["request-id"],
          sso: v.sso,
          showXml: v.xml === true,
        });
        break;
      case "request":
        report = await request(target, {
          ...common,
          sp: v.sp,
          acs: v.acs,
          binding: v.binding,
          relayState: v["relay-state"],
          forceAuthn: v["force-authn"] === true,
          passive: v.passive === true,
          nameIdFormat: v["name-id-format"],
          authnContext: v["authn-context"],
          signKey: v["sign-key"],
          sigAlg: v["sig-alg"],
        });
        pipeOutput = true;
        break;
      case "smoke":
        report = await smoke(target, { ...common, sp: v.sp, acs: v.acs });
        break;
      case "sp-from-metadata":
        report = await spFromMetadata(target, { id: v.id, entityId: v["entity-id"], allowHttp: common.allowHttp });
        pipeOutput = true;
        break;
      case "check-config":
        report = await checkConfig(target);
        break;
      case "keygen": {
        if (target) throw new UsageError("keygen takes no positional argument");
        report = keygen({
          commonName: v.cn,
          days: Number(v.days),
          bits: Number(v.bits),
          certOut: v["cert-out"],
          keyOut: v["key-out"],
          force: v.force === true,
        });
        // The key (when not written to a file) is the only thing on stdout.
        const key = report.data.privateKey as string | undefined;
        delete report.data.privateKey;
        return { code: 0, stdout: key ?? (v.json ? render(report, true) : ""), stderr: key || !v.json ? render(report, false) : "" };
      }
      default:
        throw new UsageError(`unknown command "${command}"`);
    }
  } catch (e) {
    if (e instanceof UsageError) return { code: 2, stdout: "", stderr: `error: ${e.message}\n` };
    throw e;
  }
  const code = report.failed ? 1 : 0;
  if (v.json) return { code, stdout: `${render(report, true)}\n`, stderr: "" };
  if (pipeOutput && report.output !== undefined) {
    const { output } = report;
    report.output = undefined;
    return { code, stdout: `${output}\n`, stderr: render(report, false) };
  }
  return { code, stdout: render(report, false), stderr: "" };
}
