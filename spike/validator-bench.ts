import { xmllintValidator } from "../src/saml/validator";
import * as authenio from "@authenio/samlify-node-xmllint";
const v = xmllintValidator();
const x = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_abc123" Version="2.0" IssueInstant="2026-09-24T10:00:00Z"><saml:Issuer>x</saml:Issuer></samlp:AuthnRequest>`;
export default {
  async fetch(req: Request) {
    const which = new URL(req.url).pathname;
    if (which === "/ours") return Response.json(await v.validate(x, "protocol"));
    if (which === "/authenio") return new Response(await authenio.validate(x).catch(String));
    return new Response("noop");
  },
};
