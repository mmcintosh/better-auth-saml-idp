import * as samlify from "samlify";
import * as validator from "@authenio/samlify-node-xmllint";
samlify.setSchemaValidator(validator);
export default {
  async fetch(req: Request) {
    const idp = samlify.IdentityProvider({ entityID: "x", signingCert: "", privateKey: "" } as any);
    return new Response(String(!!idp) + (await validator.validate("<x/>").catch(() => "bad")));
  },
};
