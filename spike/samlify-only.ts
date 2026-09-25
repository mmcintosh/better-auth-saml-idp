import * as samlify from "samlify";
samlify.setSchemaValidator({ validate: async () => "noop-for-size-measurement-only" });
export default {
  async fetch() {
    const idp = samlify.IdentityProvider({ entityID: "x", signingCert: "", privateKey: "" } as any);
    return new Response(String(!!idp));
  },
};
