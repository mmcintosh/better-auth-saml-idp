import type { BetterAuthClientPlugin } from "better-auth/client";
import type { samlIdp } from "./index";

/** Client plugin: type inference only. The SAML endpoints are browser-navigation targets. */
export const samlIdpClient = () =>
  ({
    id: "saml-idp",
    $InferServerPlugin: {} as ReturnType<typeof samlIdp>,
  }) satisfies BetterAuthClientPlugin;
