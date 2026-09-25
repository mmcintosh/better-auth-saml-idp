import { sso } from "@better-auth/sso";
import { getContext } from "samlify/build/src/api";
import { samlIdp } from "../src/index";
import cfg from "./.coexist-cfg.json";
export default {
  async fetch(_r: Request, env: any) {
    sso();
    const before = getContext().validate;
    let after: unknown = "not-run";
    try { samlIdp(cfg as any); after = getContext().validate; } catch (e) { after = String(e).slice(0, 200); }
    return Response.json({ ssoValidatorVisible: typeof before, unchangedAfterPlugin: before === after, after: typeof after === "string" ? after : typeof after });
  },
};
