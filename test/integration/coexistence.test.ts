// @better-auth/sso sets samlify's process-global validator at import. The IdP plugin never
// touches that global (it parses and validates AuthnRequests itself; samlify only builds
// metadata), so the SSO plugin's behaviour stays exactly as its authors chose.
import { sso } from "@better-auth/sso";
import { getContext } from "samlify/build/src/api";
import { describe, expect, it } from "vitest";
import { samlIdp } from "../../src/index";
import { baseOptions } from "../support/config";

// vitest-pool-workers loads "samlify" and "samlify/build/src/api" as two separate module
// instances, so this identity check can't be made there. Node and real wrangler/esbuild
// bundles share one instance; the bundle case is checked by spike/coexist.ts (DECISIONS.md D-006).
const isWorkerd = typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers";

describe("coexistence with @better-auth/sso", () => {
  it.skipIf(isWorkerd)("never changes samlify's process-global validator", () => {
    // Referencing sso() keeps the module (it is "sideEffects": false); its import installs the validator.
    expect(sso()).toBeTruthy();
    const before = getContext().validate;
    expect(before).toBeTypeOf("function");
    samlIdp(baseOptions());
    expect(getContext().validate).toBe(before);
  });
});
