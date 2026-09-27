// samlify console.warns on every IdP without a SingleLogoutService; without singleLogout that's
// by design, so the plugin silences exactly that message (found by the pre-release install test).
import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveOptions } from "../../src/options";
import { createIdp } from "../../src/saml/idp";
import { baseOptions } from "../support/config";

afterEach(() => vi.restoreAllMocks());

describe("createIdp without Single Logout", () => {
  it("makes no console noise, advertises no SingleLogoutService, and leaves console.warn as it was", () => {
    const warn = vi.spyOn(console, "warn");
    const idp = createIdp(resolveOptions(baseOptions()), "https://auth.test/api/auth");
    expect(warn.mock.calls.filter((c) => String(c[0]).includes("SingleLogoutService"))).toEqual([]);
    expect(idp.getMetadata()).not.toContain("SingleLogoutService");
    // The filter is gone afterwards: even that message gets through outside construction.
    console.warn("x missing endpoint of SingleLogoutService");
    expect(warn).toHaveBeenCalledWith("x missing endpoint of SingleLogoutService");
  });

  it("with Single Logout, the SLO endpoints are advertised", () => {
    const idp = createIdp(resolveOptions(baseOptions({ singleLogout: { enabled: true } })), "https://auth.test/api/auth");
    expect(idp.getMetadata()).toContain("SingleLogoutService");
  });
});
