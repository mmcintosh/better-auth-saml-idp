// samlify console.warns on every IdP without a SingleLogoutService; without singleLogout that's
// by design, so the plugin silences exactly that message (found by the pre-release install test).
import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveOptions } from "../../src/options";
import { rootIdentity } from "../../src/saml/identity";
import { createIdp } from "../../src/saml/idp";
import { baseOptions } from "../support/config";

afterEach(() => vi.restoreAllMocks());

describe("createIdp without Single Logout", () => {
  it("makes no console noise, advertises no SingleLogoutService, and leaves console.warn as it was", () => {
    const warn = vi.spyOn(console, "warn");
    const options = resolveOptions(baseOptions());
    const idp = createIdp(options, rootIdentity(options, "https://auth.test/api/auth"), options.serviceProviders);
    expect(warn.mock.calls.filter((c) => String(c[0]).includes("SingleLogoutService"))).toEqual([]);
    expect(idp.getMetadata()).not.toContain("SingleLogoutService");
    // The filter is gone afterwards: even that message gets through outside construction.
    console.warn("x missing endpoint of SingleLogoutService");
    expect(warn).toHaveBeenCalledWith("x missing endpoint of SingleLogoutService");
  });

  it("with Single Logout, the SLO endpoints are advertised", () => {
    const options = resolveOptions(baseOptions({ singleLogout: { enabled: true } }));
    const idp = createIdp(options, rootIdentity(options, "https://auth.test/api/auth"), options.serviceProviders);
    expect(idp.getMetadata()).toContain("SingleLogoutService");
  });
});
