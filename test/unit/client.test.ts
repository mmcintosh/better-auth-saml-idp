// The client plugin: registry calls typed from the server plugin, and the navigation helpers' URLs.
import { createAuthClient } from "better-auth/client";
import { describe, expect, expectTypeOf, it } from "vitest";
import { samlIdpClient } from "../../src/client";

describe("samlIdpClient", () => {
  const client = createAuthClient({ baseURL: "https://auth.example.com", plugins: [samlIdpClient()] });

  it("types the registry API from the server plugin", () => {
    expectTypeOf(client.saml2.idp.serviceProviders.create).toBeFunction();
    expectTypeOf(client.saml2.idp.serviceProviders.update).toBeFunction();
    expectTypeOf(client.saml2.idp.serviceProviders.delete).toBeFunction();
    expectTypeOf(client.saml2.idp.serviceProviders.get).toBeFunction();
  });

  it("builds logout and launch URLs under the auth base path", () => {
    expect(client.samlIdp.logoutUrl({ returnTo: "/bye" })).toBe("https://auth.example.com/api/auth/saml2/idp/logout?returnTo=%2Fbye");
    expect(client.samlIdp.logoutUrl()).toBe("https://auth.example.com/api/auth/saml2/idp/logout");
    expect(client.samlIdp.launchUrl("hub spot", { relayState: "https://app/x?y=1" })).toBe(
      "https://auth.example.com/api/auth/saml2/idp/init?sp=hub%20spot&RelayState=https%3A%2F%2Fapp%2Fx%3Fy%3D1",
    );
  });

  it("honours a custom basePath, or a baseURL that already includes the path", () => {
    const custom = createAuthClient({ baseURL: "https://a.example", basePath: "/auth", plugins: [samlIdpClient()] });
    expect(custom.samlIdp.launchUrl("x")).toBe("https://a.example/auth/saml2/idp/init?sp=x");
    const withPath = createAuthClient({ baseURL: "https://a.example/custom/auth", plugins: [samlIdpClient()] });
    expect(withPath.samlIdp.logoutUrl()).toBe("https://a.example/custom/auth/saml2/idp/logout");
  });
});
