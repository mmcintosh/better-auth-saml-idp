// The client plugin: registry calls typed from the server plugin, and the navigation helpers' URLs.
import { createAuthClient } from "better-auth/client";
import { describe, expect, expectTypeOf, it } from "vitest";
import { samlIdpClient } from "../../src/client";

describe("samlIdpClient", () => {
  const client = createAuthClient({ baseURL: "https://auth.example.com", plugins: [samlIdpClient()] });

  it("types the registry API from the server plugin", () => {
    expectTypeOf(client.samlIdp.serviceProviders.create).toBeFunction();
    expectTypeOf(client.samlIdp.serviceProviders.update).toBeFunction();
    expectTypeOf(client.samlIdp.serviceProviders.delete).toBeFunction();
    expectTypeOf(client.samlIdp.serviceProviders.get).toBeFunction();
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

  it("one namespace (API decision 2): registry calls reach /saml-idp/service-providers; SAML protocol routes aren't offered", async () => {
    const calls: { url: string; method: string }[] = [];
    const c = createAuthClient({
      baseURL: "https://auth.example.com",
      plugins: [samlIdpClient()],
      fetchOptions: {
        customFetchImpl: async (input, init) => {
          calls.push({ url: String(input instanceof Request ? input.url : input), method: init?.method ?? (input instanceof Request ? input.method : "GET") });
          return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
        },
      },
    });
    await c.samlIdp.serviceProviders.create({ serviceProvider: { id: "x" } as any });
    await c.samlIdp.serviceProviders.get({ query: { id: "x" } });
    expect(calls.map((x) => `${x.method} ${new URL(x.url).pathname}`)).toEqual([
      "POST /api/auth/saml-idp/service-providers/create",
      "GET /api/auth/saml-idp/service-providers/get",
    ]);
    // The helpers live in the same namespace.
    expectTypeOf(c.samlIdp.signOutEverywhere).toBeFunction();
    expectTypeOf(c.samlIdp.launch).toBeFunction();
    // Browser navigations are not client calls.
    // @ts-expect-error no saml2 namespace any more
    void c.saml2;
    // @ts-expect-error sso is a navigation, not a client call
    void c.samlIdp.sso;
  });
});
