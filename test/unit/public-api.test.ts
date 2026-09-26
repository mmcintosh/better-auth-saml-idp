// API decision 1 (before 1.0): the package exports an explicit list of types. The plugin's
// resolved internals are not part of it, and callbacks get a read-only ServiceProviderInfo.
import { describe, expect, it } from "vitest";
import type * as Pkg from "../../src/index";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

// Type-level: these must stay unexported (`pnpm typecheck` fails if they reappear).
// @ts-expect-error internal
type _ResolvedOptions = Pkg.ResolvedSamlIdpOptions;
// @ts-expect-error internal
type _ResolvedSp = Pkg.ResolvedServiceProvider;
// And these must stay exported.
type _Public = [Pkg.SamlIdpOptions, Pkg.ServiceProviderConfig, Pkg.StoredServiceProviderConfig, Pkg.ServiceProviderInfo, Pkg.SamlIdpErrorCode, Pkg.SamlIdpEventHandlers];

describe("public API: authorize() receives a read-only ServiceProviderInfo", () => {
  it("exactly the public fields, frozen", async () => {
    let seen: Pkg.ServiceProviderInfo | undefined;
    const { auth } = await createHost({
      saml: {
        serviceProviders: [
          {
            id: "test-sp",
            entityId: SP_ENTITY_ID,
            acsUrls: [SP_ACS],
            authorize: ({ serviceProvider }) => {
              seen = serviceProvider;
              return true;
            },
          },
        ],
      },
    });
    const browser = new Browser(auth);
    await browser.signUp();
    await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    expect(Object.keys(seen!).sort()).toEqual(["acsUrls", "entityId", "id", "nameIdFormat", "organization"]);
    expect(seen).toMatchObject({ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] });
    expect(Object.isFrozen(seen)).toBe(true);
    expect(Object.isFrozen(seen!.acsUrls)).toBe(true);
  });
});
