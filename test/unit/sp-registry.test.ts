import { describe, expect, it } from "vitest";
import { resolveOptions } from "../../src/options";
import { createSpRegistry, resolveAcsUrl } from "../../src/saml/sp-registry";
import { baseOptions, SP_ENTITY_ID } from "../support/config";

const options = () =>
  resolveOptions(
    baseOptions({
      serviceProviders: [
        { id: "a", entityId: SP_ENTITY_ID, acsUrls: ["https://sp.test/acs", "https://sp.test/acs2?x=1"] },
        { id: "b", entityId: "urn:example:sp-b", acsUrls: ["https://b.test/acs"] },
      ],
    }),
  );

describe("SP registry", () => {
  it("looks up by exact entity ID and by id", () => {
    const reg = createSpRegistry(options().serviceProviders);
    expect(reg.byEntityId(SP_ENTITY_ID)?.id).toBe("a");
    expect(reg.byEntityId("urn:example:sp-b")?.id).toBe("b");
    expect(reg.byId("b")?.entityId).toBe("urn:example:sp-b");
  });

  it.each([`${SP_ENTITY_ID}/`, SP_ENTITY_ID.toUpperCase(), ` ${SP_ENTITY_ID}`, "", "urn:example:unknown"])(
    "does not match a near-miss issuer %j",
    (issuer) => {
      expect(createSpRegistry(options().serviceProviders).byEntityId(issuer)).toBeUndefined();
    },
  );
});

describe("resolveAcsUrl", () => {
  const sp = () => createSpRegistry(options().serviceProviders).byId("a")!;

  it("uses the first registered URL when none is requested", () => {
    expect(resolveAcsUrl(sp(), undefined)).toBe("https://sp.test/acs");
    expect(resolveAcsUrl(sp(), "")).toBe("https://sp.test/acs");
    expect(resolveAcsUrl(sp(), null)).toBe("https://sp.test/acs");
  });

  it("returns a requested URL only on exact match", () => {
    expect(resolveAcsUrl(sp(), "https://sp.test/acs2?x=1")).toBe("https://sp.test/acs2?x=1");
  });

  it.each([
    "https://evil.test/acs",
    "https://sp.test/acs/",
    "https://sp.test/ACS",
    "https://sp.test/acs?x=1",
    "https://sp.test/acs2?x=1&y=2",
    "https://sp.test:443/acs",
    "https://sp.test/acs#frag",
    "http://sp.test/acs",
  ])("rejects near-miss %s (never falls back to a default)", (requested) => {
    expect(resolveAcsUrl(sp(), requested)).toBeUndefined();
  });
});
