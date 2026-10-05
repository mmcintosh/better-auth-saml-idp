// External review of 1.1.2 (D-065): SP metadata over 128 KiB was refused by the validator's own
// size check, though the docs (and the metadata fetch) allow 1 MiB. Metadata is now held to 1 MiB,
// protocol messages still to 128 KiB.
import { expect, it } from "vitest";
import { serviceProviderFromMetadata } from "../../src/index";

it("a schema-valid SP metadata document of about 200 KB is accepted", async () => {
  const descriptors = Array.from({ length: 900 }, (_, i) => `<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.test/acs/${i}/${"p".repeat(150)}" index="${i}"/>`).join("");
  const xml = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.test/sp"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${descriptors}</md:SPSSODescriptor></md:EntityDescriptor>`;
  expect(new TextEncoder().encode(xml).byteLength).toBeGreaterThan(160_000);
  const r = await serviceProviderFromMetadata(xml, { id: "big" });
  expect(r.serviceProvider.entityId).toBe("https://sp.test/sp");
});
