// Fixed in D-061: a tenant certificate's CN is "saml-idp tenant <tenantKey>", and a tenant key
// may be 64 characters, so the CN could reach 80, past RFC 5280's ub-common-name (64), which
// strict X.509 parsers enforce. It is cut to 64 characters.
import { X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import { generateTenantKey } from "../../src/saml/tenant-keys";

describe("tenant certificate common name", () => {
  it("stays within 64 characters for a 64-character tenant key", () => {
    const { certificate } = generateTenantKey("k".repeat(64));
    const cn = /CN=(.*)/.exec(new X509Certificate(certificate).subject)?.[1] ?? "";
    expect(cn.startsWith("saml-idp tenant k")).toBe(true);
    expect(cn.length).toBe(64);
  });
});
