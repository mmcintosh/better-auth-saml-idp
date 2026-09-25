import { describe, expect, inject, it } from "vitest";
import { NAMEID_EMAIL, resolveOptions, SamlIdpConfigError } from "../../src/options";
import type { SamlIdpOptions, ServiceProviderConfig } from "../../src/types";
import { baseOptions, SP_ACS, SP_ENTITY_ID } from "../support/config";

const keys = inject("keys");

function issuesFor(options: unknown): string[] {
  try {
    resolveOptions(options as SamlIdpOptions);
  } catch (e) {
    if (e instanceof SamlIdpConfigError) return e.issues;
    throw e;
  }
  throw new Error("expected resolveOptions to throw");
}

const sp = (over: Partial<ServiceProviderConfig> = {}): ServiceProviderConfig => ({
  id: "test-sp",
  entityId: SP_ENTITY_ID,
  acsUrls: [SP_ACS],
  ...over,
});

describe("resolveOptions: defaults", () => {
  it("applies secure defaults", () => {
    const r = resolveOptions(baseOptions());
    expect(r.signing).toMatchObject({
      signatureAlgorithm: "rsa-sha256",
      digestAlgorithm: "sha256",
      signResponse: true,
      signAssertion: true,
      allowInsecureSha1: false,
      additionalCertificates: [],
    });
    expect(r.assertionLifetimeSeconds).toBe(300);
    expect(r.clockSkewSeconds).toBe(60);
    expect(r.pendingRequestTtlSeconds).toBe(600);
    expect(r.relayStateMaxBytes).toBe(80);
    expect(r.warnings).toEqual([]);
    expect(typeof r.schemaValidator.validate).toBe("function");
    expect(r.accountPolicy).toEqual({ requireEmailVerified: true, allowImpersonatedSessions: false, allowAnonymousUsers: false });
    expect(r.authnContextClassRef).toBe("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");
    expect(r.baseURL).toBeUndefined();
    expect(r.signing.keyObject.asymmetricKeyType).toBe("rsa"); // parsed once, not per request
  });

  it("applies SP defaults", async () => {
    const [s] = resolveOptions(baseOptions()).serviceProviders;
    expect(s!.nameIdFormat).toBe(NAMEID_EMAIL);
    expect(s!.requireSignedAuthnRequests).toBe(false);
    expect(s!.allowIdpInitiated).toBe(false);
    const user = { id: "u1", email: "a@example.com", name: "A", emailVerified: true, createdAt: new Date(), updatedAt: new Date() };
    expect(s!.nameId).toBeUndefined(); // default is per format, computed at issuance
    expect(s!.attributes(user)).toEqual({});
    expect(await s!.authorize({ user, session: {} as any, serviceProvider: s! })).toBe(true);
  });

  it("accepts an http loopback ACS URL for local development", () => {
    expect(() => resolveOptions(baseOptions({ serviceProviders: [sp({ acsUrls: ["http://localhost:8787/acs"] })] }))).not.toThrow();
  });

  it("keeps a custom schemaValidator", () => {
    const schemaValidator = { validate: async () => ({ valid: true as const }) };
    expect(resolveOptions(baseOptions({ schemaValidator })).schemaValidator).toBe(schemaValidator);
  });

  it("accepts additional certificates for rotation", () => {
    const r = resolveOptions(baseOptions({ signing: { ...baseOptions().signing, additionalCertificates: [keys.idpNext.certificate] } }));
    expect(r.signing.additionalCertificates).toHaveLength(1);
  });
});

describe("resolveOptions: signing algorithms", () => {
  it("rejects SHA-1 without explicit opt-in", () => {
    expect(issuesFor(baseOptions({ signing: { ...baseOptions().signing, signatureAlgorithm: "rsa-sha1" } }))).toEqual([
      "signing: SHA-1 is insecure; set signing.allowInsecureSha1: true to use it anyway",
    ]);
    expect(issuesFor(baseOptions({ signing: { ...baseOptions().signing, digestAlgorithm: "sha1" } }))).toHaveLength(1);
  });

  it("allows SHA-1 with opt-in, and warns", () => {
    const r = resolveOptions(
      baseOptions({ signing: { ...baseOptions().signing, signatureAlgorithm: "rsa-sha1", allowInsecureSha1: true } }),
    );
    expect(r.signing.signatureAlgorithm).toBe("rsa-sha1");
    expect(r.warnings.join()).toMatch(/SHA-1 is enabled/);
  });

  it("rejects unknown algorithms", () => {
    expect(issuesFor(baseOptions({ signing: { ...baseOptions().signing, signatureAlgorithm: "hmac-sha256" as any } }))[0]).toMatch(
      /^signing\.signatureAlgorithm:/,
    );
  });

  it("requires at least one of signResponse / signAssertion", () => {
    expect(issuesFor(baseOptions({ signing: { ...baseOptions().signing, signResponse: false, signAssertion: false } }))).toEqual([
      "signing: at least one of signResponse and signAssertion must be true",
    ]);
  });
});

describe("resolveOptions: key material", () => {
  it("rejects a certificate that does not match the private key", () => {
    expect(issuesFor(baseOptions({ signing: { privateKey: keys.idp.privateKey, certificate: keys.sp.certificate } }))).toEqual([
      "signing.certificate: does not match signing.privateKey",
    ]);
  });

  it("rejects non-RSA keys", () => {
    expect(issuesFor(baseOptions({ signing: keys.ec }))).toContain("signing.privateKey: must be an RSA key, got ec");
  });

  it("rejects RSA keys under 2048 bits", () => {
    expect(issuesFor(baseOptions({ signing: keys.rsa1024 }))).toContain(
      "signing.privateKey: RSA key must be at least 2048 bits, got 1024",
    );
  });

  it("only WARNS about an expired certificate (never takes the auth server down)", () => {
    const r = resolveOptions(baseOptions({ signing: keys.expired }));
    expect(r.warnings.join()).toMatch(/signing\.certificate: EXPIRED on /);
  });

  it("only warns about an expired rotation certificate in additionalCertificates", () => {
    const r = resolveOptions(baseOptions({ signing: { ...baseOptions().signing, additionalCertificates: [keys.expired.certificate] } }));
    expect(r.warnings.join()).toMatch(/signing\.additionalCertificates\.0: EXPIRED on /);
  });

  it("rejects encrypted and non-PEM private keys", () => {
    const enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----";
    expect(issuesFor(baseOptions({ signing: { ...baseOptions().signing, privateKey: enc } }))).toContain(
      "signing.privateKey: encrypted private keys are not supported",
    );
    expect(issuesFor(baseOptions({ signing: { ...baseOptions().signing, privateKey: "not a key" } }))).toContain(
      "signing.privateKey: must be a PEM private key (PKCS#1 or PKCS#8)",
    );
  });

  it("rejects a malformed certificate PEM", () => {
    expect(issuesFor(baseOptions({ signing: { ...baseOptions().signing, certificate: "nope" } }))).toContain(
      "signing.certificate: must be a PEM CERTIFICATE",
    );
  });
});

describe("resolveOptions: service providers", () => {
  it("allows an empty SP list, with a warning", () => {
    expect(resolveOptions(baseOptions({ serviceProviders: [] })).warnings).toEqual([
      "serviceProviders is empty: every AuthnRequest will be rejected",
    ]);
  });

  it("rejects duplicate ids and entity IDs", () => {
    expect(issuesFor(baseOptions({ serviceProviders: [sp(), sp()] }))).toEqual([
      'serviceProviders.1.id: duplicate id "test-sp"',
      `serviceProviders.1.entityId: duplicate entityId "${SP_ENTITY_ID}"`,
    ]);
  });

  it.each([
    ["http non-loopback", "http://sp.test/acs", /must use https/],
    ["relative", "/acs", /is not an absolute URL/],
    ["fragment", "https://sp.test/acs#x", /must not contain a fragment/],
    ["credentials", "https://u:p@sp.test/acs", /must not contain credentials/],
    ["javascript:", "javascript:alert(1)", /must use https/],
  ])("rejects ACS URL: %s", (_, url, msg) => {
    expect(issuesFor(baseOptions({ serviceProviders: [sp({ acsUrls: [url] })] })).join()).toMatch(msg);
  });

  it("rejects an empty ACS allow-list", () => {
    expect(issuesFor(baseOptions({ serviceProviders: [sp({ acsUrls: [] as any })] }))).toEqual([
      "serviceProviders.0.acsUrls: must list at least one ACS URL",
    ]);
  });

  it("requires spCertificate when requireSignedAuthnRequests is set", () => {
    expect(issuesFor(baseOptions({ serviceProviders: [sp({ requireSignedAuthnRequests: true })] }))).toEqual([
      "serviceProviders.0.spCertificate: is required when requireSignedAuthnRequests is true",
    ]);
    expect(() =>
      resolveOptions(baseOptions({ serviceProviders: [sp({ requireSignedAuthnRequests: true, spCertificate: keys.sp.certificate })] })),
    ).not.toThrow();
  });

  it("refuses IdP-initiated SSO (not in v1)", () => {
    expect(issuesFor(baseOptions({ serviceProviders: [sp({ allowIdpInitiated: true })] }))).toEqual([
      "serviceProviders.0.allowIdpInitiated: IdP-initiated SSO is not supported in this version",
    ]);
  });

  it("rejects bad SP ids and non-function hooks", () => {
    const issues = issuesFor(baseOptions({ serviceProviders: [sp({ id: "has space", authorize: true as any })] }));
    expect(issues).toContain("serviceProviders.0.id: must be 1-64 characters of A-Z a-z 0-9 _ -");
    expect(issues).toContain("serviceProviders.0.authorize: must be a function");
  });

  it("rejects unknown keys (typos must not silently disable a check)", () => {
    expect(issuesFor(baseOptions({ serviceProviders: [{ ...sp(), requireSignedAuthnRequest: true } as any] })).join()).toMatch(
      /requireSignedAuthnRequest/,
    );
  });
});

describe("resolveOptions: baseURL", () => {
  it("accepts and normalises an absolute base URL", () => {
    expect(resolveOptions(baseOptions({ baseURL: "https://auth.example.com/api/auth/" })).baseURL).toBe("https://auth.example.com/api/auth");
  });
  it.each(["/api/auth", "https://a.test/x?y=1", "https://a.test/x#f", "javascript:alert(1)"])("rejects baseURL %j", (baseURL) => {
    expect(issuesFor(baseOptions({ baseURL })).join()).toMatch(/^baseURL:/);
  });
});

describe("resolveOptions: limits", () => {
  it.each([
    [{ assertionLifetimeSeconds: 10 }, /assertionLifetimeSeconds/],
    [{ assertionLifetimeSeconds: 7200 }, /assertionLifetimeSeconds/],
    [{ relayStateMaxBytes: 40 }, /relayStateMaxBytes/],
    [{ relayStateMaxBytes: 4096 }, /relayStateMaxBytes/],
    [{ clockSkewSeconds: -1 }, /clockSkewSeconds/],
    [{ pendingRequestTtlSeconds: 5 }, /pendingRequestTtlSeconds/],
  ])("rejects out-of-range %j", (over, msg) => {
    expect(issuesFor(baseOptions(over as Partial<SamlIdpOptions>)).join()).toMatch(msg);
  });

  it("warns when assertion lifetime exceeds 5 minutes", () => {
    expect(resolveOptions(baseOptions({ assertionLifetimeSeconds: 600 })).warnings).toEqual([
      "assertionLifetimeSeconds is 600; the recommended maximum is 300",
    ]);
  });

  it.each(["sign-in", "//evil.test/login", "ftp://x", "/\\evil.example", "/sign in", "/a\u0000b"])("rejects loginPage %j", (loginPage) => {
    expect(issuesFor(baseOptions({ loginPage })).join()).toMatch(/^loginPage:/);
  });
});
