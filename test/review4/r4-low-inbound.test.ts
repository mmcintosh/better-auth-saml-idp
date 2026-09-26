// Review 4, Low items on inbound messages and what reaches logs and events.
//   L1: a signed AuthnRequest without Destination was accepted (SLO already refused this).
//   L2: Subject/NameID and its Format were unbounded, and land in the pending row.
//   L6: event details and log lines carried C1 controls and bidi overrides from attacker XML.
import { describe, expect, inject, it } from "vitest";
import { logSafe } from "../../src/saml/request";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost } from "../support/host";
import { authnRequestXml, Browser, redirectUrl } from "../support/sp";

const keys = inject("keys");
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];

describe("R4-L1: a signed AuthnRequest must carry Destination", () => {
  it("signed without Destination is refused; signed with it, or unsigned without it, still work", async () => {
    const { auth } = await createHost({ saml: { serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], spCertificate: keys.sp.certificate }] } });
    const browser = new Browser(auth);
    const res = await browser.fetch(await redirectUrl(authnRequestXml({ destination: null }).xml, { sign: true }));
    expect(await code(res)).toBe("INVALID_SAML_REQUEST");
    expect((await browser.fetch(await redirectUrl(authnRequestXml().xml, { sign: true }))).status).toBe(302);
    expect((await browser.fetch(await redirectUrl(authnRequestXml({ destination: null }).xml))).status).toBe(302);
  });
});

describe("R4-L2: the Subject an SP asks about is bounded", () => {
  const subject = (nameId: string, format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") =>
    `<saml:Subject><saml:NameID Format="${format}">${nameId}</saml:NameID></saml:Subject>`;
  it("a 60 KiB NameID or a long Format is refused before anything is stored; a normal one works", async () => {
    const { auth } = await createHost({ saml: { serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }] } });
    const browser = new Browser(auth);
    // Subject comes before NameIDPolicy in the schema, and authnRequestXml puts `inner` last, so
    // splice it in right after the Issuer.
    const withSubject = (s: string) => authnRequestXml().xml.replace("</saml:Issuer>", `</saml:Issuer>${s}`);
    expect(await code(await browser.fetch(await redirectUrl(withSubject(subject("a".repeat(60 * 1024))))))).toBe("INVALID_SAML_REQUEST");
    expect(await code(await browser.fetch(await redirectUrl(withSubject(subject("u@example.com", `urn:x:${"f".repeat(300)}`)))))).toBe("INVALID_SAML_REQUEST");
    expect((await browser.fetch(await redirectUrl(withSubject(subject("u@example.com"))))).status).toBe(302);
  });
});

describe("R4-L6: log-safe text has no characters that make it read differently", () => {
  it("C0, C1, bidi overrides and invisible formatting characters are replaced", () => {
    for (const c of ["\u0000", "\u001b", "\u007f", "\u0085", "\u009b", "؜", "​", "‎", "‮", "⁦", "⁩", "﻿"])
      expect(logSafe(`a${c}b`)).toBe("a?b");
    expect(logSafe("Ünïcødé text, 日本語")).toBe("Ünïcødé text, 日本語");
  });
});
