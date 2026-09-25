// R3-4: recordParticipant() stores expiresAt = the session's expiresAt at issuance time. Better
// Auth extends a session's expiresAt on use (session.updateAge), but the participant row is never
// extended, and sweepExpired() deletes it once the ORIGINAL expiry passes. A long-lived session
// therefore loses its SLO participants while it is still valid: logout no longer reaches those
// SPs, and the originator/IdP still report Success.
import { describe, expect, it } from "vitest";
import { resetSweepThrottle, sweepExpired } from "../../src/storage/sweep";
import { listParticipants } from "../../src/storage/participants";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, SSO_URL } from "../support/sp";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("Single Logout: participants must live as long as the session", () => {
  it("a refreshed (extended) session keeps its logout participants", async () => {
    const { auth } = await createHost({
      auth: { session: { expiresIn: 4, updateAge: 1 } },
      saml: {
        singleLogout: { enabled: true },
        serviceProviders: [{ id: "sp-b", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], singleLogoutService: { url: "https://sp.test/slo" } }],
      },
    });
    const browser = new Browser(auth);
    await browser.signUp();
    const t0 = Date.now();
    const xml = authnRequestXml({ issuer: SP_ENTITY_ID, acsUrl: SP_ACS }).xml;
    const url = `${SSO_URL}?SAMLRequest=${encodeURIComponent(Buffer.from((await import("node:zlib")).deflateRawSync(xml)).toString("base64"))}`;
    await readAutoPost(await browser.fetch(url)); // SP is now a participant, expiresAt = t0 + 4 s

    await sleep(2000);
    // Using the session extends it (updateAge 1 s < age): new expiresAt ~ now + 4 s.
    const s1 = (await (await browser.fetch(`${AUTH_BASE}/get-session`)).json()) as { session: { id: string; expiresAt: string } } | null;
    expect(s1).not.toBeNull();
    expect(new Date(s1!.session.expiresAt).getTime()).toBeGreaterThan(t0 + 5000);

    await sleep(2600); // past the ORIGINAL expiry, well before the extended one
    const s2 = (await (await browser.fetch(`${AUTH_BASE}/get-session`)).json()) as { session: { id: string } } | null;
    expect(s2).not.toBeNull(); // session still valid

    const ctx = await auth.$context;
    // Sweep at the real "now" (throttle reset): the original expiry has passed, the extended one hasn't.
    resetSweepThrottle();
    await sweepExpired(ctx.adapter as any, () => {}, Date.now(), { participants: true });
    // The session is alive, so its participant list must still name the SP.
    expect((await listParticipants(ctx.adapter as any, s2!.session.id)).participants.map((p) => p.spId)).toEqual(["sp-b"]);

    // Consequence: IdP-initiated logout goes straight to returnTo without a LogoutRequest to the SP.
    const res = await browser.fetch(`${AUTH_BASE}/saml2/idp/logout?returnTo=/`);
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get("location")!).origin).toBe("https://sp.test");
  });
});
