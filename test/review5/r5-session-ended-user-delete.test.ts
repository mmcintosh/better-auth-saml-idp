// Fixed in D-048; kept as regression tests. Comments saying "today" describe fad67c2.
// Review 5 (D-043): deleting a user ends their sessions through the hooks (session.ended fires),
// but the participant rows, which carry the NameID (usually the email), outlive the user until the
// old session's expiry (7 days by default). Nothing removes them on user deletion.
import { describe, expect, it, vi } from "vitest";
import type { SamlIdpEvent, SessionEndedEvent } from "../../src/events";
import { PARTICIPANT_MODEL } from "../../src/storage/participants";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

describe("R5-3: participant rows outlive a deleted user", () => {
  it("after deleteUser, no participant row should still name the user (today they stay, with the NameID, until expiry)", async () => {
    const events: SamlIdpEvent[] = [];
    const { auth } = await createHost({
      saml: {
        serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }],
        events: { onSessionEnded: (e) => void events.push(e) },
      },
    });
    const browser = new Browser(auth);
    const user = await browser.signUp();
    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    expect(xml).toContain("<saml:Assertion");
    const ctx = await auth.$context;
    await ctx.internalAdapter.deleteUser(user.id);
    // The end of the session is reported (this passes today).
    await vi.waitFor(() => expect(events.filter((e): e is SessionEndedEvent => e.type === "session.ended")).toHaveLength(1));
    expect((events[0] as SessionEndedEvent).participants[0]?.nameId).toBe(user.email);
    // The user is gone…
    expect(await ctx.internalAdapter.findUserById(user.id)).toBeNull();
    // …but their SP-session rows, NameID included, are not.
    const rows = (await ctx.adapter.findMany({ model: PARTICIPANT_MODEL, where: [{ field: "userId", value: user.id }] })) as { nameId: string }[];
    expect(rows).toHaveLength(0);
  });
});
