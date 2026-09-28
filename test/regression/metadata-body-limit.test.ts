// R3-1: D-026 / docs/security.md claim the SP metadata fetch reads "at most 1 MiB". The cap is
// enforced only via the Content-Length header; a chunked/streamed body without one is read in
// full by `res.text()` before precheckXml sees it. A metadata host (or whoever controls the URL)
// can make the IdP buffer hundreds of MB on the request path (the first use awaits the fetch),
// which on Workers exceeds the isolate memory limit.
import { afterEach, describe, expect, inject, it, vi } from "vitest";
import { resolveOptions } from "../../src/options";
import { SpMetadataCache } from "../../src/saml/sp-metadata-refresh";
import { libxml2Validator } from "../../src/saml/validator";
import { baseOptions, SP_ACS, SP_ENTITY_ID } from "../support/config";

const MD_URL = "https://sp.test/saml/metadata.xml";
const MiB = 1024 * 1024;

afterEach(() => vi.unstubAllGlobals());

describe("SP metadata refresh: body size cap", () => {
  it("stops reading a streamed metadata body (no Content-Length) at about 1 MiB", async () => {
    inject("keys");
    const sp = resolveOptions(baseOptions({ serviceProviders: [{ id: "md-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], metadata: { url: MD_URL } }] })).serviceProviders[0]!;
    const chunk = new Uint8Array(64 * 1024).fill(0x20); // whitespace: never becomes valid XML
    let pulled = 0;
    vi.stubGlobal("fetch", async () => {
      const stream = new ReadableStream<Uint8Array>({
        pull(c) {
          if (pulled >= 6 * MiB) return c.close();
          pulled += chunk.byteLength;
          c.enqueue(chunk);
        },
      });
      // A streamed Response carries no Content-Length, exactly like a chunked HTTP response.
      return new Response(stream, { status: 200, headers: { "content-type": "application/samlmetadata+xml" } });
    });
    const cache = new SpMetadataCache(libxml2Validator());
    const logs: string[] = [];
    const out = await cache.prepare(sp, { info: (m) => logs.push(m), warn: (m) => logs.push(m) }, () => {});
    expect(out.spCertificates).toEqual([]); // nothing learned, as documented
    // The documented bound: at most 1 MiB is fetched. Allow one extra chunk of slack.
    // Allow two chunks of slack: the reader stops once past 1 MiB, and the stream has already
    // pulled one chunk ahead (highWaterMark 1). Bounded either way.
    expect(pulled).toBeLessThanOrEqual(MiB + 2 * chunk.byteLength);
  });
});
