// better-auth-saml-idp on CharDB, end to end inside workerd: the root IdP, a tenant with its own
// signing key, SP-initiated sign-in through the tenant, replay protection, key rotation, and a
// non-member refused. The plugin's own test suite covers the rest; this proves it on CharDB.
import { env, exports } from "cloudflare:workers";
import { beforeAll, describe, expect, test } from "vitest";
import { migrations } from "../src/migrations.ts";

const origin = env.BETTER_AUTH_URL;
const IDP = origin + "/api/auth/saml2/idp";

const request = (path: string, init?: RequestInit) => exports.default.fetch(new Request(new URL(path, origin), { redirect: "manual", ...init }));

function mergeCookies(current: string, headers: Headers): string {
  const cookies = new Map<string, string>();
  for (const c of [...current.split("; "), ...headers.getSetCookie().map((v) => v.split(";", 1)[0] ?? "")]) {
    const i = c.indexOf("=");
    if (i > 0) cookies.set(c.slice(0, i), c);
  }
  return [...cookies.values()].join("; ");
}

/** A Better Auth or plugin API call as a signed-in browser would make it. */
async function api(path: string, cookie: string, body?: unknown) {
  const res = await request("/api/auth/" + path, {
    method: body === undefined ? "GET" : "POST",
    headers: { origin, cookie, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, cookie: mergeCookies(cookie, res.headers) };
}

async function migrate() {
  const call = async (path: string, body?: unknown) => {
    const res = await request("/_chardb/migrations/" + path, {
      method: body ? "POST" : "GET",
      headers: { authorization: "Bearer " + env.CDB_ADMIN_TOKEN, ...(body ? { "content-type": "application/json" } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const json = (await res.json()) as any;
    expect(res.status, JSON.stringify(json)).toBe(200);
    return json;
  };
  const { state } = await call("state");
  if (state.activeVersion >= migrations.version) return;
  const migrationId = "vitest-saml";
  await call("begin", { migrationId, targetVersion: migrations.version });
  await call("shard", { migrationId, shardId: "ShardDO_0" });
  for (let v = state.activeVersion + 1; v <= migrations.version; v++) await call("catalog", { migrationId, version: v });
  await call("complete", { migrationId });
}

/** Sign up, open the verification link from the dev mailbox (auto sign-in), return the cookie. */
async function verifiedUser(email: string): Promise<string> {
  const up = await api("sign-up/email", "", { email, password: "correct-horse-battery", name: email });
  expect(up.status, JSON.stringify(up.body)).toBe(200);
  const mail = (await (await request("/dev/mailbox?email=" + encodeURIComponent(email))).json()) as { link: string };
  const verified = await request(mail.link);
  expect([200, 302]).toContain(verified.status);
  const cookie = mergeCookies("", verified.headers);
  expect(cookie).toContain("session_token");
  return cookie;
}

/** An HTTP-Redirect AuthnRequest URL for `sso` from SP `issuer`. */
async function authnRequest(sso: string, issuer: string, acs: string): Promise<{ url: string; id: string }> {
  const id = "_" + crypto.randomUUID();
  const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${new Date().toISOString()}" Destination="${sso}" AssertionConsumerServiceURL="${acs}"><saml:Issuer>${issuer}</saml:Issuer></samlp:AuthnRequest>`;
  const deflated = new Uint8Array(await new Response(new Blob([xml]).stream().pipeThrough(new CompressionStream("deflate-raw"))).arrayBuffer());
  return { url: sso + "?SAMLRequest=" + encodeURIComponent(btoa(String.fromCharCode(...deflated))), id };
}

const samlResponse = (html: string) => atob(/name="SAMLResponse" value="([^"]+)"/.exec(html)?.[1] ?? "");
const certsOf = (xml: string) => [...xml.matchAll(/<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/g)].map((m) => m[1]?.replace(/\s/g, ""));
const pemBody = (pem: string) => pem.replace(/-----[^-]+-----|\s/g, "");

describe("better-auth-saml-idp on CharDB", () => {
  let admin = "";
  let organizationId = "";
  const sp = { entityId: "https://app.acme.test/sp", acs: "https://app.acme.test/acs" };

  beforeAll(async () => {
    await migrate();
    admin = await verifiedUser("admin@chardb.test");
  });

  test("the root IdP publishes its metadata", async () => {
    const res = await request("/api/auth/saml2/idp/metadata");
    expect(res.status).toBe(200);
    const xml = await res.text();
    expect(xml).toContain(`entityID="${IDP}"`);
    expect(certsOf(xml)).toEqual([pemBody(env.SAML_IDP_CERT)]);
  });

  test("a tenant gets its own identity and signing key", async () => {
    const org = await api("organization/create", admin, { name: "Acme", slug: "acme", keepCurrentActiveOrganization: true });
    expect(org.status, JSON.stringify(org.body)).toBe(200);
    organizationId = org.body.id;
    const created = await api("saml-idp/tenants/create", admin, { organizationId, tenantKey: "acme" });
    expect(created.status, JSON.stringify(created.body)).toBe(200);
    expect(created.body.tenant).toMatchObject({ entityId: IDP + "/metadata/acme", signing: "own", keys: [expect.objectContaining({ state: "active" })] });

    const xml = await (await request("/api/auth/saml2/idp/metadata/acme")).text();
    expect(xml).toContain(`entityID="${IDP}/metadata/acme"`);
    expect(certsOf(xml)).toEqual([pemBody(created.body.tenant.keys[0].certificate)]);
    expect(certsOf(xml)).not.toContain(pemBody(env.SAML_IDP_CERT));
  });

  test("SP-initiated sign-in through the tenant: issued by the tenant, signed with its key, replay refused", async () => {
    const stored = await api("saml-idp/service-providers/create", admin, {
      serviceProvider: { id: "acme-app", entityId: sp.entityId, acsUrls: [sp.acs], tenant: organizationId, attributes: { email: "email" } },
    });
    expect(stored.status, JSON.stringify(stored.body)).toBe(200);

    const { url } = await authnRequest(IDP + "/sso/acme", sp.entityId, sp.acs);
    const res = await request(url, { headers: { cookie: admin } });
    const html = await res.text();
    expect(res.status, html.slice(0, 300)).toBe(200);
    expect(html).toContain(`action="${sp.acs}"`);
    const xml = samlResponse(html);
    expect(xml).toContain(`<saml:Issuer>${IDP}/metadata/acme</saml:Issuer>`);
    expect(xml).toContain("admin@chardb.test");
    const keys = await api("saml-idp/tenants/keys?organizationId=" + organizationId, admin);
    const active = keys.body.tenant.keys.find((k: any) => k.state === "active");
    expect(certsOf(xml)).toContain(pemBody(active.certificate));

    // The same AuthnRequest again: its ID is single-use (a UNIQUE key in CharDB).
    const replay = await request(url, { headers: { cookie: admin } });
    expect(await replay.text()).toContain("DUPLICATE_REQUEST_ID");

    // The sign-in reaches the tenant's audit log. It's written in the background, which on Workers
    // needs waitUntil: CharDB hands Better Auth the Worker's (since zpg6/chardb#40).
    let events: { type: string; spId: string | null }[] = [];
    for (let i = 0; i < 30 && !events.some((e) => e.type === "assertion.issued"); i++) {
      await new Promise((r) => setTimeout(r, 100));
      events = (await api(`saml-idp/audit?tenantId=${organizationId}`, admin)).body.events;
    }
    expect(events).toContainEqual(expect.objectContaining({ type: "assertion.issued", spId: "acme-app" }));
  });

  test("the tenant's key rotates: rotate, then activate (forced here; 24 hours otherwise)", async () => {
    const before = (await api("saml-idp/tenants/keys?organizationId=" + organizationId, admin)).body.tenant.keys;
    const rotated = await api("saml-idp/tenants/keys/rotate", admin, { organizationId });
    expect(rotated.status, JSON.stringify(rotated.body)).toBe(200);
    const early = await api("saml-idp/tenants/keys/activate", admin, { organizationId });
    expect(early.body.code).toBe("TENANT_SIGNING_KEY_TOO_NEW");
    const activated = await api("saml-idp/tenants/keys/activate", admin, { organizationId, force: true });
    expect(activated.status, JSON.stringify(activated.body)).toBe(200);
    const after = activated.body.tenant.keys;
    const newActive = after.find((k: any) => k.state === "active");
    expect(newActive.kid).not.toBe(before.find((k: any) => k.state === "active").kid);
    expect(after.find((k: any) => k.state === "previous")).toBeTruthy();
    const xml = await (await request("/api/auth/saml2/idp/metadata/acme")).text();
    expect(certsOf(xml)).toContain(pemBody(newActive.certificate));
  });

  test("a user outside the tenant's organization is refused, and can't manage it", async () => {
    const stranger = await verifiedUser("stranger@chardb.test");
    const { url } = await authnRequest(IDP + "/sso/acme", sp.entityId, sp.acs);
    const res = await request(url, { headers: { cookie: stranger } });
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("ACCESS_DENIED");
    const tenants = await api("saml-idp/tenants", stranger);
    expect(tenants.status).toBe(403);
  });
});
