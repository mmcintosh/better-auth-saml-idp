import { setupNetwork } from "@msw/cloudflare";
import { env, exports } from "cloudflare:workers";
import { HttpResponse, http } from "msw";
import { describe, expect, test } from "vitest";
import { migrations } from "../src/migrations.ts";

const origin = "https://chardb.test";
const migrationId = "vitest-initial-schema";

async function request(path: string, init?: RequestInit): Promise<Response> {
  return exports.default.fetch(new Request(new URL(path, origin), init));
}

async function json(path: string, init?: RequestInit): Promise<{ response: Response; body: any }> {
  const response = await request(path, init);
  const text = await response.text();
  let body: any;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(path + " returned invalid JSON (" + response.status + "): " + text);
  }
  return { response, body };
}

async function migration(path: string, body?: Record<string, unknown>): Promise<any> {
  const result = await json("/_chardb/migrations/" + path, {
    method: body ? "POST" : "GET",
    headers: {
      authorization: "Bearer " + env.CDB_ADMIN_TOKEN,
      ...(body ? { "content-type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  expect(result.response.status, JSON.stringify(result.body)).toBe(200);
  expect(result.body.ok).toBe(true);
  return result.body;
}

function responseCookies(headers: Headers): string[] {
  return headers.getSetCookie();
}

function mergeCookies(current: string, headers: Headers): string {
  const cookies = new Map<string, string>();
  const pairs = [
    ...current.split("; "),
    ...responseCookies(headers).map(value => value.split(";", 1)[0] ?? ""),
  ];
  for (const cookie of pairs) {
    const separator = cookie.indexOf("=");
    if (separator > 0) cookies.set(cookie.slice(0, separator), cookie);
  }
  return [...cookies.values()].join("; ");
}

async function auth(path: string, cookie: string, body?: Record<string, unknown>) {
  const result = await json("/api/auth/" + path, {
    method: body ? "POST" : "GET",
    headers: {
      origin,
      ...(cookie ? { cookie } : {}),
      ...(body ? { "content-type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  expect(result.response.status, JSON.stringify(result.body)).toBe(200);
  return {
    body: result.body,
    cookie: mergeCookies(cookie, result.response.headers),
  };
}

describe("generated Cloudflare Worker", () => {
  test("migrates, authenticates, and persists one organization", async () => {
    expect(typeof env.CDB_CATALOG.idFromName).toBe("function");
    expect(typeof env.CDB_SHARD.idFromName).toBe("function");
    expect(typeof env.CDB_GATEWAY.idFromName).toBe("function");
    expect(typeof env.CDB_RESHARD.idFromName).toBe("function");

    const r2Key = "vitest/native-binding";
    await env.CDB_FILES.put(r2Key, "bound through wrangler.toml");
    expect(await (await env.CDB_FILES.get(r2Key))?.text()).toBe("bound through wrangler.toml");
    await env.CDB_FILES.delete(r2Key);

    const health = await json("/health");
    expect(health.response.status, JSON.stringify(health.body)).toBe(200);
    expect(health.body).toMatchObject({
      ok: true,
      deploymentId: "chardb.app.v1/a90a2d91-d596-4594-88b2-ba56dcb8c345",
      schemaVersion: migrations.version,
      schemaDigest: migrations.digest,
    });
    const targetVersion = migrations.version;

    const before = await migration("state");
    expect(before.state).toMatchObject({ status: "active" });
    expect(Number.isSafeInteger(before.state.activeVersion)).toBe(true);
    expect(before.state.activeVersion).toBeLessThanOrEqual(targetVersion);

    if (before.state.activeVersion < targetVersion) {
      await migration("begin", { migrationId, targetVersion });
      const inventory = await migration("shards?migrationId=" + migrationId);
      expect(inventory.shards.map((shard: { shardId: string }) => shard.shardId)).toEqual(["ShardDO_0"]);
      await migration("shard", { migrationId, shardId: "ShardDO_0" });
      for (let version = before.state.activeVersion + 1; version <= targetVersion; version++) {
        await migration("catalog", { migrationId, version });
      }
      await migration("complete", { migrationId });
    }

    const after = await migration("state");
    expect(after.state).toMatchObject({ activeVersion: targetVersion, status: "active", migrationId: null });

    const signedIn = await auth("sign-in/anonymous", "", {});
    expect(signedIn.cookie).not.toBe("");
    let cookie = signedIn.cookie;
    const slug = "vitest-" + crypto.randomUUID();
    const created = await auth("organization/create", cookie, {
      name: "Vitest organization",
      slug,
      keepCurrentActiveOrganization: true,
    });
    cookie = created.cookie;
    const organizationId = created.body.id;
    expect(typeof organizationId).toBe("string");

    const active = await auth("organization/set-active", cookie, { organizationId });
    cookie = active.cookie;
    const organizations = await auth("organization/list", cookie);
    expect(organizations.body).toEqual([
      expect.objectContaining({ id: organizationId, name: "Vitest organization", slug }),
    ]);
    const session = await auth("get-session", cookie);
    expect(session.body.session.activeOrganizationId).toBe(organizationId);

    const jwks = await json("/api/auth/jwks");
    expect(jwks.response.status, JSON.stringify(jwks.body)).toBe(200);
    let jwksRequests = 0;
    const network = setupNetwork();
    network.configure({ onUnhandledFrame: "error" });
    network.use(
      http.get(origin + "/api/auth/jwks", () => {
        jwksRequests += 1;
        return HttpResponse.json(jwks.body);
      }, { once: true }),
    );
    await network.enable();
    try {
      const token = await auth("token", cookie);
      expect(typeof token.body.token).toBe("string");

      const messageId = crypto.randomUUID();
      const written = await json("/api/messages", {
        method: "POST",
        headers: {
          authorization: "Bearer " + token.body.token,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          id: messageId,
          organizationId,
          body: "written inside workerd",
          clientCreatedAt: Date.now(),
        }),
      });
      expect(written.response.status, JSON.stringify(written.body)).toBe(200);
      expect(written.body.id).toBe(messageId);

      const read = await json("/api/messages?organizationId=" + encodeURIComponent(organizationId), {
        headers: { authorization: "Bearer " + token.body.token },
      });
      expect(read.response.status, JSON.stringify(read.body)).toBe(200);
      expect(read.body).toEqual([
        expect.objectContaining({ id: messageId, organizationId, body: "written inside workerd" }),
      ]);
      expect(jwksRequests).toBe(1);
    } finally {
      await network.disable();
    }
  });
});
