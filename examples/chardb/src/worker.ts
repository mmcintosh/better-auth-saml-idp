import { client } from "@chardb/core";
import { FileId } from "@chardb/core/files";
import { chardb } from "@chardb/core/server";
import { desc, eq } from "drizzle-orm";
import * as api from "./api.ts";
import { auth, devMailbox } from "./auth.ts";
import { migrations } from "./migrations.ts";
import * as queries from "./queries.ts";
import * as domain from "./schema.ts";
import { signInPage } from "./sign-in.ts";

// One factory call composes the runtime: merged Drizzle schema, lazy
// manifest from `api`'s exports, Hono router for non-reserved routes,
// and the Durable Object classes wired by the generated Wrangler config.
// The returned `app` is the wrangler-ready module. Chain routes on it.
export const app = chardb({
  ownership: "organization",
  auth,
  schema: domain,
  api: { ...api, ...queries },
  migrations,
});

app.get("/health", (c) => c.json({
  ok: true,
  deploymentId: "chardb.app.v1/a90a2d91-d596-4594-88b2-ba56dcb8c345",
  schemaVersion: migrations.version,
  schemaDigest: migrations.digest,
}));
// The IdP's login page (samlIdp loginPage): signs in by email, then returns to callbackURL.
app.get("/sign-in", (c) => signInPage(c.req.url));
// DEVELOPMENT ONLY (DEV_MAILBOX="true"): the verification link that would have been emailed.
app.get("/dev/mailbox", (c) => {
  if (process.env.DEV_MAILBOX !== "true") return c.notFound();
  const email = c.req.query("email") ?? "";
  const link = devMailbox.get(email);
  return link ? c.json({ email, link }) : c.json({ email, link: null }, 404);
});
app.get("/api/messages", async (c) => {
  const token = c.req.header("authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) return c.json({ error: "missing bearer token" }, 401);
  const url = new URL(c.req.url);
  const organizationId = url.searchParams.get("organizationId") ?? "";
  const requestedLimit = Number(url.searchParams.get("limit") ?? "50");
  if (!Number.isInteger(requestedLimit) || requestedLimit < 1 || requestedLimit > 100) {
    return c.json({ error: "limit must be an integer from 1 through 100" }, 400);
  }
  const rows = await client(c.env.DB, { jwt: token, authOrigin: url.origin })
    .select()
    .from(domain.messages)
    .where(eq(domain.messages.organizationId, organizationId))
    .orderBy(desc(domain.messages.createdAt), desc(domain.messages.id))
    .limit(requestedLimit);
  return c.json(rows);
});
app.post("/api/messages", async (c) => {
  const token = c.req.header("authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) return c.json({ error: "missing bearer token" }, 401);
  const body = await c.req.json<{
    id: string;
    organizationId: string;
    body: string;
    attachment?: string | null;
    clientCreatedAt: number;
  }>();
  return c.json(await client(c.env.DB, { jwt: token, authOrigin: new URL(c.req.url).origin })
    .mutate(api.postMessage, {
      ...body,
      attachment: body.attachment == null ? null : FileId(body.attachment),
    }));
});

export default app;
export const { DB, Catalog, Cdb, Gateway, Resharder } = app;
