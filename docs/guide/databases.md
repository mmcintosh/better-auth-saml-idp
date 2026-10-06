# Databases

[Guide](README.md) › Databases

The plugin stores everything through Better Auth's database adapter, so it runs on any database Better Auth supports. What matters is that the database **enforces uniqueness**: replay protection, the registry and Single Logout all rely on the database rejecting a second insert, which is what makes them hold across instances and under concurrency.

## What CI proves

The database-dependent behaviours run against a real server in CI (`test/adapters`); the full suite runs on SQLite (Node) and D1 (workerd):
- a full sign-in;
- replay protection under 10 concurrent identical requests, and the unique key enforced by the database itself (on MongoDB, from the very first insert);
- single-use resume links under concurrent use;
- a registry create race, exact-match lookups, and boolean and date round-trips;
- logout participants: upsert, list and clear;
- organization memberships (the `in` operator);
- the expiry sweep (`lt`).

| Database | Adapter | Tables | Status |
|---|---|---|---|
| SQLite | Kysely (`node:sqlite`) | `npx auth migrate` ([Next.js example](../../examples/nextjs/README.md#database): `getMigrations` in a script) | ✅ CI (the whole suite) |
| Cloudflare D1 | Drizzle | migrations ([example](../../examples/workers-hono/migrations/)) | ✅ CI (the whole suite, workerd) and live |
| PostgreSQL 17 | Kysely (a `pg` pool) | `npx auth migrate` | ✅ CI |
| MySQL 8.4 | Kysely (a `mysql2` pool) | `npx auth migrate` | ✅ CI |
| MongoDB 8.2 (replica set) | `mongodbAdapter` | created by the adapter | ✅ CI |
| PostgreSQL 17 | Drizzle (`drizzle-orm/node-postgres`) | `npx auth generate`, then your migration | ✅ CI as the query layer; tables from Better Auth's migrator ([below](#drizzle-and-prisma)) |
| MySQL 8.4 | Drizzle (`drizzle-orm/mysql2`) | `npx auth generate`, then your migration | ✅ CI as the query layer; tables from Better Auth's migrator |
| PostgreSQL 17 | Prisma 7 (`@prisma/adapter-pg`) | `npx auth generate`, then `prisma migrate` | ✅ CI as the query layer; tables from Better Auth's migrator |
| [CharDB](https://github.com/zpg6/chardb) 0.1 (Durable Objects) | CharDB's own | `chardb migrations generate` ([example](../../examples/chardb/README.md)) | 🧪 experimental: the example's flow (tenants, per-tenant keys, replay protection) in workerd, weekly in CI; not the whole suite |
| Any | Better Auth's memory adapter | | ❌ doesn't enforce uniqueness: development only |

### Drizzle and Prisma

What CI checks for Drizzle and Prisma is the **adapter**: every behaviour above, through Drizzle or Prisma queries. The **tables** in those runs are created by Better Auth's Kysely migrator, not from a Drizzle or Prisma schema, so CI doesn't check that a schema you generate carries the plugin's unique keys. The ORM schemas the tests query with are built from Better Auth's own table definitions (`getAuthTables`, in `test/adapters/orm-schemas.ts`), the way `npx auth generate` builds them; Prisma's client is generated from that schema on each run.

If you create the tables from a generated schema, check that it has these unique keys before going live; without them, the protections that rely on them are silently off:

| Table | Unique | What relies on it |
|---|---|---|
| `samlIdpSeenRequest` | `key` | AuthnRequest replay protection |
| `samlIdpServiceProvider` | `spId`; `entityId` (tenants off) or `lookupKey` (tenants on) | the registry: one SP per id and entity ID |
| `samlIdpSessionParticipant` | `key` | Single Logout: each SP once per session |
| `samlIdpTenant` | `organizationId`, `tenantKey` | tenants: one per organization, one per key |
| `samlIdpRetiredTenantKey` | `tenantKey` | tenants: a deleted tenant's key is never reused |

## Creating the tables

```bash
npx auth migrate     # Kysely (SQLite, Postgres, MySQL, MSSQL): creates the tables
npx auth generate    # Drizzle or Prisma: writes the schema; then run your ORM's migration
```

The plugin's tables are declared like any Better Auth plugin's, including their unique indexes, so these commands include them. Which tables appear depends on what you enable; see the [schema](schema.md). On D1, apply the example's SQL migrations.

## MongoDB

- **Run a replica set** (Atlas always is; for a single self-hosted server, start it with `--replSet` and run `rs.initiate()` once). Better Auth's MongoDB adapter uses transactions when given a `client`, and a standalone server rejects them.
- **Indexes are created by the adapter**, on first use of each collection, from the plugin's table-level index declarations. The plugin declares its unique indexes at table level for this reason: Better Auth 1.7's MongoDB adapter ignores field-level `unique`, and without the table-level declaration, replay protection silently did nothing on MongoDB (found by this test matrix; see [DECISIONS D-033](../../DECISIONS.md)).
- To check: `db.samlIdpSeenRequest.getIndexes()` should list `saml_idp_seen_request_key_unique` with `unique: true` after the first sign-in.

## Database load

Per sign-in, the plugin adds roughly: one insert (replay key), a pending-request write and consume if the user must sign in first, a user and session re-read, and, with Single Logout, one participant upsert. Stored SPs are cached per isolate. Expired rows are swept at most once a minute per isolate.
