# Databases

[Guide](README.md) › Databases

The plugin stores everything through Better Auth's database adapter, so it runs on any database Better Auth supports. What matters is that the database **enforces uniqueness**: replay protection, the registry and Single Logout all rely on the database rejecting a second insert, which is what makes them hold across instances and under concurrency.

## What CI proves

Every database-dependent behaviour runs against a real server in CI (`test/adapters`):
- a full sign-in;
- replay protection under 10 concurrent identical requests, and the unique key enforced by the database itself (on MongoDB, from the very first insert);
- single-use resume links under concurrent use;
- a registry create race, exact-match lookups, and boolean and date round-trips;
- logout participants: upsert, list and clear;
- organization memberships (the `in` operator);
- the expiry sweep (`lt`).

| Database | Adapter | Tables | Status |
|---|---|---|---|
| SQLite | Kysely (`node:sqlite`) | `npx auth migrate` | ✅ CI (the whole suite) |
| Cloudflare D1 | Drizzle | migrations ([example](../../examples/workers-hono/migrations/)) | ✅ CI (the whole suite, workerd) and live |
| PostgreSQL 17 | Kysely (a `pg` pool) | `npx auth migrate` | ✅ CI |
| MySQL 8.4 | Kysely (a `mysql2` pool) | `npx auth migrate` | ✅ CI |
| MongoDB 8.2 (replica set) | `mongodbAdapter` | created by the adapter | ✅ CI |
| PostgreSQL / MySQL | Drizzle | `npx auth generate` | expected to work; not yet in CI |
| Any | Prisma | `npx auth generate` | expected to work; not yet in CI |
| Any | Better Auth's memory adapter | | ❌ doesn't enforce uniqueness: development only |

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
