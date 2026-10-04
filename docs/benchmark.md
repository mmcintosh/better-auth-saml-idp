# Benchmark: sign-ins on Cloudflare Workers and D1

How many SAML sign-ins the plugin handles on Workers, how fast, and what limits it, measured on 2026-10-04 with the scripts in [`scripts/bench`](../scripts/bench), so you can rerun it on your own account.

## Summary

- **A signed-in user's sign-in to an SP takes about 260 ms end to end**, from a client about 55 ms from the Worker, with **about 20 ms of CPU** on the Worker. Most of the rest is waiting on D1.
- **One D1 database tops out at about 28 sign-ins per second** (about 100,000 an hour). Past that, requests queue: throughput stays flat and latency grows with concurrency. No request failed at any level tested.
- **The limit is the database, not the plugin's CPU.** In this test one D1 database answered about 200 queries a second, whatever the queries were. Better Auth's own `get-session` (two reads, 4 ms of CPU) leveled off at about 110 a second the same way, and a sign-in makes about seven queries. The Workers side scaled freely: the metadata endpoint, with no database work, reached 750 requests a second at flat latency.
- **A full sign-in from nothing** (the SP's request, the password, the signed response) takes about 620 ms and tops out at about 14 a second, because Better Auth's password check (about 90 ms of CPU) and session creation add work and queries.

## Results

All runs: closed loops (each client sends its next request as soon as the last one is answered), a 5-second uncounted warm-up, then 20–30 seconds per level. Every response was checked: a sign-in counts only if it's a signed SAML Response with status Success. **Errors: none, in any run.**

### `sso`: a signed-in user signs in to an SP

One `GET /sso` with a new AuthnRequest, answered with the signed Response.

| Clients | Sign-ins | Per second | p50 ms | p95 ms | p99 ms | max ms |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 110 | 3.7 | 262 | 402 | 439 | 739 |
| 10 | 441 | 14.7 | 672 | 921 | 1119 | 1528 |
| 25 | 655 | 21.8 | 1142 | 1557 | 2070 | 2517 |
| 50 | 842 | 28.1 | 1792 | 2710 | 3104 | 5078 |

### `login`: a full sign-in from nothing

`GET /sso` (parked, 302), `POST /api/auth/sign-in/email`, `GET /resume` → signed Response, timed together.

| Clients | Sign-ins | Per second | p50 ms | p95 ms | p99 ms | max ms |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 32 | 1.6 | 623 | 790 | 803 | 803 |
| 5 | 121 | 6.0 | 813 | 1108 | 1239 | 1254 |
| 10 | 193 | 9.7 | 1073 | 1440 | 1690 | 2183 |
| 25 | 289 | 14.4 | 1807 | 2259 | 2579 | 3062 |

### Baselines

| Clients | `metadata` per second | p50 ms | `get-session` per second | p50 ms |
|---:|---:|---:|---:|---:|
| 1 | 16.9 | 55 | 9.8 | 96 |
| 10 | 181 | 50 | 71.1 | 132 |
| 25 | 453 | 51 | 98.3 | 262 |
| 50 | 754 | 61 | 110.7 | 483 |

### Worker CPU per request (a 20% sample, all levels)

| Endpoint | p50 ms | p95 ms |
|---|---:|---:|
| `/sso`, signed in (parse, checks, sign) | 20 | 50 |
| `/resume` (the same, after sign-in) | 21 | 55 |
| `/api/auth/sign-in/email` (Better Auth's password check) | 92 | 147 |
| `/api/auth/get-session` | 4 | 9 |
| `/metadata` | 1 | 3 |

Under load, an `/sso` request's wall time was a median 1,310 ms against its 20 ms of CPU: it was waiting.

## Where a sign-in's queries go

From D1's query insights for the `sso` runs. Each query took 0.25–0.5 ms inside D1, so the SQL itself is about 2–3 ms per sign-in. The ceiling comes from how many queries one database will run a second, not from how long each takes.

| Query | Why |
|---|---|
| read the session and the user | Better Auth's session check, from the database rather than a cookie cache, so a revoked session gets no assertion |
| read the user again | the plugin's re-read right before signing, so a user banned a moment ago gets nothing (a review proved it load-bearing) |
| insert the request ID | replay protection: a second use of the same AuthnRequest is refused by a UNIQUE key |
| write the logout participant | Single Logout: which SPs this session signed in to. One insert on a session's first sign-in to an SP; when the same session signs in to the same SP again, as in this benchmark, an insert, a read and an update |
| insert an audit event | the audit log (`auditLog`), in the background |

So, per D1 database:

- **Turning off what you don't use raises the ceiling.** Without `auditLog` or Single Logout, a sign-in makes one to three fewer writes.
- **Beyond one database's ceiling**, spread the load: a database per tenant, or another database. The plugin is tested on PostgreSQL, MySQL and MongoDB ([databases](guide/databases.md)); reaching Postgres from Workers through Hyperdrive should work but hasn't been benchmarked.
- **About 28 sign-ins a second is about 100,000 an hour.** Most apps never come near it. The numbers are here so you know where the edge is before you get there.

## Method

- **IdP:** the [Workers example](../examples/workers-hono) as it ships, at commit `cd4b99e` (1.1.2), deployed as its own Worker with its own D1 database ([`scripts/bench/deploy.sh`](../scripts/bench/deploy.sh)). Its audit log, Single Logout and tenants are on, as in the example. The one change: **Better Auth's rate limit is off** (`RATE_LIMIT=off`, a benchmark-only switch), because all the load came from one machine, and Better Auth limits each IP address to 100 requests in 10 seconds by default.
- **Platform:** a Workers Paid account, on workers.dev. The D1 database was created without a location hint and runs in Eastern North America (ENAM), with read replication disabled.
- **SP:** one dummy SP. Responses are returned to the client, never posted on, so no third party is involved.
- **Users:** 20 test users, signed in once beforehand ([`setup.mjs`](../scripts/bench/setup.mjs)). `sso` cycles through their sessions.
- **Load:** [`run.mjs`](../scripts/bench/run.mjs), on Node 24, from one machine about 55 ms (metadata p50) from the Worker. Each `sso` request carries a new AuthnRequest with a new ID, so replay protection does its full work.
- **CPU:** `wrangler tail` sampling 20% of requests during the runs.
- **Limits of this test:** one client location; one database region; one run per level; a closed-loop load, which shows the throughput ceiling and the queueing beyond it but isn't a model of real traffic. The D1 ceiling observed here is a measurement on one account on one day, not a published Cloudflare limit.

## Rerun it

```sh
sh scripts/bench/deploy.sh                                   # your own benchmark Worker and D1 (Workers Paid)
node scripts/bench/setup.mjs https://better-auth-saml-idp-bench.<sub>.workers.dev 20
node scripts/bench/run.mjs sso 1,10,25,50 30                 # also: login, session, metadata
sh scripts/bench/deploy.sh delete                            # remove the Worker and its database
```

Results are printed as a table and saved as JSON in `scripts/bench/.state/` (git-ignored). If you run it somewhere else (another region, read replicas, Postgres through Hyperdrive), please share what you find.
