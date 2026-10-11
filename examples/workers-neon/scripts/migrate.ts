// Creates or updates the tables in the Postgres database at DATABASE_URL: Better Auth's own and
// the SAML plugin's (samlIdpSeenRequest, …), from the same options the Worker runs with. Safe to
// run again. Use Neon's direct connection string here, not Hyperdrive's.
// Run with `DATABASE_URL=… pnpm db:migrate` (Node strips the types; it reads .dev.vars for the
// settings the options need; the tables don't depend on their values).
import { getMigrations } from "better-auth/db/migration";
import { Pool } from "pg";
import { type AuthEnv, buildAuth } from "../src/auth.ts";

const url = process.env.DATABASE_URL;
if (!url) throw new Error("DATABASE_URL is not set: the Postgres connection string to migrate");
const pool = new Pool({ connectionString: url });
try {
  const { toBeCreated, toBeAdded, runMigrations } = await getMigrations(buildAuth(process.env as unknown as AuthEnv, "http://localhost:8787", pool).options);
  if (!toBeCreated.length && !toBeAdded.length) {
    console.log("database is up to date");
  } else {
    await runMigrations();
    const tables = [...toBeCreated, ...toBeAdded].map((t) => t.table);
    console.log(`migrated: ${[...new Set(tables)].join(", ")}`);
  }
} finally {
  await pool.end();
}
