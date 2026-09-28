// Creates or updates the tables in ./data.db: Better Auth's own and the SAML plugin's
// (samlIdpSeenRequest, …), from the same options the app runs with. Safe to run again.
// Run with `pnpm db:migrate` (Node strips the types; it reads .env.local).
import { getMigrations } from "better-auth/db/migration";
import { getAuth } from "../src/lib/auth.ts";

const { toBeCreated, toBeAdded, runMigrations } = await getMigrations(getAuth().options);
if (!toBeCreated.length && !toBeAdded.length) {
  console.log("database is up to date");
} else {
  await runMigrations();
  const tables = [...toBeCreated, ...toBeAdded].map((t) => t.table);
  console.log(`migrated: ${[...new Set(tables)].join(", ")}`);
}
