// Creates benchmark users on the benchmark Worker (scripts/bench/deploy.sh), marks them verified
// in its D1 database (the example only asserts verified emails, and it sends no email), signs each
// one in, and saves their sessions and passwords to scripts/bench/.state/ (git-ignored).
//
//   node scripts/bench/setup.mjs https://better-auth-saml-idp-bench.<sub>.workers.dev [users=20]
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const base = (process.argv[2] ?? "").replace(/\/+$/, "");
const count = Number(process.argv[3] ?? 20);
if (!base.startsWith("https://")) throw new Error("usage: node scripts/bench/setup.mjs https://<bench worker> [users]");

const json = { "content-type": "application/json", origin: base };
const stamp = Date.now().toString(36);
const users = Array.from({ length: count }, (_, i) => ({ email: `bench-${stamp}-${i}@bench.invalid`, password: `${crypto.randomUUID()}Aa1!`, name: `Bench User ${i}` }));

for (const u of users) {
  const r = await fetch(`${base}/api/auth/sign-up/email`, { method: "POST", headers: json, body: JSON.stringify(u) });
  if (!r.ok) throw new Error(`sign-up ${u.email}: ${r.status} ${await r.text()}`);
}
console.log(`created ${users.length} users`);

// Verified directly in D1: there's no mailbox to read on a benchmark Worker.
execFileSync(
  "npx",
  ["wrangler", "d1", "execute", "saml-idp-bench", "--remote", "-c", "wrangler.bench.jsonc", "--command", `UPDATE users SET email_verified = 1 WHERE email LIKE 'bench-${stamp}-%@bench.invalid'`],
  { cwd: join(here, "../../examples/workers-hono"), stdio: ["ignore", "ignore", "inherit"] },
);
console.log("marked them verified");

const sessions = [];
for (const u of users) {
  const r = await fetch(`${base}/api/auth/sign-in/email`, { method: "POST", headers: json, body: JSON.stringify({ email: u.email, password: u.password }) });
  if (!r.ok) throw new Error(`sign-in ${u.email}: ${r.status} ${await r.text()}`);
  sessions.push({ ...u, cookie: r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ") });
}
mkdirSync(join(here, ".state"), { recursive: true });
writeFileSync(join(here, ".state/sessions.json"), JSON.stringify({ base, users: sessions }, null, 2), { mode: 0o600 });
console.log(`signed in ${sessions.length}; saved to scripts/bench/.state/sessions.json`);
