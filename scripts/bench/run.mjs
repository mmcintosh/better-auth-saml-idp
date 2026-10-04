// Load test of the benchmark Worker, using the sessions from setup.mjs. Closed loops: N concurrent
// clients, each sending its next request as soon as the last one is answered, for a fixed time
// after an uncounted warm-up. Every response is checked, not just timed.
//
//   node scripts/bench/run.mjs [scenario=sso] [concurrency=1,10,25,50] [seconds=30]
//
// Scenarios:
//   sso       a signed-in user's SP-initiated sign-in: one GET /sso with a new AuthnRequest, answered
//             with a signed SAML Response (Success). The IdP's hot path: request parsing and checks,
//             replay protection (a D1 write), session and user re-reads, signing, and the audit and
//             logout-participant writes.
//   login     a full sign-in from nothing: GET /sso (parked, 302), POST the password, GET /resume →
//             signed Response. Adds Better Auth's password check (scrypt) and session creation.
//   metadata  GET the IdP metadata: a baseline for the platform's own overhead.
//   session   GET Better Auth's get-session for a signed-in user: two D1 reads and little CPU, to
//             tell a database limit from a CPU one.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";

const here = dirname(fileURLToPath(import.meta.url));
const state = JSON.parse(readFileSync(join(here, ".state/sessions.json"), "utf8"));
const base = state.base;
const scenario = process.argv[2] ?? "sso";
const levels = (process.argv[3] ?? "1,10,25,50").split(",").map(Number);
const seconds = Number(process.argv[4] ?? 30);
const WARMUP_MS = 5000;
const SP = "https://bench.invalid/sp";
const SSO = `${base}/api/auth/saml2/idp/sso`;

function ssoUrl() {
  const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_${crypto.randomUUID().replace(/-/g, "")}" Version="2.0" IssueInstant="${new Date().toISOString()}" Destination="${SSO}" AssertionConsumerServiceURL="https://bench.invalid/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>${SP}</saml:Issuer></samlp:AuthnRequest>`;
  return `${SSO}?${new URLSearchParams({ SAMLRequest: deflateRawSync(Buffer.from(xml)).toString("base64"), RelayState: "bench" })}`;
}

/** The SAML status in an auto-POST page, or why there's none. */
async function samlStatus(res) {
  const body = await res.text();
  const m = /name="SAMLResponse" value="([^"]+)"/.exec(body);
  if (!m) return `no SAMLResponse (${res.status})`;
  const s = /StatusCode Value="urn:oasis:names:tc:SAML:2\.0:status:([A-Za-z]+)"/.exec(Buffer.from(m[1], "base64").toString());
  return s?.[1] ?? "no status";
}

const jar = (cookies, res) => {
  for (const c of res.headers.getSetCookie()) {
    const [pair] = c.split(";");
    const at = pair.indexOf("=");
    cookies.set(pair.slice(0, at), pair.slice(at + 1));
  }
};
const cookieHeader = (cookies) => [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");

let next = 0;
const user = () => state.users[next++ % state.users.length];

/** One unit of work; resolves to "ok" or an error label. */
const work = {
  metadata: async () => {
    const r = await fetch(`${base}/api/auth/saml2/idp/metadata`);
    await r.arrayBuffer();
    return r.ok ? "ok" : `HTTP ${r.status}`;
  },
  session: async () => {
    const r = await fetch(`${base}/api/auth/get-session`, { headers: { cookie: user().cookie } });
    const body = await r.json().catch(() => null);
    return r.ok && body?.user ? "ok" : `HTTP ${r.status}`;
  },
  sso: async () => {
    const r = await fetch(ssoUrl(), { headers: { cookie: user().cookie }, redirect: "manual" });
    if (r.status !== 200) return `HTTP ${r.status}`;
    const s = await samlStatus(r);
    return s === "Success" ? "ok" : s;
  },
  login: async () => {
    const u = user();
    const cookies = new Map();
    const parked = await fetch(ssoUrl(), { redirect: "manual" });
    await parked.arrayBuffer();
    jar(cookies, parked);
    const loc = parked.headers.get("location");
    if (parked.status !== 302 || !loc) return `park HTTP ${parked.status}`;
    const resume = new URL(loc, base).searchParams.get("callbackURL");
    const signIn = await fetch(`${base}/api/auth/sign-in/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: base, cookie: cookieHeader(cookies) },
      body: JSON.stringify({ email: u.email, password: u.password }),
    });
    await signIn.arrayBuffer();
    if (!signIn.ok) return `sign-in HTTP ${signIn.status}`;
    jar(cookies, signIn);
    const r = await fetch(resume, { headers: { cookie: cookieHeader(cookies) }, redirect: "manual" });
    if (r.status !== 200) return `resume HTTP ${r.status}`;
    const s = await samlStatus(r);
    return s === "Success" ? "ok" : s;
  },
}[scenario];
if (!work) throw new Error(`unknown scenario ${scenario}`);

const pct = (sorted, p) => (sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))] : NaN);

async function level(concurrency) {
  const latencies = [];
  const errors = new Map();
  const warmEnd = Date.now() + WARMUP_MS;
  const end = warmEnd + seconds * 1000;
  const loop = async () => {
    while (Date.now() < end) {
      const t0 = performance.now();
      let outcome;
      try {
        outcome = await work();
      } catch (e) {
        outcome = `network: ${e.cause?.code ?? e.message}`;
      }
      if (Date.now() < warmEnd) continue;
      if (outcome === "ok") latencies.push(performance.now() - t0);
      else errors.set(outcome, (errors.get(outcome) ?? 0) + 1);
    }
  };
  await Promise.all(Array.from({ length: concurrency }, loop));
  latencies.sort((a, b) => a - b);
  const errorCount = [...errors.values()].reduce((a, b) => a + b, 0);
  return {
    concurrency,
    ok: latencies.length,
    errors: errorCount,
    errorKinds: Object.fromEntries(errors),
    perSecond: +(latencies.length / seconds).toFixed(1),
    p50: +pct(latencies, 50).toFixed(0),
    p95: +pct(latencies, 95).toFixed(0),
    p99: +pct(latencies, 99).toFixed(0),
    max: +(latencies.at(-1) ?? NaN).toFixed(0),
  };
}

const results = [];
console.log(`${scenario} against ${base}: ${seconds} s per level after a ${WARMUP_MS / 1000} s warm-up`);
console.log("| concurrency | ok | errors | per second | p50 ms | p95 ms | p99 ms | max ms |\n|---:|---:|---:|---:|---:|---:|---:|---:|");
for (const c of levels) {
  const r = await level(c);
  results.push(r);
  console.log(`| ${r.concurrency} | ${r.ok} | ${r.errors}${r.errors ? ` ${JSON.stringify(r.errorKinds)}` : ""} | ${r.perSecond} | ${r.p50} | ${r.p95} | ${r.p99} | ${r.max} |`);
}
const file = join(here, `.state/${scenario}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
writeFileSync(file, JSON.stringify({ scenario, base, seconds, warmupMs: WARMUP_MS, at: new Date().toISOString(), node: process.version, results }, null, 2));
console.log(`saved ${file}`);
