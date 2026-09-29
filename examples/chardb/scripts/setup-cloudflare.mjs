import { mkdtemp, open, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const workerName = "chardb-saml-idp";
const filesBucket = "chardb-saml-idp-files";
const deploymentId = "chardb.app.v1/a90a2d91-d596-4594-88b2-ba56dcb8c345";
const ownershipKey = "_chardb/control/ownership.json";
const ownershipMarker = JSON.stringify({
  format: "chardb.r2-ownership.v1",
  deploymentId,
  workerName,
  filesBucket,
}) + "\n";
const wranglerModule = fileURLToPath(import.meta.resolve("wrangler"));
const chardbModule = join(dirname(fileURLToPath(import.meta.resolve("@chardb/core"))), "cli", "bin.mjs");
// This example lives inside another project, whose own wrangler.jsonc Wrangler would find first:
// name this project's config explicitly.
const wrangler = (...args) => [process.execPath, wranglerModule, ...args, "--config", "wrangler.toml"];
const chardb = (...args) => [process.execPath, chardbModule, ...args];

function childEnvironment() {
  const env = { ...process.env };
  delete env.CHARDB_URL;
  delete env.CHARDB_ADMIN_TOKEN;
  delete env.BETTER_AUTH_SECRET;
  return env;
}

async function command(args, { capture = false } = {}) {
  const child = Bun.spawn(args, {
    env: childEnvironment(),
    stdin: "inherit",
    stdout: capture ? "pipe" : "inherit",
    stderr: capture ? "pipe" : "inherit",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    capture ? new Response(child.stdout).text() : "",
    capture ? new Response(child.stderr).text() : "",
  ]);
  return { exitCode, stdout, stderr };
}

function detail(result) {
  return (result.stderr || result.stdout).trim().slice(0, 2_000);
}

export function isMissingBucket(result) {
  return result.exitCode !== 0 && /The specified bucket does not exist\./i.test(result.stderr + "\n" + result.stdout);
}

export function isMissingObject(result) {
  return result.exitCode !== 0 && /The specified (?:key|object) does not exist.|object not found/i.test(
    result.stderr + "\n" + result.stdout,
  );
}

export function parseSetupArguments(args) {
  const adoptExistingBucket = args.includes("--adopt-existing-bucket");
  if (args.some(arg => arg !== "--adopt-existing-bucket") || args.length !== (adoptExistingBucket ? 1 : 0)) {
    throw new Error("usage: bun scripts/setup-cloudflare.mjs [--adopt-existing-bucket]");
  }
  return { adoptExistingBucket };
}

function parseTomlString(line, key) {
  const match = line.match(new RegExp("^" + key + "\\s*=\\s*(\"(?:[^\"\\\\]|\\\\.)*\")\\s*(?:#.*)?$"));
  if (!match) return undefined;
  try {
    return JSON.parse(match[1]);
  } catch {
    throw new Error("wrangler.toml contains an invalid quoted " + key);
  }
}

export function configuredIdentity(raw) {
  let section = "root";
  let name;
  const buckets = [];
  let bucket = null;
  const finishBucket = () => {
    if (bucket) buckets.push(bucket);
    bucket = null;
  };
  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    if (/^\[\[r2_buckets\]\]\s*(?:#.*)?$/.test(line)) {
      finishBucket();
      section = "r2";
      bucket = {};
      continue;
    }
    if (/^\[/.test(line)) {
      finishBucket();
      section = "other";
      continue;
    }
    if (section === "root") name ??= parseTomlString(line, "name");
    if (section === "r2") {
      bucket.binding ??= parseTomlString(line, "binding");
      bucket.bucketName ??= parseTomlString(line, "bucket_name");
    }
  }
  finishBucket();
  const files = buckets.filter(candidate => candidate.binding === "CDB_FILES");
  if (typeof name !== "string" || files.length !== 1 || typeof files[0].bucketName !== "string") {
    throw new Error("wrangler.toml must contain one Worker name and one CDB_FILES R2 bucket");
  }
  return { workerName: name, filesBucket: files[0].bucketName };
}

export function assertGeneratedConfig(raw) {
  const configured = configuredIdentity(raw);
  if (configured.workerName !== workerName || configured.filesBucket !== filesBucket) {
    throw new Error("wrangler.toml drifted from the generated deployment contract; regenerate or review the scripts");
  }
  return configured;
}

async function requireCurrentConfig() {
  const path = join(process.cwd(), "wrangler.toml");
  if (!(await Bun.file(path).exists())) throw new Error("generated Cloudflare commands require wrangler.toml");
  assertGeneratedConfig(await Bun.file(path).text());
}

async function probeBucket(run = command) {
  const result = await run(wrangler("r2", "bucket", "info", filesBucket, "--json"), { capture: true });
  if (result.exitCode !== 0) return { result };
  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    throw new Error("Wrangler returned invalid JSON while inspecting R2 bucket " + filesBucket);
  }
  if (!parsed || parsed.name !== filesBucket) {
    throw new Error("Wrangler inspected a different R2 bucket than " + filesBucket);
  }
  return { result, parsed };
}

async function withTemporaryDirectory(callback) {
  const directory = await mkdtemp(join(tmpdir(), "chardb-r2-ownership-"));
  try {
    return await callback(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function readOwnershipMarker(run = command) {
  return withTemporaryDirectory(async directory => {
    const path = join(directory, "ownership.json");
    const result = await run(wrangler("r2", "object", "get", filesBucket + "/" + ownershipKey, "--file", path), {
      capture: true,
    });
    if (isMissingObject(result)) return null;
    if (result.exitCode !== 0) {
      throw new Error("could not inspect the CharDB R2 ownership marker: " + detail(result));
    }
    if (!(await Bun.file(path).exists())) {
      throw new Error("Wrangler did not write the CharDB R2 ownership marker");
    }
    return Bun.file(path).text();
  });
}

async function writeOwnershipMarker(run = command) {
  await withTemporaryDirectory(async directory => {
    const path = join(directory, "ownership.json");
    const file = await open(path, "wx", 0o600);
    try {
      await file.writeFile(ownershipMarker);
    } finally {
      await file.close();
    }
    const result = await run(wrangler("r2", "object", "put", filesBucket + "/" + ownershipKey, "--file", path), {
      capture: true,
    });
    if (result.exitCode !== 0) {
      throw new Error("could not write the CharDB R2 ownership marker: " + detail(result));
    }
  });
}

function assertOwnershipMarker(marker) {
  if (marker !== ownershipMarker) {
    throw new Error(
      "R2 bucket " + filesBucket + " has a different CharDB ownership marker; refusing to modify it",
    );
  }
}

export async function setupFilesBucket({ adoptExistingBucket = false, run = command } = {}) {
  const before = await probeBucket(run);
  let createdBucket = false;
  try {
    if (!before.parsed) {
      if (!isMissingBucket(before.result)) {
        throw new Error("could not inspect R2 bucket " + filesBucket + ": " + detail(before.result));
      }
      const created = await run(wrangler("r2", "bucket", "create", filesBucket));
      if (created.exitCode !== 0) throw new Error("could not create R2 bucket " + filesBucket);
      createdBucket = true;
      const after = await probeBucket(run);
      if (!after.parsed) throw new Error("R2 bucket " + filesBucket + " was not visible after creation");
    }
    const marker = await readOwnershipMarker(run);
    if (marker === null) {
      if (!createdBucket && !adoptExistingBucket) {
        throw new Error(
          "R2 bucket " + filesBucket + " already exists without CharDB ownership; " +
          "review it, then rerun with --adopt-existing-bucket to adopt it",
        );
      }
      await writeOwnershipMarker(run);
      assertOwnershipMarker(await readOwnershipMarker(run));
    } else {
      assertOwnershipMarker(marker);
    }
  } catch (error) {
    if (createdBucket) {
      const rollback = await run(wrangler("r2", "bucket", "delete", filesBucket), { capture: true });
      if (rollback.exitCode !== 0) {
        throw new AggregateError([error, new Error("could not roll back the new R2 bucket: " + detail(rollback))]);
      }
    }
    throw error;
}
}

async function main() {
  const { adoptExistingBucket } = parseSetupArguments(process.argv.slice(2));
  for (const path of [wranglerModule, chardbModule]) {
    if (!(await Bun.file(path).exists())) throw new Error("missing local dependencies; run bun install first");
  }
  const doctor = await command(chardb("doctor"));
  if (doctor.exitCode !== 0) throw new Error("chardb doctor rejected wrangler.toml");
  await requireCurrentConfig();

  await setupFilesBucket({ adoptExistingBucket });
  console.log("Cloudflare R2 bucket " + filesBucket + " is owned by " + workerName);
}

if (import.meta.main) await main();
