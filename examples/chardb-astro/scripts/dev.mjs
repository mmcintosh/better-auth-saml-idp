import { realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const WINDOWS_WATCHDOG_ARGUMENT = "--chardb-windows-watchdog";
const WINDOWS_UTILITY_TIMEOUT_MS = 5_000;
const WINDOWS_STDIN_CANCEL_TIMEOUT_MS = 1_000;
const READINESS_PROBE_TIMEOUT_MS = 1_000;

async function runWindowsUtility(command) {
  const child = Bun.spawn(command, { stdin: "ignore", stdout: "pipe", stderr: "pipe", windowsHide: true });
  const stdout = new Response(child.stdout).text();
  const stderr = new Response(child.stderr).text();
  const outcome = await Promise.race([
    child.exited.then(exitCode => ({ exitCode })),
    Bun.sleep(WINDOWS_UTILITY_TIMEOUT_MS).then(() => null),
  ]);
  if (!outcome) {
    child.kill("SIGKILL");
    await Promise.race([child.exited, Bun.sleep(1_000)]);
    throw new Error(command[0] + " exceeded " + WINDOWS_UTILITY_TIMEOUT_MS + "ms");
  }
  return { exitCode: outcome.exitCode, stdout: await stdout, stderr: await stderr };
}

async function windowsProcessSnapshot() {
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "@(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, CreationDate) | ConvertTo-Json -Compress",
  ].join("; ");
  const result = await runWindowsUtility([
    "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script,
  ]);
  if (result.exitCode !== 0) {
    throw new Error("PowerShell process enumeration failed with " + result.exitCode + ": " + result.stderr.trim());
  }
  const parsed = JSON.parse(result.stdout || "[]");
  const rows = Array.isArray(parsed) ? parsed : [parsed];
  return rows
    .map(row => ({
      pid: Number(row.ProcessId),
      parentPid: Number(row.ParentProcessId),
      createdAt: typeof row.CreationDate === "string" ? row.CreationDate : "",
    }))
    .filter(row =>
      Number.isSafeInteger(row.pid) && row.pid > 0 &&
      Number.isSafeInteger(row.parentPid) && row.createdAt.length > 0
    );
}

function descendantProcesses(snapshot, rootPid) {
  const children = new Map();
  for (const row of snapshot) {
    const entries = children.get(row.parentPid) ?? [];
    entries.push(row);
    children.set(row.parentPid, entries);
  }
  const descendants = [];
  const pending = [...(children.get(rootPid) ?? [])];
  const seen = new Set([rootPid]);
  while (pending.length > 0) {
    const child = pending.pop();
    if (seen.has(child.pid)) continue;
    seen.add(child.pid);
    descendants.push(child);
    pending.push(...(children.get(child.pid) ?? []));
  }
  return descendants;
}

function descendantsOfProcessIdentity(snapshot, rootPid, rootCreatedAt) {
  const root = snapshot.find(row => row.pid === rootPid);
  if (root && root.createdAt !== rootCreatedAt) return [];
  return descendantProcesses(snapshot, rootPid);
}

async function forceWindowsProcessTree(pid) {
  const result = await runWindowsUtility(["taskkill.exe", "/PID", String(pid), "/T", "/F"]);
  if (result.exitCode !== 0) {
    const snapshot = await windowsProcessSnapshot();
    if (snapshot.some(row => row.pid === pid)) {
      throw new Error("taskkill failed for process " + pid + ": " + result.stderr.trim());
    }
  }
}

async function runWindowsWatchdog(rootPid) {
  const tracked = new Map();
  const initialSnapshot = await windowsProcessSnapshot();
  const root = initialSnapshot.find(row => row.pid === rootPid);
  if (!root) return;
  const rootCreatedAt = root.createdAt;
  const stdinReader = Bun.stdin.stream().getReader();
  let inputClosed = false;
  const observeInput = (async () => {
    try {
      while (!(await stdinReader.read()).done) {
        // The parent writes nothing. EOF means it closed the watchdog pipe.
      }
    } finally {
      inputClosed = true;
    }
  })().catch(() => undefined);
  try {
    while (!inputClosed) {
      const snapshot = await windowsProcessSnapshot();
      const currentRoot = snapshot.find(row => row.pid === rootPid);
      if (!currentRoot) {
        for (const child of descendantsOfProcessIdentity(snapshot, rootPid, rootCreatedAt)) {
          if (child.pid !== process.pid) tracked.set(child.pid, child.createdAt);
        }
        break;
      }
      if (currentRoot.createdAt !== rootCreatedAt) break;
      for (const child of descendantsOfProcessIdentity(snapshot, rootPid, rootCreatedAt)) {
        if (child.pid !== process.pid) tracked.set(child.pid, child.createdAt);
      }
      await Bun.sleep(50);
    }
  } finally {
    await Promise.race([
      stdinReader.cancel().catch(() => undefined),
      Bun.sleep(WINDOWS_STDIN_CANCEL_TIMEOUT_MS),
    ]);
    void observeInput;
  }
  for (let pass = 0; pass < 3; pass++) {
    const snapshot = await windowsProcessSnapshot();
    for (const child of descendantsOfProcessIdentity(snapshot, rootPid, rootCreatedAt)) {
      if (child.pid !== process.pid) tracked.set(child.pid, child.createdAt);
    }
    const live = new Map(snapshot.map(row => [row.pid, row.createdAt]));
    for (const [pid, createdAt] of tracked) {
      if (live.get(pid) === createdAt) await forceWindowsProcessTree(pid);
    }
    await Bun.sleep(25);
  }
}

const watchdogIndex = process.argv.indexOf(WINDOWS_WATCHDOG_ARGUMENT);
if (watchdogIndex !== -1) {
  const rootPid = Number(process.argv[watchdogIndex + 1]);
  if (!Number.isSafeInteger(rootPid) || rootPid <= 0) throw new Error("invalid Windows watchdog parent PID");
  await runWindowsWatchdog(rootPid);
  process.exit(0);
}

function localOrigin(raw, fallback, name) {
  const url = new URL(raw ?? fallback);
  if (
    url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
    url.username || url.password || (url.pathname !== "" && url.pathname !== "/") || url.search || url.hash
  ) {
    throw new Error(name + " must be a loopback HTTP origin");
  }
  return url;
}

function localChildEnvironment(extra = {}) {
  const env = { ...process.env };
  delete env.CHARDB_URL;
  delete env.CHARDB_WEB_URL;
  delete env.CHARDB_ADMIN_TOKEN;
  delete env.BETTER_AUTH_SECRET;
  return { ...env, ...extra };
}

const deploymentId = "chardb.app.v1/a90a2d91-d596-4594-88b2-ba56dcb8c345";
const origin = localOrigin(process.env.CHARDB_DEV_URL, "http://127.0.0.1:8787", "CHARDB_DEV_URL");
const webOrigin = localOrigin(process.env.CHARDB_DEV_WEB_URL, "http://127.0.0.1:4321", "CHARDB_DEV_WEB_URL");
const adminToken = "local-chardb-admin";
const authSecret = "local-chardb-auth-secret-that-is-at-least-32-characters";
const projectRoot = realpathSync.native(fileURLToPath(new URL("..", import.meta.url)));
const persistTo = process.env.CHARDB_DEV_PERSIST_TO ?? join(projectRoot, ".wrangler", "state");
const wranglerModule = join(
  dirname(fileURLToPath(import.meta.resolve("wrangler/package.json"))),
  "bin",
  "wrangler.js",
);
// The web app is Astro (this example's difference from examples/chardb): its dev server replaces Vite's.
const astroModule = realpathSync.native(
  join(dirname(fileURLToPath(import.meta.resolve("astro/package.json"))), "bin", "astro.mjs"),
);
const chardbBin = join(projectRoot, "node_modules", "@chardb", "core", "dist", "cli", "bin.mjs");
const nodeRuntime = Bun.which("node");

for (const path of [wranglerModule, astroModule, chardbBin]) {
  if (!(await Bun.file(path).exists())) throw new Error("missing local dependencies; run bun install first");
}
if (!nodeRuntime) throw new Error("Wrangler and Astro require Node.js on PATH");

const watchdog = process.platform === "win32"
  ? Bun.spawn([process.execPath, fileURLToPath(import.meta.url), WINDOWS_WATCHDOG_ARGUMENT, String(process.pid)], {
      stdin: "pipe", stdout: "inherit", stderr: "inherit", windowsHide: true,
    })
  : undefined;

const worker = Bun.spawn(
  [
    nodeRuntime,
    wranglerModule,
    "dev",
    // This example lives inside another project, whose wrangler.jsonc Wrangler would find first.
    "--config",
    "wrangler.toml",
    "--ip",
    origin.hostname,
    "--port",
    origin.port || "8787",
    "--persist-to",
    persistTo,
    "--var",
    "CDB_ADMIN_TOKEN:" + adminToken,
    "--var",
    "BETTER_AUTH_SECRET:" + authSecret,
  ],
  {
    env: localChildEnvironment(),
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
    detached: process.platform !== "win32",
  },
);

let web;

function processGroupExists(pid) {
  if (process.platform === "win32") return false;
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ESRCH") return false;
    if (error && typeof error === "object" && "code" in error && error.code === "EPERM") return true;
    throw error;
  }
}

async function waitForProcessGroupExit(pid, waitMs) {
  const deadline = performance.now() + waitMs;
  while (processGroupExists(pid) && performance.now() < deadline) await Bun.sleep(10);
  return !processGroupExists(pid);
}

async function terminateProcessGroup(child, signal) {
  if (!child) return;
  if (process.platform === "win32") {
    await forceWindowsProcessTree(child.pid);
    const exited = await Promise.race([child.exited.then(() => true), Bun.sleep(2_000).then(() => false)]);
    if (!exited) throw new Error("process tree " + child.pid + " survived taskkill");
    return;
  }
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ESRCH") return;
    throw error;
  }
  if (await waitForProcessGroupExit(child.pid, 2_000)) {
    await child.exited;
    return;
  }
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch (error) {
    if (!(error && typeof error === "object" && "code" in error && error.code === "ESRCH")) throw error;
  }
  if (!(await waitForProcessGroupExit(child.pid, 2_000))) {
    throw new Error("process group " + child.pid + " survived SIGKILL");
  }
  await child.exited;
}

let termination;
const stop = signal => {
  termination ??= (async () => {
    const results = await Promise.allSettled([
      terminateProcessGroup(web, signal),
      terminateProcessGroup(worker, signal),
    ]);
    if (watchdog) {
      watchdog.stdin.end();
      const exited = await Promise.race([watchdog.exited.then(() => true), Bun.sleep(2_000).then(() => false)]);
      if (!exited) watchdog.kill("SIGKILL");
    }
    const failures = results.filter(result => result.status === "rejected").map(result => result.reason);
    if (failures.length > 0) throw new AggregateError(failures, "generated dev process cleanup failed");
  })();
  void termination.catch(() => {});
  return termination;
};
process.on("SIGINT", () => void stop("SIGINT"));
process.on("SIGTERM", () => void stop("SIGTERM"));

async function waitForWorker() {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (worker.exitCode !== null) throw new Error("Wrangler exited before the health check passed");
    let response;
    try {
      response = await fetch(new URL("/health", origin), {
        signal: AbortSignal.timeout(READINESS_PROBE_TIMEOUT_MS),
      });
    } catch {
      // Wrangler has not opened its local listener yet.
      await Bun.sleep(100);
      continue;
    }
    if (response.ok) {
      let body;
      try {
        body = await response.json();
      } catch {
        // Wrangler can briefly return a successful response while its Worker
        // is still replacing the startup listener. Treat that response as a
        // readiness miss and keep polling within the existing deadline.
        await Bun.sleep(100);
        continue;
      }
      if (
        body && typeof body === "object" && body.ok === true && body.deploymentId === deploymentId &&
        Number.isSafeInteger(body.schemaVersion) && body.schemaVersion >= 1
      ) {
        return body.schemaVersion;
      }
      throw new Error("/health did not identify the expected local Worker " + deploymentId);
    }
    await Bun.sleep(100);
  }
  throw new Error("timed out waiting for " + origin.origin + "/health");
}

async function waitForWeb() {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (!web || web.exitCode !== null) throw new Error("Astro exited before the browser URL was ready");
    const outcome = await Promise.race([
      fetch(webOrigin, { signal: AbortSignal.timeout(READINESS_PROBE_TIMEOUT_MS) })
        .then(response => ({ kind: "response", response }))
        .catch(() => ({ kind: "retry" })),
      web.exited.then(exitCode => ({ kind: "exit", exitCode })),
    ]);
    if (outcome.kind === "exit") {
      throw new Error("Astro exited with status " + outcome.exitCode + " before the browser URL was ready");
    }
    if (outcome.kind === "response" && outcome.response.ok) return;
    await Bun.sleep(100);
  }
  throw new Error("timed out waiting for " + webOrigin.origin);
}

async function assertWebOriginAvailable() {
  try {
    const response = await fetch(webOrigin, {
      signal: AbortSignal.timeout(READINESS_PROBE_TIMEOUT_MS),
    });
    await response.body?.cancel();
  } catch {
    return;
  }
  throw new Error(webOrigin.origin + " is already serving another process");
}

async function applyMigrations(targetVersion) {
  const migration = Bun.spawn(
    [
      process.execPath,
      chardbBin,
      "migrate",
      "--url",
      origin.origin,
      "--id",
      "local-schema-v" + targetVersion,
      "--target",
      String(targetVersion),
      "--concurrency",
      "4",
    ],
    {
      env: localChildEnvironment({ CHARDB_ADMIN_TOKEN: adminToken }),
      stdout: "inherit",
      stderr: "inherit",
    },
  );
  const exitCode = await migration.exited;
  if (exitCode !== 0) {
    throw new Error("chardb migrate exited with status " + exitCode);
  }
}

try {
  const targetVersion = await waitForWorker();
  await applyMigrations(targetVersion);
  await assertWebOriginAvailable();
  web = Bun.spawn(
    // --ignore-lock: this script owns and stops the server, so Astro's lock file isn't needed; it
    // also keeps Astro in the foreground when it detects an AI agent (it backgrounds itself then).
    [nodeRuntime, astroModule, "dev", "--host", webOrigin.hostname, "--port", webOrigin.port || "4321", "--ignore-lock"],
    {
      cwd: projectRoot,
      env: localChildEnvironment({ CHARDB_DEV_URL: origin.origin, CHARDB_DEV_WEB_URL: webOrigin.origin }),
      stdin: "inherit",
      stdout: "inherit",
      stderr: "inherit",
      detached: process.platform !== "win32",
    },
  );
  await waitForWeb();
  console.log("chardb app ready at " + webOrigin.origin + " with schema version " + targetVersion);
  process.exitCode = await Promise.race([worker.exited, web.exited]);
  await stop("SIGTERM");
} catch (error) {
  await stop("SIGTERM");
  await Promise.all([worker.exited, ...(web ? [web.exited] : [])]);
  throw error;
}
