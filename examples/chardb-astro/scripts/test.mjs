import { realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const nodeRuntime = Bun.which("node");
if (!nodeRuntime) throw new Error("Cloudflare Vitest requires Node.js on PATH");

// A canonical CLI path prevents Windows drive-letter casing from loading the
// Vitest runner twice.
const project = realpathSync.native(fileURLToPath(new URL("..", import.meta.url)));
const vitestPackage = fileURLToPath(import.meta.resolve("vitest/package.json"));
const vitestCli = realpathSync.native(join(dirname(vitestPackage), "vitest.mjs"));
const child = Bun.spawn(
  [nodeRuntime, vitestCli, "run", "--no-file-parallelism", ...process.argv.slice(2)],
  { cwd: project, stdin: "inherit", stdout: "inherit", stderr: "inherit" },
);
const exitCode = await child.exited;
if (exitCode !== 0) process.exit(exitCode);
