const steps = [
  ["browser", [process.execPath, "run", "build:web"]],
  ["Worker", [process.execPath, "run", "build:worker"]],
];

for (const [label, args] of steps) {
  const child = Bun.spawn(args, { stdin: "inherit", stdout: "inherit", stderr: "inherit" });
  const exitCode = await child.exited;
  if (exitCode !== 0) throw new Error(label + " build exited with status " + exitCode);
}
