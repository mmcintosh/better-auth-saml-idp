#!/usr/bin/env node
// Entry point for `npx better-auth-saml-idp`. The commands live in main.ts (tested directly).
import { setDefaultAutoSelectFamilyAttemptTimeout } from "node:net";
import { run } from "./main";

// Cloudflare and other dual-stack hosts: Node's 250 ms happy-eyeballs attempt timeout is too
// short on some networks, which shows up as fetch timeouts.
setDefaultAutoSelectFamilyAttemptTimeout(3000);

run(process.argv.slice(2)).then(
  ({ code, stdout, stderr }) => {
    if (stderr) process.stderr.write(stderr);
    if (stdout) process.stdout.write(stdout);
    process.exitCode = code;
  },
  (e) => {
    process.stderr.write(`unexpected error: ${(e as Error).stack ?? e}\n`);
    process.exitCode = 2;
  },
);
