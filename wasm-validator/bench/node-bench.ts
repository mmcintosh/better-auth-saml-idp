// Node timings, same process for both validators. Run from the repo root:
//   wasm-validator/bench/node-bench.sh
import { readFileSync } from "node:fs";
import * as authenio from "@authenio/samlify-node-xmllint";
import { createWasmValidator } from "../src/index";

const x = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_abc123" Version="2.0" IssueInstant="2026-09-24T10:00:00Z"><saml:Issuer>x</saml:Issuer></samlp:AuthnRequest>`;
const ms = (t0: number) => (performance.now() - t0).toFixed(3);

async function bench(name: string, fn: () => Promise<unknown>, warmN: number) {
  let t0 = performance.now();
  const first = await fn();
  const cold = ms(t0);
  for (let i = 0; i < 10; i++) await fn();
  t0 = performance.now();
  for (let i = 0; i < warmN; i++) await fn();
  const warm = ((performance.now() - t0) / warmN).toFixed(3);
  console.log(`${name.padEnd(8)} cold first call ${cold} ms | warm ${warm} ms/validation (n=${warmN}) | result ${JSON.stringify(first)}`);
}

const bytes = readFileSync("wasm-validator/dist/xsd.wasm");
let t0 = performance.now();
const mod = await WebAssembly.compile(bytes);
console.log(`wasm     WebAssembly.compile ${ms(t0)} ms`);
const v = createWasmValidator(mod);
await bench("wasm", () => v.validate(x, "protocol"), 2000);
await bench("xmllint", () => authenio.validate(x).catch(String), 50);
