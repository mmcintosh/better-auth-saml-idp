// Captures the WASM bytes libxml2-wasm embeds, and emits a workerd-loadable copy of its glue.
import { readFileSync, writeFileSync } from "node:fs";
const dir = process.argv[2];
let bytes;
const orig = WebAssembly.instantiate;
WebAssembly.instantiate = (b, i) => { bytes ??= new Uint8Array(b); return orig(b, i); };
await import("libxml2-wasm");
writeFileSync(`${dir}/libxml2.wasm`, bytes);

// 1. Drop the embedded blob from the emscripten glue (unused once instantiateWasm is provided).
let raw = readFileSync(`${dir}/libxml2raw.mjs`, "latin1");
const start = raw.indexOf("pa??=ea('");
const end = raw.indexOf("');return a((await sa(c)).instance)");
if (start < 0 || end < 0) throw new Error("glue layout changed; refusing to patch");
raw = raw.slice(0, start) + "pa??=ea(''" + raw.slice(end + 1);
writeFileSync(`${dir}/libxml2raw.mjs`, raw, "latin1");

// 2. Pass a precompiled module through emscripten's instantiateWasm hook.
let glue = readFileSync(`${dir}/libxml2.mjs`, "utf8");
const needle = "const libxml2 = await moduleLoader();";
if (!glue.includes(needle)) throw new Error("libxml2.mjs layout changed; refusing to patch");
glue = glue.replace(needle, `import wasmModule from './libxml2.wasm';
const libxml2 = await moduleLoader({
    instantiateWasm(imports, done) {
        WebAssembly.instantiate(wasmModule, imports).then((instance) => done(instance, wasmModule));
        return {};
    },
});`);
writeFileSync(`${dir}/libxml2.mjs`, glue);
console.log("wasm bytes:", bytes.length);
