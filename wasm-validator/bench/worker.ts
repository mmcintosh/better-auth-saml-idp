// Benchmark worker: timed from outside with curl (bench/run.sh), because
// in-Worker timers are clamped.
import wasmModule from "../../wasm/xsd.wasm";
import * as authenio from "@authenio/samlify-node-xmllint";
import { createWasmValidator } from "../../src/saml/wasm/validator";

const v = createWasmValidator(wasmModule);
const x = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_abc123" Version="2.0" IssueInstant="2026-09-24T10:00:00Z"><saml:Issuer>x</saml:Issuer></samlp:AuthnRequest>`;

export default {
  async fetch(req: Request) {
    const u = new URL(req.url);
    const n = Number(u.searchParams.get("n") ?? "1");
    if (u.pathname === "/wasm") {
      let r;
      for (let i = 0; i < n; i++) r = await v.validate(x, "protocol");
      return Response.json(r);
    }
    if (u.pathname === "/xmllint") {
      let r;
      for (let i = 0; i < n; i++) r = await authenio.validate(x).catch(String);
      return new Response(String(r));
    }
    return new Response("noop");
  },
};
