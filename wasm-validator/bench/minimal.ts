// Smallest real consumer: used for `wrangler deploy --dry-run` size numbers.
import wasmModule from "../../wasm/xsd.wasm";
import { createWasmValidator } from "../../src/saml/wasm/validator";

const v = createWasmValidator(wasmModule);
export default {
  async fetch(req: Request) {
    return Response.json(await v.validate(await req.text(), "protocol"));
  },
};
