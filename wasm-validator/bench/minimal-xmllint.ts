// Size comparison only: the same minimal worker using node-xmllint.
import * as authenio from "@authenio/samlify-node-xmllint";
export default {
  async fetch(req: Request) {
    return new Response(String(await authenio.validate(await req.text()).catch(String)));
  },
};
