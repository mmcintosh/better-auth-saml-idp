import { toNextJsHandler } from "better-auth/next-js";
import { getAuth } from "../../../../lib/auth";

// node:sqlite and the plugin's XSD validator need Node. It's the default in Next.js 16; stated
// so that nobody moves this route to the Edge runtime.
export const runtime = "nodejs";

const handler = (request: Request) => getAuth().handler(request);
export const { GET, POST } = toNextJsHandler(handler);
