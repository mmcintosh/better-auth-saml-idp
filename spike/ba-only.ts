import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
export default { fetch: (r: Request) => betterAuth({ database: memoryAdapter({}), secret: "x".repeat(32) }).handler(r) };
