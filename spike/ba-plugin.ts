import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { samlIdp } from "../src/index";
declare const env: any;
export default {
  fetch: (r: Request) =>
    betterAuth({ database: memoryAdapter({}), secret: "x".repeat(32), plugins: [samlIdp(env.CFG)] }).handler(r),
};
