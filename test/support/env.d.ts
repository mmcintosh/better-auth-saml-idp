declare namespace Cloudflare {
  interface Env {
    DB: D1Database;
    KV: KVNamespace;
    TEST_MIGRATIONS: import("cloudflare:test").D1Migration[];
  }
}

declare module "*.xml?raw" {
  const content: string;
  export default content;
}
