declare namespace Cloudflare {
  interface Env {
    CDB_CATALOG: DurableObjectNamespace;
    CDB_SHARD: DurableObjectNamespace;
    CDB_GATEWAY: DurableObjectNamespace;
    CDB_RESHARD: DurableObjectNamespace;
    CDB_FILES: R2Bucket;
    CDB_ADMIN_TOKEN: string;
    BETTER_AUTH_SECRET: string;
    BETTER_AUTH_URL: string;
    SAML_IDP_PRIVATE_KEY: string;
    SAML_IDP_CERT: string;
    SAML_REGISTRY_ADMINS: string;
    DEV_MAILBOX: string;
  }

  interface GlobalProps {
    mainModule: typeof import("../src/worker.ts");
    durableNamespaces: "Catalog" | "Cdb" | "Gateway" | "Resharder";
  }
}
