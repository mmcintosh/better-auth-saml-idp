// Better Auth's background work (the SAML plugin's events and audit rows) must be kept alive with
// the Worker's waitUntil, or the runtime drops it once the response is sent. src/auth.ts is also
// loaded by CharDB's CLI and Vite plugin, outside the Worker, so it can't import cloudflare:workers
// itself: src/worker.ts hands the real waitUntil in.
let keepAlive: ((promise: Promise<unknown>) => void) | undefined;

export function setWaitUntil(waitUntil: (promise: Promise<unknown>) => void): void {
  keepAlive = waitUntil;
}

export function runInBackground(promise: Promise<unknown>): void {
  if (keepAlive) keepAlive(promise);
  else promise.catch(() => {});
}
