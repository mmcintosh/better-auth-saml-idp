import { createAuthClient } from "better-auth/react";
import { anonymousClient, jwtClient, organizationClient } from "better-auth/client/plugins";
import { createChardbReactClient } from "@chardb/react";
import { useCallback, useEffect, useState } from "react";

export const db = createChardbReactClient({
  url: window.location.origin,
  ownership: "organization",
  auth: ({ baseURL }) => createAuthClient({
    baseURL,
    plugins: [anonymousClient(), organizationClient(), jwtClient()],
  }),
});

/** A JSON call; throws the API's message (and its issues) on failure. */
export async function call<T = any>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, body === undefined
    ? { credentials: "include" }
    : { method: "POST", credentials: "include", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const json = (await res.json().catch(() => ({}))) as { message?: string; error?: string; issues?: string[] };
  if (!res.ok) throw new Error([json.message || json.error || `HTTP ${res.status}`, ...(json.issues ?? [])].join(" · "));
  return json as T;
}

/** The plugin's registry and tenant API. */
export const saml = (path: string, body?: unknown) => call(`/api/auth/saml-idp${path}`, body);

export interface Me {
  readonly user: { id: string; email: string; emailVerified: boolean } | null;
  readonly samlAdmin: boolean;
  readonly devMailbox: boolean;
  readonly idp: string;
}

/** Load `fn` now and on `reload()`; errors are kept, not thrown. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [state, setState] = useState<{ data?: T; error?: string; loading: boolean }>({ loading: true });
  const load = useCallback(() => {
    setState((s) => ({ ...s, loading: true }));
    fn().then((data) => setState({ data, loading: false }), (e: Error) => setState({ error: e.message, loading: false }));
    // biome-ignore lint/correctness/useExhaustiveDependencies: the caller names the dependencies
  }, deps);
  useEffect(load, [load]);
  return { ...state, reload: load };
}

/** Run an action, reporting its outcome through `notify`. */
export function useAction(notify: (text: string, kind?: "ok" | "err") => void) {
  const [busy, setBusy] = useState(false);
  const run = async (fn: () => Promise<unknown>, done?: string) => {
    setBusy(true);
    try {
      await fn();
      if (done) notify(done);
      return true;
    } catch (e) {
      notify((e as Error).message, "err");
      return false;
    } finally {
      setBusy(false);
    }
  };
  return { busy, run };
}

export const shortDate = (v: string | number | Date) => new Date(v).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
