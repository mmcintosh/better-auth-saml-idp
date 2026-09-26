import type { BetterAuthClientPlugin } from "better-auth/client";
import type { samlIdp } from "./index";

type ClientOptions = { baseURL?: string | undefined; basePath?: string | undefined } | undefined;

/** `s` without trailing slashes (a loop: `/\/+$/` is quadratic on many slashes). */
function trimSlashes(s: string): string {
  let end = s.length;
  while (end > 0 && s[end - 1] === "/") end--;
  return s.slice(0, end);
}

/** The Better Auth endpoint URL for `path`, from the client's baseURL/basePath. */
function authUrl(options: ClientOptions, path: string): string {
  const base = options?.baseURL ?? (typeof window !== "undefined" ? window.location.origin : "");
  if (!base) throw new Error("samlIdpClient: set baseURL on createAuthClient outside the browser");
  const u = new URL(base);
  // A baseURL with a path is the auth base itself (Better Auth's convention); else basePath.
  const basePath = trimSlashes(u.pathname && u.pathname !== "/" ? u.pathname : (options?.basePath ?? "/api/auth"));
  return `${u.origin}${basePath}${path}`;
}

function navigate(url: string): void {
  if (typeof window === "undefined") throw new Error("samlIdpClient: navigation helpers need a browser");
  window.location.assign(url);
}

/**
 * Client plugin. Registry calls are typed from the server plugin, e.g.
 * `authClient.samlIdp.serviceProviders.create({ serviceProvider })`. The SAML flows themselves
 * are browser navigations, so these helpers build (and follow) their URLs:
 *
 *   authClient.samlIdp.signOutEverywhere({ returnTo: "/" }); // Single Logout, every SP
 *   authClient.samlIdp.launch("hubspot");                    // IdP-initiated SSO (allowIdpInitiated)
 */
export const samlIdpClient = () =>
  ({
    id: "saml-idp",
    $InferServerPlugin: {} as ReturnType<typeof samlIdp>,
    getActions: (_$fetch, _$store, options) => ({
      samlIdp: {
        /** URL of IdP-initiated logout (`singleLogout.enabled`): every SP, then `returnTo`. */
        logoutUrl: (o: { returnTo?: string } = {}) =>
          authUrl(options, `/saml2/idp/logout${o.returnTo !== undefined ? `?returnTo=${encodeURIComponent(o.returnTo)}` : ""}`),
        /** Sign out of the IdP and every SP that got an assertion in this session. */
        signOutEverywhere: (o: { returnTo?: string } = {}) =>
          navigate(authUrl(options, `/saml2/idp/logout${o.returnTo !== undefined ? `?returnTo=${encodeURIComponent(o.returnTo)}` : ""}`)),
        /** URL that signs the user in to an SP from the IdP (the SP needs `allowIdpInitiated`). */
        launchUrl: (sp: string, o: { relayState?: string } = {}) =>
          authUrl(options, `/saml2/idp/init?sp=${encodeURIComponent(sp)}${o.relayState !== undefined ? `&RelayState=${encodeURIComponent(o.relayState)}` : ""}`),
        /** Go to an SP, signed in (IdP-initiated SSO). */
        launch: (sp: string, o: { relayState?: string } = {}) =>
          navigate(authUrl(options, `/saml2/idp/init?sp=${encodeURIComponent(sp)}${o.relayState !== undefined ? `&RelayState=${encodeURIComponent(o.relayState)}` : ""}`)),
      },
    }),
  }) satisfies BetterAuthClientPlugin;
