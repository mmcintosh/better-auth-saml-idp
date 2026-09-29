import { anonymous } from "better-auth/plugins/anonymous";
import { jwt } from "better-auth/plugins/jwt";
import { organization } from "better-auth/plugins/organization";
import { defineAuth } from "@chardb/core/server";
import { samlIdpPlugin } from "./saml.ts";

function trustedDevelopmentOrigins(request?: Request): string[] {
  if (!request) return [];
  try {
    const worker = new URL(request.url);
    const candidate = new URL(request.headers.get("origin") ?? request.headers.get("referer") ?? "");
    const loopback = (hostname: string) =>
      hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
    if (worker.protocol !== "http:" || !loopback(worker.hostname)) return [];
    if (candidate.protocol !== "http:" || !loopback(candidate.hostname)) return [];
    return [candidate.origin];
  } catch {
    return [];
  }
}

/** DEV_MAILBOX: the latest verification link per email address (per isolate), served at /dev/mailbox. */
export const devMailbox = new Map<string, string>();

export const auth = defineAuth({
  appName: "chardb-saml-idp",
  // The IdP only asserts verified email addresses, so sign-in is by email, verified.
  emailAndPassword: { enabled: true, requireEmailVerification: true },
  emailVerification: {
    sendOnSignUp: true,
    autoSignInAfterVerification: true,
    sendVerificationEmail: async ({ user, url }) => {
      // DEVELOPMENT ONLY: keep the link instead of sending it. Never set DEV_MAILBOX in production.
      if (process.env.DEV_MAILBOX === "true") {
        devMailbox.set(user.email, url);
        return;
      }
      // Production: send `url` to `user.email` with your email provider here.
      console.error("[example] email sending is not configured; set up sendVerificationEmail");
    },
  },
  plugins: [anonymous(), organization(), jwt(), samlIdpPlugin()],
  trustedOrigins: trustedDevelopmentOrigins,
});
