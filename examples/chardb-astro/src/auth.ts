import { anonymous } from "better-auth/plugins/anonymous";
import { jwt } from "better-auth/plugins/jwt";
import { organization } from "better-auth/plugins/organization";
import { defineAuth } from "@chardb/core/server";
import { runInBackground } from "./background.ts";
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

/** DEV_MAILBOX: every link "sent" to an address (per isolate), newest last, served at /dev/mailbox. */
export const devMailbox = new Map<string, { subject: string; link: string }[]>();
const deliver = (email: string, subject: string, link: string) => devMailbox.set(email, [...(devMailbox.get(email) ?? []), { subject, link }].slice(-20));

export const auth = defineAuth({
  appName: "chardb-saml-idp",
  // The same pinned origin as the IdP's entity IDs (src/saml.ts), so Better Auth's own links
  // (email verification, invitations) use it too, even behind the dev server's proxy.
  ...(process.env.BETTER_AUTH_URL ? { baseURL: process.env.BETTER_AUTH_URL } : {}),
  // The IdP only asserts verified email addresses, so sign-in is by email, verified.
  emailAndPassword: { enabled: true, requireEmailVerification: true },
  emailVerification: {
    sendOnSignUp: true,
    autoSignInAfterVerification: true,
    sendVerificationEmail: async ({ user, url }) => {
      // DEVELOPMENT ONLY: keep the link instead of sending it. Never set DEV_MAILBOX in production.
      if (process.env.DEV_MAILBOX === "true") {
        deliver(user.email, "Verify your email", url);
        return;
      }
      // Production: send `url` to `user.email` with your email provider here.
      console.error("[example] email sending is not configured; set up sendVerificationEmail");
    },
  },
  // Keep background work (the SAML plugin's events and audit rows) alive after the response.
  advanced: { backgroundTasks: { handler: runInBackground } },
  plugins: [
    anonymous(),
    organization({
      // Invitations go to the dev mailbox too (/dev/mailbox?email=…); production: send `url` by email.
      sendInvitationEmail: async ({ email, id }) => {
        const url = `${process.env.BETTER_AUTH_URL}/?invitation=${encodeURIComponent(id)}`;
        if (process.env.DEV_MAILBOX === "true") deliver(email, "You're invited to an organization", url);
        else console.error("[example] email sending is not configured; set up sendInvitationEmail");
      },
    }),
    jwt(),
    samlIdpPlugin(),
  ],
  trustedOrigins: trustedDevelopmentOrigins,
});
