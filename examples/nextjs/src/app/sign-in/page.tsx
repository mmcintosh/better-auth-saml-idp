"use client";

// The IdP's login page (samlIdp's `loginPage`). The plugin sends users here with:
//  - callbackURL: its absolute /saml2/idp/resume URL, to follow after signing in;
//  - prompt=login: the SP demanded a fresh sign-in (ForceAuthn), so ask even with a session.
// No acr_values: this example has no step-up levels (authnContext.levels), so the IdP never sends
// it; an SP asking for a class the example can't deliver is answered by the IdP itself. See
// docs/guide/flows.md and docs/guide/getting-started.md (step 5).
import { useSearchParams } from "next/navigation";
import { type FormEvent, Suspense, useEffect, useRef, useState } from "react";
import { authClient } from "../../lib/auth-client";

/** callbackURL if it points back to this origin, otherwise "/" (never an open redirect). */
function safeCallback(raw: string | null): string {
  if (!raw) return "/";
  try {
    const url = new URL(raw, window.location.origin);
    return url.origin === window.location.origin ? url.href : "/";
  } catch {
    return "/";
  }
}

function SignIn() {
  const params = useSearchParams();
  const promptLogin = params.get("prompt") === "login";
  const { data: session, isPending } = authClient.useSession();
  const [mode, setMode] = useState<"sign-in" | "sign-up">("sign-in");
  const [error, setError] = useState("");
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);

  // Already signed in: continue straight away, unless the SP demanded a fresh sign-in. Decided
  // once, on the first session answer: after signing in here, onSubmit navigates (the resume
  // link is single-use, so it must be followed once).
  const decided = useRef(false);
  useEffect(() => {
    if (isPending || decided.current) return;
    decided.current = true;
    if (session && !promptLogin) window.location.assign(safeCallback(params.get("callbackURL")));
  }, [isPending, session, promptLogin, params]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setBusy(true);
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email"));
    const password = String(form.get("password"));
    const callbackURL = safeCallback(params.get("callbackURL"));
    if (mode === "sign-up") {
      // The verification link returns to callbackURL, signed in (autoSignInAfterVerification).
      const name = String(form.get("name") || email);
      const { error } = await authClient.signUp.email({ email, password, name, callbackURL });
      setBusy(false);
      if (error) setError(error.message ?? `Sign-up failed (${error.status})`);
      else setSent(true);
      return;
    }
    // No callbackURL here: the client would follow it itself. This page navigates once, below.
    const { error } = await authClient.signIn.email({ email, password });
    if (error) {
      setBusy(false);
      setError(error.message ?? `Sign-in failed (${error.status})`);
      return;
    }
    window.location.assign(callbackURL);
  }

  if (isPending || (session && !promptLogin)) return <p>Loading…</p>;
  if (sent) return <p>Check your email for a verification link to finish signing in. In development, the link is printed in the terminal running <code>next dev</code>.</p>;

  return (
    <>
      <h1>{mode === "sign-in" ? "Sign in" : "Create an account"}</h1>
      {promptLogin && session && (
        <p className="note">The application asked you to sign in again{session.user.email ? ` (signed in as ${session.user.email})` : ""}.</p>
      )}
      <form onSubmit={onSubmit}>
        <label htmlFor="email">Email</label>
        <input id="email" name="email" type="email" autoComplete="username" required />
        <label htmlFor="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete={mode === "sign-in" ? "current-password" : "new-password"}
          minLength={8}
          required
        />
        {mode === "sign-up" && (
          <>
            <label htmlFor="name">Name</label>
            <input id="name" name="name" autoComplete="name" />
          </>
        )}
        <button type="submit" disabled={busy}>
          {mode === "sign-in" ? "Sign in" : "Create account"}
        </button>{" "}
        <button type="button" onClick={() => setMode(mode === "sign-in" ? "sign-up" : "sign-in")}>
          {mode === "sign-in" ? "Create an account instead" : "I already have an account"}
        </button>
        <p className="error" role="alert">
          {error}
        </p>
      </form>
    </>
  );
}

export default function SignInPage() {
  // useSearchParams needs a Suspense boundary for `next build`.
  return (
    <Suspense fallback={<p>Loading…</p>}>
      <SignIn />
    </Suspense>
  );
}
