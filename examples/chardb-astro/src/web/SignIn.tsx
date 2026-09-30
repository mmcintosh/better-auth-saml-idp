import { type FormEvent, useState } from "react";
import { db, type Me } from "./lib.ts";

/** Email sign-in and sign-up. The IdP only asserts verified addresses, so sign-up sends a link. */
export function SignIn({ me, onSignedIn }: { me: Me | undefined; onSignedIn: () => void }) {
  const [mode, setMode] = useState<"in" | "up">("in");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [mailboxLink, setMailboxLink] = useState<string | null>(null);
  const invited = new URLSearchParams(window.location.search).has("invitation");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = mode === "in"
        ? await db.auth.signIn.email({ email, password })
        : await db.auth.signUp.email({ email, password, name: name || email, callbackURL: window.location.href });
      if (result.error) throw new Error(result.error.message ?? "failed");
      if (mode === "up") {
        setSent(true);
        if (me?.devMailbox) void checkMailbox();
      } else onSignedIn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function checkMailbox() {
    const res = await fetch(`/dev/mailbox?email=${encodeURIComponent(email)}`);
    const json = (await res.json().catch(() => ({}))) as { messages?: { subject: string; link: string }[] };
    setMailboxLink(json.messages?.filter((m) => m.subject === "Verify your email").at(-1)?.link ?? null);
  }

  return (
    <main className="auth">
      <div className="auth-card">
        <div className="brand">
          <span className="logo">◆</span>
          <div>
            <strong>CharDB SAML IdP</strong>
            <small className="muted">better-auth-saml-idp on CharDB · experimental</small>
          </div>
        </div>
        {sent ? (
          <div className="stack">
            <h1>Check your email</h1>
            <p className="muted">A verification link was sent to <b>{email}</b>. Opening it signs you in.</p>
            {me?.devMailbox ? (
              <div className="notice">
                <b>Development mailbox.</b> No email is sent locally; the link is kept by the Worker.
                {mailboxLink ? <a className="button" href={mailboxLink}>Open the verification link</a> : <button type="button" onClick={() => void checkMailbox()}>Look for the link</button>}
              </div>
            ) : null}
            <button type="button" className="ghost" onClick={() => { setSent(false); setMode("in"); }}>Back to sign in</button>
          </div>
        ) : (
          <form className="stack" onSubmit={submit}>
            <h1>{mode === "in" ? "Sign in" : "Create an account"}</h1>
            {invited ? <p className="notice">You've been invited to an organization. Sign in, or create an account with the invited address, to accept.</p> : null}
            {mode === "up" ? <input aria-label="Name" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} /> : null}
            <input aria-label="Email" type="email" required placeholder="you@example.com" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
            <input aria-label="Password" type="password" required minLength={8} placeholder="Password (8 or more characters)" autoComplete={mode === "in" ? "current-password" : "new-password"} value={password} onChange={(e) => setPassword(e.target.value)} />
            <button type="submit" disabled={busy}>{busy ? "…" : mode === "in" ? "Sign in" : "Create account"}</button>
            {error ? <p className="error">{error}</p> : null}
            <button type="button" className="ghost" onClick={() => setMode(mode === "in" ? "up" : "in")}>
              {mode === "in" ? "No account? Create one" : "I already have an account"}
            </button>
            {me?.devMailbox ? <p className="muted small">Locally, <code>admin@example.test</code> is the host's SAML admin (<code>SAML_REGISTRY_ADMINS</code>).</p> : null}
          </form>
        )}
      </div>
    </main>
  );
}
