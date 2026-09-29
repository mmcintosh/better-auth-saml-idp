import { useEffect, useState } from "react";
import { Activity } from "./Activity.tsx";
import { call, db, type Me, useLoad } from "./lib.ts";
import { Organizations } from "./Organizations.tsx";
import { Overview } from "./Overview.tsx";
import { ServiceProviders } from "./ServiceProviders.tsx";
import { SignIn } from "./SignIn.tsx";
import { Tenants } from "./Tenants.tsx";
import { TryIt } from "./TryIt.tsx";

const PAGES = [
  ["overview", "Overview"],
  ["organizations", "Organizations"],
  ["tenants", "Tenants"],
  ["sps", "Service providers"],
  ["try", "Try it"],
  ["activity", "Activity"],
] as const;
type Page = (typeof PAGES)[number][0];
const pageFromHash = (): Page => (PAGES.find(([id]) => `#/${id}` === window.location.hash)?.[0] ?? "overview");

export type Notify = (text: string, kind?: "ok" | "err") => void;

export function App() {
  const session = db.auth.useSession();
  const me = useLoad(() => call<Me>("/api/demo/me"), [session.data?.user.id]);
  const [page, setPage] = useState<Page>(pageFromHash);
  const [toast, setToast] = useState<{ text: string; kind: "ok" | "err" } | null>(null);
  const notify: Notify = (text, kind = "ok") => {
    setToast({ text, kind });
    setTimeout(() => setToast((t) => (t?.text === text ? null : t)), kind === "err" ? 8000 : 4000);
  };

  useEffect(() => {
    const onHash = () => setPage(pageFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // An invitation link (?invitation=…): accept it once signed in.
  const user = me.data?.user;
  useEffect(() => {
    const id = new URLSearchParams(window.location.search).get("invitation");
    if (!id || !user) return;
    void db.auth.organization.acceptInvitation({ invitationId: id }).then((r) => {
      history.replaceState(null, "", `/${window.location.hash || "#/organizations"}`);
      if (r.error) notify(`Invitation: ${r.error.message}`, "err");
      else notify("Invitation accepted: you're a member of the organization.");
    });
  }, [user?.id]);

  if (session.isPending || me.loading && !me.data) return <main className="auth"><p className="muted">Loading…</p></main>;
  if (!user) return <SignIn me={me.data} onSignedIn={() => me.reload()} />;

  const go = (p: Page) => {
    window.location.hash = `#/${p}`;
  };
  const props = { me: me.data as Me, notify };
  return (
    <db.Provider>
      <div className="layout">
        <aside className="sidebar">
          <div className="brand">
            <span className="logo">◆</span>
            <div>
              <strong>CharDB SAML IdP</strong>
              <small className="muted">experimental example</small>
            </div>
          </div>
          <nav>
            {PAGES.map(([id, label]) => (
              <a key={id} href={`#/${id}`} className={page === id ? "active" : undefined}>{label}</a>
            ))}
          </nav>
          <div className="whoami">
            <div className="muted small">Signed in as</div>
            <div className="email">{user.email}</div>
            {me.data?.samlAdmin ? <span className="pill info">SAML admin</span> : <span className="pill neutral">user</span>}
            <button type="button" className="ghost small" onClick={() => void db.auth.signOut().then(() => me.reload())}>Sign out</button>
          </div>
        </aside>
        <main className="content">
          {page === "overview" ? <Overview {...props} go={go} /> : null}
          {page === "organizations" ? <Organizations {...props} /> : null}
          {page === "tenants" ? <Tenants {...props} /> : null}
          {page === "sps" ? <ServiceProviders {...props} /> : null}
          {page === "try" ? <TryIt {...props} /> : null}
          {page === "activity" ? <Activity {...props} /> : null}
        </main>
      </div>
      {toast ? <div className={`toast ${toast.kind}`} role="status">{toast.text}</div> : null}
    </db.Provider>
  );
}
