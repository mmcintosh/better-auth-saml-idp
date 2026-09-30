// The island every page mounts: it loads the session, shows the sign-in form or the page, accepts
// an invitation link (?invitation=…), and shows the page's notices. Pages are real URLs (Astro),
// so moving between them is a plain link.
import { useEffect, useState } from "react";
import { Activity } from "./Activity.tsx";
import { call, db, type Me, useLoad } from "./lib.ts";
import { Organizations } from "./Organizations.tsx";
import { Overview } from "./Overview.tsx";
import { ServiceProviders } from "./ServiceProviders.tsx";
import { SignIn } from "./SignIn.tsx";
import { Tenants } from "./Tenants.tsx";
import { TryIt } from "./TryIt.tsx";

export type Notify = (text: string, kind?: "ok" | "err") => void;
export type Page = "overview" | "organizations" | "tenants" | "sps" | "try" | "activity";
export const PATHS: Record<Page, string> = {
  overview: "/",
  organizations: "/organizations",
  tenants: "/tenants",
  sps: "/service-providers",
  try: "/try",
  activity: "/activity",
};

export function Gate({ page }: { page: Page }) {
  const session = db.auth.useSession();
  const me = useLoad(() => call<Me>("/api/demo/me"), [session.data?.user.id]);
  const [toast, setToast] = useState<{ text: string; kind: "ok" | "err" } | null>(null);
  const notify: Notify = (text, kind = "ok") => {
    setToast({ text, kind });
    setTimeout(() => setToast((t) => (t?.text === text ? null : t)), kind === "err" ? 8000 : 4000);
  };

  const user = me.data?.user;
  useEffect(() => {
    const id = new URLSearchParams(window.location.search).get("invitation");
    if (!id || !user) return;
    void db.auth.organization.acceptInvitation({ invitationId: id }).then((r) => {
      history.replaceState(null, "", window.location.pathname);
      if (r.error) notify(`Invitation: ${r.error.message}`, "err");
      else window.location.assign(`${PATHS.organizations}?accepted=1`);
    });
  }, [user?.id]);
  useEffect(() => {
    if (new URLSearchParams(window.location.search).has("accepted")) notify("Invitation accepted: you're a member of the organization.");
  }, []);

  if (session.isPending || (me.loading && !me.data)) return <p className="muted">Loading…</p>;
  if (!user) return <SignIn me={me.data} onSignedIn={() => me.reload()} />;

  const props = { me: me.data as Me, notify };
  const go = (p: Page) => window.location.assign(PATHS[p]);
  return (
    <db.Provider>
      {page === "overview" ? <Overview {...props} go={go} /> : null}
      {page === "organizations" ? <Organizations {...props} /> : null}
      {page === "tenants" ? <Tenants {...props} /> : null}
      {page === "sps" ? <ServiceProviders {...props} /> : null}
      {page === "try" ? <TryIt {...props} /> : null}
      {page === "activity" ? <Activity {...props} /> : null}
      {toast ? <div className={`toast ${toast.kind}`} role="status">{toast.text}</div> : null}
    </db.Provider>
  );
}
