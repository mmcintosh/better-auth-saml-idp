// The sidebar's "signed in as", an island of its own: the rest of the sidebar is static HTML.
import { call, db, type Me, useLoad } from "./lib.ts";

export function WhoAmI() {
  const session = db.auth.useSession();
  const me = useLoad(() => call<Me>("/api/demo/me"), [session.data?.user.id]);
  const user = me.data?.user;
  if (!user) return null;
  return (
    <div className="whoami">
      <div className="muted small">Signed in as</div>
      <div className="email">{user.email}</div>
      {me.data?.samlAdmin ? <span className="pill info">SAML admin</span> : <span className="pill neutral">user</span>}
      <button type="button" className="ghost small" onClick={() => void db.auth.signOut().then(() => window.location.assign("/"))}>Sign out</button>
    </div>
  );
}
