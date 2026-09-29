import { type FormEvent, useState } from "react";
import type { Notify } from "./App.tsx";
import type { Org } from "./data.ts";
import { db, type Me, useAction, useLoad } from "./lib.ts";
import { Card, Empty, Field, Pill } from "./ui.tsx";

interface Member { id: string; role: string; userId: string; user: { email: string; name: string } }
interface Invitation { id: string; email: string; role: string; status: string; expiresAt: string | Date }

const unwrap = <T,>(r: { data: T | null; error: { message?: string | undefined } | null }) => {
  if (r.error) throw new Error(r.error.message ?? "failed");
  return r.data as T;
};

export function Organizations({ me, notify }: { me: Me; notify: Notify }) {
  const orgs = useLoad(async () => unwrap(await db.auth.organization.list()) as Org[], [me.user?.id]);
  const [selected, setSelected] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const { busy, run } = useAction(notify);
  const current = selected ?? orgs.data?.[0]?.id ?? null;

  async function create(e: FormEvent) {
    e.preventDefault();
    const ok = await run(async () => {
      const org = unwrap(await db.auth.organization.create({ name, slug, keepCurrentActiveOrganization: true })) as Org;
      setSelected(org.id);
    }, `Created ${name}. You're its owner.`);
    if (ok) {
      setName("");
      setSlug("");
      orgs.reload();
    }
  }

  return (
    <>
      <header className="page-head">
        <h1>Organizations</h1>
        <p className="muted">Better Auth's organization plugin, stored in CharDB's Catalog. An organization's owners and admins manage its tenant's SPs; its members can sign in through the tenant.</p>
      </header>
      <div className="split">
        <Card title="Your organizations">
          {orgs.data?.length ? (
            <ul className="list">
              {orgs.data.map((o) => (
                <li key={o.id}>
                  <button type="button" className={`item ${o.id === current ? "active" : ""}`} onClick={() => setSelected(o.id)}>
                    <strong>{o.name}</strong>
                    <small className="muted">{o.slug}</small>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <Empty>{orgs.loading ? "Loading…" : "None yet."}</Empty>
          )}
          <form className="stack top" onSubmit={create}>
            <h3>New organization</h3>
            <input aria-label="Name" placeholder="Acme Corp" value={name} onChange={(e) => { setName(e.target.value); if (!slug || slug === slugify(name)) setSlug(slugify(e.target.value)); }} />
            <input aria-label="Slug" placeholder="acme" value={slug} onChange={(e) => setSlug(e.target.value)} />
            <button type="submit" disabled={busy || !name || !slug}>Create</button>
          </form>
        </Card>
        {current ? <OrganizationDetail key={current} organizationId={current} me={me} notify={notify} onDeleted={() => { setSelected(null); orgs.reload(); }} /> : null}
      </div>
    </>
  );
}

const slugify = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 64);

function OrganizationDetail({ organizationId, me, notify, onDeleted }: { organizationId: string; me: Me; notify: Notify; onDeleted: () => void }) {
  const full = useLoad(async () => unwrap(await db.auth.organization.getFullOrganization({ query: { organizationId } })) as unknown as Org & { members: Member[]; invitations: Invitation[] }, [organizationId]);
  const identity = db.useIdentity();
  const { busy, run } = useAction(notify);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<"member" | "admin">("admin");
  const myRole = full.data?.members.find((m) => m.userId === me.user?.id)?.role ?? "";
  const canManage = /owner|admin/.test(myRole);

  async function invite(e: FormEvent) {
    e.preventDefault();
    if (await run(async () => unwrap(await db.auth.organization.inviteMember({ email, role, organizationId })), me.devMailbox ? `Invited ${email}. Locally the link is at /dev/mailbox?email=${email}.` : `Invited ${email}.`)) {
      setEmail("");
      full.reload();
    }
  }

  if (!full.data) return <Card title="…">{full.error ? <p className="error">{full.error}</p> : <p className="muted">Loading…</p>}</Card>;
  const org = full.data;
  const pending = org.invitations.filter((i) => i.status === "pending");
  return (
    <Card
      title={org.name}
      subtitle={<>slug <code>{org.slug}</code> · your role <Pill tone="info">{myRole || "none"}</Pill></>}
      actions={
        <>
          <button type="button" className="ghost" disabled={identity.organizationId === org.id} onClick={() => void run(async () => unwrap(await db.auth.organization.setActive({ organizationId: org.id })), `${org.name} is your active organization.`)}>
            {identity.organizationId === org.id ? "Active" : "Make active"}
          </button>
          {myRole === "owner" ? (
            <button type="button" className="danger" disabled={busy} onClick={() => confirm(`Delete ${org.name}? Its tenant, if any, is switched off.`) && void run(async () => { unwrap(await db.auth.organization.delete({ organizationId: org.id })); onDeleted(); }, `Deleted ${org.name}.`)}>Delete</button>
          ) : null}
        </>
      }
    >
      <h3>Members</h3>
      <table className="table">
        <thead><tr><th>Email</th><th>Role</th><th /></tr></thead>
        <tbody>
          {org.members.map((m) => (
            <tr key={m.id}>
              <td>{m.user.email}{m.userId === me.user?.id ? <span className="muted"> (you)</span> : null}</td>
              <td>
                {canManage && m.role !== "owner" ? (
                  <select value={m.role} disabled={busy} onChange={(e) => void run(async () => { unwrap(await db.auth.organization.updateMemberRole({ memberId: m.id, role: e.target.value as "member" | "admin", organizationId })); full.reload(); }, `${m.user.email} is now ${e.target.value}.`)}>
                    <option value="member">member</option>
                    <option value="admin">admin</option>
                  </select>
                ) : <Pill tone={m.role === "owner" ? "info" : "neutral"}>{m.role}</Pill>}
              </td>
              <td className="right">
                {canManage && m.role !== "owner" && m.userId !== me.user?.id ? (
                  <button type="button" className="ghost small" disabled={busy} onClick={() => void run(async () => { unwrap(await db.auth.organization.removeMember({ memberIdOrEmail: m.id, organizationId })); full.reload(); }, `Removed ${m.user.email}.`)}>Remove</button>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">With delegation on, owners and <b>admins</b> manage the tenant's SPs; the plugin re-reads membership on every request, so a demotion applies at once.</p>
      {canManage ? (
        <>
          <h3>Invite</h3>
          <form className="inline" onSubmit={invite}>
            <Field label="Email"><input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="colleague@example.com" /></Field>
            <Field label="Role">
              <select value={role} onChange={(e) => setRole(e.target.value as "member" | "admin")}>
                <option value="admin">admin (manages SPs)</option>
                <option value="member">member (signs in)</option>
              </select>
            </Field>
            <button type="submit" disabled={busy || !email}>Invite</button>
          </form>
          {pending.length ? (
            <table className="table">
              <thead><tr><th>Pending invitation</th><th>Role</th><th /></tr></thead>
              <tbody>
                {pending.map((i) => (
                  <tr key={i.id}>
                    <td>{i.email}{me.devMailbox ? <> · <a href={`/dev/mailbox?email=${encodeURIComponent(i.email)}`} target="_blank" rel="noreferrer">dev mailbox</a></> : null}</td>
                    <td>{i.role}</td>
                    <td className="right"><button type="button" className="ghost small" disabled={busy} onClick={() => void run(async () => { unwrap(await db.auth.organization.cancelInvitation({ invitationId: i.id })); full.reload(); }, "Invitation cancelled.")}>Cancel</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
        </>
      ) : null}
    </Card>
  );
}
