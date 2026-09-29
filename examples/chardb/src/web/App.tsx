import { createAuthClient } from "better-auth/react";
import { type Organization, anonymousClient, jwtClient, organizationClient } from "better-auth/client/plugins";
import { fileRef } from "@chardb/core/files";
import { createChardbReactClient } from "@chardb/react";
import { type FormEvent, useEffect, useState } from "react";
import { uuidv7 } from "uuidv7";
import { postMessage, replaceMessageAttachment } from "../api.ts";
import { listMessages } from "../queries.ts";

const messageAttachment = fileRef("messages", "attachment");

const workerUrl = window.location.origin;
const db = createChardbReactClient({
  url: workerUrl,
  ownership: "organization",
  auth: ({ baseURL }) => createAuthClient({
    baseURL,
    plugins: [anonymousClient(), organizationClient(), jwtClient()],
  }),
});

let anonymousSignInRequest: ReturnType<typeof db.auth.signIn.anonymous> | undefined;

function signInAnonymously() {
  anonymousSignInRequest ??= db.auth.signIn.anonymous().finally(() => {
    anonymousSignInRequest = undefined;
  });
  return anonymousSignInRequest;
}

export function App() {
  const session = db.auth.useSession();
  const [authError, setAuthError] = useState<string | null>(null);

  useEffect(() => {
    if (session.isPending || session.data) return;
    let active = true;
    void (async () => {
      try {
        const result = await signInAnonymously();
        if (active && result.error) setAuthError(result.error.message);
      } catch (cause) {
        if (active) setAuthError(cause instanceof Error ? cause.message : String(cause));
      }
    })();
    return () => {
      active = false;
    };
  }, [session.data, session.isPending]);

  if (!session.data) {
    return <main className="shell">{authError ? "Sign-in failed: " + authError : "Signing in..."}</main>;
  }

  return (
    <db.Provider>
      <Workspace />
    </db.Provider>
  );
}

function Workspace() {
  const identity = db.useIdentity();
  const organizations = db.auth.useListOrganizations();
  const activeOrganizationId = identity.organizationId;
  const userId = identity.user?.id;
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [savingOrganization, setSavingOrganization] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function selectOrganization(organizationId: string | null) {
    setSavingOrganization(true);
    setError(null);
    try {
      const result = await db.auth.organization.setActive({ organizationId });
      if (result.error) throw new Error(result.error.message);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSavingOrganization(false);
    }
  }

  async function createOrganization(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const organizationName = name.trim();
    const organizationSlug = slug.trim();
    if (!organizationName || !organizationSlug || savingOrganization) return;
    setSavingOrganization(true);
    setError(null);
    try {
      const created = await db.auth.organization.create({
        name: organizationName,
        slug: organizationSlug,
        keepCurrentActiveOrganization: true,
      });
      if (created.error || !created.data) {
        throw new Error(created.error?.message ?? "Better Auth did not return the new organization");
      }
      const active = await db.auth.organization.setActive({ organizationId: created.data.id });
      if (active.error) throw new Error(active.error.message);
      setName("");
      setSlug("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSavingOrganization(false);
    }
  }

  async function deleteActiveOrganization() {
    if (!activeOrganizationId || savingOrganization) return;
    setSavingOrganization(true);
    setError(null);
    try {
      const deleted = await db.auth.organization.delete({ organizationId: activeOrganizationId });
      if (deleted.error) throw new Error(deleted.error.message);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSavingOrganization(false);
    }
  }

  return (
    <main className="shell">
      <header>
        <div>
          <h1>chardb messages</h1>
          <p data-testid="auth-status" data-user-id={userId}>
            Signed in with Better Auth
          </p>
        </div>
      </header>

      <section className="organizations" aria-label="Organizations">
        <label>
          Active organization
          <select
            data-testid="organization-select"
            value={activeOrganizationId ?? ""}
            disabled={savingOrganization || organizations.isPending}
            onChange={event => void selectOrganization(event.target.value || null)}
          >
            <option value="">Choose an organization</option>
            {(organizations.data ?? []).map((organization: Organization) => (
              <option key={organization.id} value={organization.id} data-slug={organization.slug}>
                {organization.name}
              </option>
            ))}
          </select>
        </label>

        <form className="organization-form" onSubmit={createOrganization}>
          <input
            data-testid="create-organization-name"
            aria-label="Organization name"
            value={name}
            placeholder="Organization name"
            disabled={savingOrganization}
            onChange={event => setName(event.target.value)}
          />
          <input
            data-testid="create-organization-slug"
            aria-label="Organization slug"
            value={slug}
            placeholder="organization-slug"
            disabled={savingOrganization}
            onChange={event => setSlug(event.target.value)}
          />
          <button
            data-testid="create-organization-submit"
            type="submit"
            disabled={savingOrganization || !name.trim() || !slug.trim()}
          >
            {savingOrganization ? "Saving..." : "Create organization"}
          </button>
        </form>
        <button
          data-testid="delete-organization"
          type="button"
          disabled={savingOrganization || !activeOrganizationId}
          onClick={() => void deleteActiveOrganization()}
        >
          Delete active organization
        </button>
      </section>

      {activeOrganizationId && userId ? (
        <Messages organizationId={activeOrganizationId} userId={userId} />
      ) : (
        <section className="messages" data-testid="message-list">
          <p className="empty">Create or choose an organization to start.</p>
        </section>
      )}
      {error ? <p className="error">{error}</p> : null}
    </main>
  );
}

interface MessageRow {
  readonly id: string;
  readonly authorId: string;
  readonly body: string;
  readonly attachment: string | null;
}

function MessageCard({
  message,
  userId,
}: {
  readonly message: MessageRow;
  readonly userId: string;
}) {
  const attachment = db.useFile(messageAttachment);
  const replace = db.useMutation(replaceMessageAttachment);
  const [selected, setSelected] = useState<{ readonly file: File; readonly retryKey: string } | null>(null);
  const [replacing, setReplacing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submitReplacement(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected || replacing) return;
    setReplacing(true);
    setError(null);
    try {
      const uploaded = await attachment.upload({
        file: selected.file,
        idempotencyKey: selected.retryKey,
      });
      await replace({ id: message.id, attachment: uploaded.fileId });
      setSelected(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setReplacing(false);
    }
  }

  return (
    <article
      className={message.authorId === userId ? "mine" : undefined}
      data-message-id={message.id}
      data-attachment-id={message.attachment ?? undefined}
    >
      <small>{message.authorId === userId ? "you" : message.authorId}</small>
      <p>{message.body}</p>
      {message.attachment ? (
        <a
          data-testid="message-attachment"
          href={attachment.downloadUrl({ rowId: message.id })}
        >
          Download attachment
        </a>
      ) : null}
      {message.authorId === userId ? (
        <form className="attachment-form" onSubmit={submitReplacement}>
          <input
            key={selected?.retryKey ?? "empty"}
            data-testid="message-replacement-file"
            aria-label={"Replace attachment for " + message.body}
            type="file"
            accept="image/jpeg,image/png"
            disabled={replacing}
            onChange={event => {
              const file = event.target.files?.[0];
              setSelected(file ? { file, retryKey: crypto.randomUUID() } : null);
            }}
          />
          <button type="submit" disabled={replacing || !selected}>
            {replacing ? "Replacing..." : "Replace attachment"}
          </button>
        </form>
      ) : null}
      {error ? <p className="error">{error}</p> : null}
    </article>
  );
}

function Messages({ organizationId, userId }: { readonly organizationId: string; readonly userId: string }) {
  const { data = [], state } = db.useQuery(listMessages, { limit: 50 });
  const mutate = db.useMutation(postMessage);
  const attachment = db.useFile(messageAttachment);
  const [body, setBody] = useState("");
  const [selectedFile, setSelectedFile] = useState<{ readonly file: File; readonly retryKey: string } | null>(null);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const message = body.trim();
    if (!message || sending) return;
    setSending(true);
    setError(null);
    try {
      const uploaded = selectedFile
        ? await attachment.upload({
            file: selectedFile.file,
            idempotencyKey: selectedFile.retryKey,
          })
        : null;
      await mutate({
        id: uuidv7(),
        body: message,
        attachment: uploaded?.fileId ?? null,
        clientCreatedAt: Date.now(),
      });
      setBody("");
      setSelectedFile(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSending(false);
    }
  }

  return (
    <>
      <div className="query-status">
        <code data-testid="query-state" data-organization-id={organizationId}>{state}</code>
      </div>

      <section
        className="messages"
        data-testid="message-list"
        data-organization-id={organizationId}
        aria-live="polite"
      >
        {data.length === 0 ? <p className="empty">No messages yet.</p> : null}
        {[...data].reverse().map(message => (
          <MessageCard
            key={message.id}
            message={message}
            userId={userId}
          />
        ))}
      </section>

      <form onSubmit={submit}>
        <input
          aria-label="Message"
          value={body}
          maxLength={2_000}
          placeholder="Write a message"
          disabled={sending}
          onChange={event => setBody(event.target.value)}
        />
        <input
          key={selectedFile?.retryKey ?? "empty"}
          data-testid="message-file"
          aria-label="Attachment"
          type="file"
          accept="image/jpeg,image/png"
          disabled={sending}
          onChange={event => {
            const selected = event.target.files?.[0];
            setSelectedFile(selected ? { file: selected, retryKey: crypto.randomUUID() } : null);
          }}
        />
        <button type="submit" disabled={sending || !body.trim()}>
          {sending ? "Sending..." : "Send"}
        </button>
      </form>
      {error ? <p className="error">{error}</p> : null}
    </>
  );
}
