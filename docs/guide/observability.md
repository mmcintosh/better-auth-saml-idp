# Observability

[Guide](README.md) › Observability

What the IdP did, for audit trails, SIEM forwarding and metrics. There are two ways to get it:
- **event callbacks**, to send events wherever you like;
- an optional **audit-log table** in your database.

## Event callbacks

```ts
samlIdp({
  // …
  events: {
    onAssertionIssued: (e) => log.info("saml.assertion", e),
    onDenied: (e) => log.warn("saml.denied", e),
    onLogout: (e) => log.info("saml.logout", e),
  },
});
```

| Callback | When |
|---|---|
| `onAssertionIssued` | An assertion was signed and handed to the browser for the SP's ACS. Covers SP- and IdP-initiated sign-in. |
| `onAssertionExchanged` | An OAuth client exchanged an assertion this IdP issued (`clientId`, `assertionId`, the SP and user). See [Exchanging assertions for OAuth tokens](token-exchange.md). |
| `onDenied` | The IdP refused something, either with an error page (`code` is one of the [error codes](errors.md)), or with a SAML error Response to the SP (`code: "SAML_STATUS"` with `status`, e.g. `NoPassive`). |
| `onLogout` | Single Logout ended an IdP session, started by an SP or by your app's sign-out-everywhere. |
| `onSessionEnded` | A session ended *without* Single Logout (revoked, disabled, `/sign-out`, expired), with the SPs that weren't told. Fires outside requests too, so it has no IP or user agent. See [When the session ends without the browser](single-logout.md#when-the-session-ends-without-the-browser). |
| `onTenantChanged` | With [tenants](multi-tenant.md): an administrator created, enabled, disabled or deleted a tenant, or rotated, activated or retired one of its keys. |
| `onServiceProviderChanged` | A stored SP was created, updated, enabled, disabled or deleted through the [registry API](service-providers.md#registry-api), by your managers or a tenant's administrator (`delegated`). |

Every event has `type`, `at` (a `Date`), and when available `ipAddress` and `userAgent`. The IP is read the way Better Auth reads it: from `advanced.ipAddress.ipAddressHeaders` (which `withCloudflare` sets to `cf-connecting-ip`), a valid IP only, and from a multi-value header such as `X-Forwarded-For` only through `advanced.ipAddress.trustedProxies`, since its left-most entry is whatever the client sent. It's absent with `disableIpTracking`.

<details><summary>Event fields</summary>

**`assertion.issued`**

| Field | Description |
|---|---|
| `spId`, `entityId` | The SP. |
| `userId`, `sessionId` | Who, in which Better Auth session. |
| `assertionId` | The assertion's `ID`, as the SP logs it. |
| `initiatedBy` | `"sp"` (a Response to an AuthnRequest) or `"idp"` (IdP-initiated). |
| `inResponseTo` | The AuthnRequest's ID (SP-initiated only). |
| `acsUrl` | Where it was posted. |
| `nameIdFormat`, `nameId` | The NameID as sent. It may be an email address: personal data. |
| `attributes` | The attribute **names** sent. Values are never included. |
| `encrypted` | Whether the assertion was encrypted. |

**`denied`**

| Field | Description |
|---|---|
| `code` | An [error code](errors.md), or `"SAML_STATUS"`. |
| `status` | For `SAML_STATUS`: `{ code, subCode? }`, e.g. `Responder` / `NoPassive`. |
| `spId` | The SP, when the request identified one. |
| `userId` | The signed-in user, when there was one. |
| `detail` | Why, as in the debug log: log-safe, at most 300 characters. |

**`logout`**

| Field | Description |
|---|---|
| `initiatedBy` | `"sp"` (an SP's LogoutRequest) or `"idp"` (`signOutEverywhere`). |
| `spId` | The SP that started it (SP-initiated only). |
| `userId`, `sessionId` | Whose session ended. |
| `notifying` | The other SPs that will be sent a LogoutRequest, in order. |

**`tenant.changed`**

| Field | Description |
|---|---|
| `action` | `created`, `enabled`, `disabled`, `deleted`, `key.rotated`, `key.activated` or `key.retired`. |
| `userId` | The administrator who did it. |
| `tenantId`, `tenantKey` | The tenant (its organization id, and the key in its URLs). |
| `kid` | For key actions: which key (for `key.retired`, a comma-separated list). |
| `forced` | `true` for an activation that skipped `minPublishedSeconds`. |

**`service-provider.changed`**

| Field | Description |
|---|---|
| `action` | `created`, `updated`, `enabled`, `disabled` or `deleted`. |
| `userId` | Who did it. |
| `spId`, `entityId` | The SP. |
| `tenantId` | Its tenant, when it has one. |
| `delegated` | `true` when a tenant's administrator did it ([delegation](multi-tenant.md#delegated-administration)), `false` for your managers. |

</details>

**How handlers run:**
- **In the background.** Handlers go through Better Auth's background tasks (`advanced.backgroundTasks.handler`, which is `waitUntil` on Workers; see [Cloudflare Workers](cloudflare-workers.md)). A slow handler never delays the user.
- **As observers.** A handler that throws or rejects is logged, and the sign-in or logout it observed is unaffected. So a handler can't *block* anything; use [`authorize`](users-and-access.md#authorize) for that.
- **They see everything, including noise.** `onDenied` also fires for unauthenticated protocol errors (a malformed request, an unknown SP), which anyone can trigger. That's what a SIEM wants to see, but rate-limit or sample before paging anyone.

## Audit-log table

```ts
samlIdp({
  // …
  auditLog: { enabled: true, retentionDays: 90 }, // default 90, up to 3650
});
```

This records the same events in the [`samlIdpAuditEvent`](schema.md#samlidpauditevent-with-auditlogenabled) table, one row per event:
- `type`, `at`, `spId`, `userId`, `code`, `ipAddress` and `userAgent` are columns, so you can query them;
- the whole event is stored as JSON in `details`.

Create the table with your migrations: `npx auth migrate` or `generate`, or D1 migration `0005`.

- **Only denials for a signed-in user are stored.** Any other refusal (a malformed request, an unknown issuer, or a SAML error Response to a known SP, whose entity ID anyone can put in a request) goes to `onDenied` but not the table, so an attacker can't grow it at will. "Signed in" includes users whose email isn't verified yet: with open sign-up, one registration gets past this, so keep Better Auth's rate limits on. SAML error Responses are also logged as warnings, such as `[saml-idp] SAML status Responder/InvalidNameIDPolicy for SP google-workspace: …`: when an SP only says "couldn't sign you in", that line says why.
- **Retention:** rows expire after `retentionDays` and are swept automatically, like the plugin's other expiring rows.
- **Best effort:** rows are written in the background. A failed write is logged; it never fails the sign-in. If you need every event durably, forward from the callbacks to a store that guarantees it.
- **Personal data:** `details` holds the NameID (often an email) and the IP. Set `retentionDays` to what your privacy policy allows. The session-participant table (with Single Logout or `onSessionEnded`) also holds each SP's NameID; its rows expire with the session, and are removed at once when the user is deleted.

Example queries (SQL, default table names):

```sql
-- Who signed in to which SP today
SELECT at, sp_id, user_id, ip_address FROM saml_idp_audit_events
WHERE type = 'assertion.issued' AND at > strftime('%s','now','-1 day') * 1000 ORDER BY at;

-- Denials by code for one SP
SELECT code, count(*) FROM saml_idp_audit_events WHERE type = 'denied' AND sp_id = 'zoom' GROUP BY code;
```

(These use SQLite/D1 millisecond timestamps. Adjust the date arithmetic for your database.)

## Logs

Independently of the above, the plugin logs through Better Auth's logger:
- `info` for issued assertions, logouts and registry changes;
- `warn` and `error` for problems;
- `debug` for every refusal with its reason.

Set `logger: { level: "debug" }` in Better Auth to see refusals while setting up an SP.
