# Exchanging assertions for OAuth tokens

Since 1.2.0. An agent that signed a person in through this IdP holds a SAML Assertion. With **assertion exchange**, it can trade that Assertion at your OAuth authorization server for tokens (RFC 8693 token exchange with `subject_token_type=urn:ietf:params:oauth:token-type:saml2`). This is the flow in [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) §4.5, which Okta's Cross App Access and MCP's Enterprise-Managed Authorization use.

This plugin doesn't run the token endpoint. It answers the question only the IdP can: *did I issue this Assertion, to the SP this client stands for, and has it not been exchanged before?* The token endpoint is an OAuth authorization server plugin (an ID-JAG issuer) installed on the same Better Auth instance, which calls this plugin to check the Assertion.

Nothing changes for SPs that don't opt in.

## Turn it on for an SP

```ts
samlIdp({
  // …
  serviceProviders: [
    {
      id: "agent",
      entityId: "https://agent.example.com/saml",
      acsUrls: ["https://agent.example.com/saml/acs"],
      tokenExchange: { clientId: "agent-oauth-client" },
    },
  ],
});
```

- `clientId` is the OAuth client allowed to exchange this SP's assertions, as your authorization server knows it. Any other client is refused.
- The Assertion must be signed: `sign` must be `"both"` (the default) or `"assertion"`. `"response"` is refused at startup.
- Encrypted assertions work. The client presents the decrypted `<saml:Assertion>`.
- **Stored SPs** (the [registry](service-providers.md#registry)) can carry `tokenExchange` too, once you set the server option `tokenExchange: { enabled: true }`. An SP in code with `tokenExchange` turns it on by itself.
- With [tenants](multi-tenant.md) and delegation, a tenant's administrator **can't set or change** `tokenExchange`. They can keep what you set or remove it. Which client may turn a tenant's members' assertions into tokens is the host's decision.

## What happens

1. **At sign-in**, for an SP with `tokenExchange` only, the plugin writes one short-lived record per assertion, a Better Auth verification value keyed by a hash of the assertion ID. It expires with the assertion (`NotOnOrAfter` plus clock skew). There's no new table. If the record can't be written, the sign-in still succeeds and an error is logged; that one assertion just can't be exchanged.
2. **At exchange**, the authorization server calls `getSamlIdpExchange(ctx).verifyIssuedAssertion(ctx, assertionXml, { clientId })`. It checks, in order:
   - **Strict input:** a single `<saml:Assertion>` element (not a Response), at most 64 KiB, no DTD, against the SAML schema.
   - **Issuer:** this IdP's entity ID, or an enabled tenant's.
   - **Signature:** on the Assertion itself, by that identity's key only (with per-tenant keys, the tenant's own), with the same wrapping (XSW) defences as signed requests. `KeyInfo` in the message is ignored.
   - **Shape:** exactly what this IdP issues: one NameID, one bearer confirmation, one audience, one authentication statement.
   - **Time:** `NotBefore` and `NotOnOrAfter`, with `clockSkewSeconds`.
   - **SP:** the audience's SP, in the issuing tenant, has `tokenExchange` with this client.
   - **Single use:** the record is consumed atomically, so across instances only one exchange wins. This happens only after the signature has verified, so made-up assertion IDs can't use up real records. The record must match the Assertion.
   - **The person, now:** the user still exists, isn't banned, has a verified email (unless `accountPolicy` allows otherwise), and still belongs to the SP's organization or tenant. Where sessions are in the database, the session they signed in with must still exist and be unexpired. The SP's `authorize()` isn't run again: it ran at sign-in, minutes earlier.
3. An **`assertion.exchanged` event** goes to `events.onAssertionExchanged` and the audit log.

Verification makes no outbound request (no metadata refresh, no fetch).

## For authorization-server authors

```ts
import { AssertionExchangeError, getSamlIdpExchange } from "better-auth-saml-idp";

const exchange = getSamlIdpExchange(ctx); // undefined when exchange is off
const verified = await exchange.verifyIssuedAssertion(ctx, assertionXml, { clientId });
// verified: { assertionId, issuer, tenantId, serviceProvider: { id, entityId }, userId, sessionId?,
//             nameId, nameIdFormat, authnInstant, authnContextClassRef?, notOnOrAfter }
```

It throws `AssertionExchangeError` with a `code`: `MALFORMED`, `NOT_OURS`, `BAD_SIGNATURE`, `NOT_YET_VALID`, `EXPIRED`, `NOT_EXCHANGEABLE`, `WRONG_CLIENT`, `ALREADY_EXCHANGED` or `ACCOUNT_INACTIVE`. The message is for your logs. Don't send it to the client, and don't let clients tell `WRONG_CLIENT` or `ALREADY_EXCHANGED` apart from the rest. The capability is versioned (`version: 1`); later additions will be backward compatible.

## Limits

- **Assertions issued before an SP opted in** have no record and are refused (`ALREADY_EXCHANGED`).
- **Key rotation:** only the identity's current signing key is accepted. An assertion signed just before a rotation (root `signing` or a tenant's key activation) can't be exchanged after it. Assertions live 5 minutes by default.
- **Sessions only in secondary storage:** the session check needs sessions in the database (`session.storeSessionInDatabase`). Without that, the user checks still run but the session isn't re-checked.
