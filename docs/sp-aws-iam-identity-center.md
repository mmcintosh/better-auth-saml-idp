# Service provider: AWS IAM Identity Center

AWS IAM Identity Center can use an external SAML 2.0 IdP for the AWS access portal. It's a strict SP, which makes it a good real-world test.

Source for the AWS side: https://docs.aws.amazon.com/singlesignon/latest/userguide/how-to-connect-idp.html (checked 2026-09-25).

> [!CAUTION]
> **Changing IAM Identity Center's identity source changes how *everyone* in that AWS organization signs in to the access portal.** Do this only in a **sandbox AWS account or organization** that nobody else relies on. Also keep an IAM user or the root user available, so you can switch back.

## 1. Deploy the IdP

Follow [examples/workers-hono](../examples/workers-hono/README.md#deploy), then save the IdP metadata to a file:

```sh
curl -o idp-metadata.xml https://<worker>.workers.dev/api/auth/saml2/idp/metadata
```

## 2. Get the AWS service provider values

**IAM Identity Center console → Settings → Identity source → Actions → Change identity source → External identity provider → Next.**

Under **Service provider metadata**, choose **Download metadata file**. From that file, note:
- the `entityID` (the "IAM Identity Center issuer URL")
- **every** `AssertionConsumerService` `Location`. AWS lists both IPv4-only and dual-stack ACS URLs, plus one per replicated Region.

## 3. Register AWS as an SP on the IdP

```json
[{ "id": "aws-identity-center",
   "entityId": "<issuer URL / entityID from the AWS metadata>",
   "acsUrls": ["<ACS URL 1>", "<ACS URL 2>"] }]
```

Put this in `SAML_SERVICE_PROVIDERS`, then redeploy. List every ACS URL that AWS publishes, because the plugin only posts to allow-listed URLs.

## 4. Finish in AWS

- Under **Identity provider metadata**, upload `idp-metadata.xml`, then choose **Next**, type **ACCEPT**, and choose **Change identity source**.
- **Provision a test user.** SAML can't create users in IAM Identity Center. Add the user manually (**Users → Add user**), with a **username equal to the email** the IdP sends as NameID. Alternatively, set up SCIM.
- Assign that user to an AWS account or permission set.

## 5. Test

Open the AWS access portal URL, which is shown on the IAM Identity Center dashboard. You should be sent to the IdP's `/sign-in`. Sign in as the provisioned email and you'll land in the portal. **Screenshot the portal; this is the Phase 3 evidence.**

## Troubleshooting

- AWS reports an unknown user: the Identity Center username must match the NameID (the email) exactly.
- The IdP returns `ACS_URL_NOT_ALLOWED`: add the ACS URL AWS actually used, whether IPv4 or dual-stack, to `acsUrls`.
- To switch back: **Settings → Identity source → Change identity source → Identity Center directory**.
