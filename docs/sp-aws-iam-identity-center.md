# Service provider: AWS IAM Identity Center

AWS IAM Identity Center can use an external SAML 2.0 IdP for the AWS access portal, so users sign in to AWS with their Better Auth account. Verified live on 2026-09-28 with a new AWS organization: a multi-Region Identity Center instance (Ohio primary, N. Virginia added) accepted our signed assertion. The user landed in the access portal and opened the AWS console in an assigned permission set. AWS is stored in the plugin's database registry (DECISIONS D-054).

Source for the AWS side: https://docs.aws.amazon.com/singlesignon/latest/userguide/how-to-connect-idp.html (checked 2026-09-25).

> [!CAUTION]
> **Changing IAM Identity Center's identity source changes how *everyone* in that AWS organization signs in to the access portal.** Do this only in a **sandbox AWS account or organization** that nobody else relies on. Also keep an IAM user or the root user available, so you can switch back.

What to expect from AWS:
- Identity Center doesn't sign its AuthnRequests (`AuthnRequestsSigned="false"`), and wants the assertion signed. The plugin always signs it.
- The NameID is the email (`emailAddress` format), and it must equal the Identity Center **username**.
- No SAML Single Logout: signing out of the portal ends only the AWS session. The IdP session stays.

## 1. Deploy the IdP

Follow [examples/workers-hono](../examples/workers-hono/README.md#deploy), then save the IdP metadata to a file:

```sh
curl -o idp-metadata.xml https://<worker>.workers.dev/api/auth/saml2/idp/metadata
```

## 2. Get the AWS service provider values

If Identity Center isn't enabled yet: **IAM Identity Center → Enable**, which also creates an AWS Organization. The Region you choose becomes the primary Region and can't be changed later.

Then **Settings → Identity source → Actions → Change identity source → External identity provider → Next.** Under **Service provider metadata**, choose **Download metadata file**. The file has:
- the `entityID` (the "IAM Identity Center issuer URL"), such as `https://us-east-2.signin.aws.amazon.com/platform/saml/d-xxxxxxxxxx`;
- **several** `AssertionConsumerService` URLs: one per Region of the instance, on both `<region>.signin.aws` and `<region>.sso.signin.aws`. In the live test, AWS posted to a `sso.signin.aws` one.

The page has **Dual-stack** and **IPv4-only** tabs. The dual-stack file already lists the IPv4-only ACS URL.

## 3. Register AWS as an SP on the IdP

Either paste the downloaded metadata into the example's `/admin` page (**Add a service provider**, ID `aws-identity-center`, **Convert to configuration**, **Save**), or put it in `SAML_SERVICE_PROVIDERS` and redeploy:

```json
[{ "id": "aws-identity-center",
   "entityId": "<issuer URL / entityID from the AWS metadata>",
   "acsUrls": ["<every ACS URL in the AWS metadata>"] }]
```

Keep every ACS URL AWS publishes, because the plugin only posts to allow-listed URLs.

## 4. Finish in AWS

- Under **Identity provider metadata**, upload `idp-metadata.xml`, then choose **Next**, type **ACCEPT**, and choose **Change identity source**. Right after the change, the page may show "External identity provider configuration not available" above the saved IdP details. That panel is for AWS's own details, not the IdP's; sign-in worked in the live test regardless.
- **Provision a test user.** SAML can't create users in IAM Identity Center. Add the user manually (**Users → Add user**), with a **username equal to the email** the IdP sends as NameID. Alternatively, set up SCIM.
- Assign that user to an AWS account with a permission set.

The user and the assignment can also be made with the AWS CLI (`aws identitystore create-user`, `aws sso-admin create-permission-set`, `attach-managed-policy-to-permission-set` and `create-account-assignment`).

## 5. Test

Open the AWS access portal URL, which is shown on the IAM Identity Center dashboard. You should be sent to the IdP's `/sign-in`, or straight back if you already have an IdP session. You'll land in the portal with the assigned account. Open the account and its permission set to reach the console.

## Troubleshooting

- AWS shows its own sign-in page ("Something doesn't compute"): the identity source is still the Identity Center directory. Finish step 4 first.
- AWS reports an unknown user: the Identity Center username must match the NameID (the email) exactly.
- The IdP returns `ACS_URL_NOT_ALLOWED`: add the ACS URL AWS actually used to `acsUrls`. AWS adds ACS URLs when you add Regions, so download the metadata again after that.
- To switch back: **Settings → Identity source → Change identity source → Identity Center directory**.
