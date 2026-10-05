# Your app as the identity provider: sign-in and provisioning

An identity provider does two jobs for the apps it serves: it **signs people in**, and it **keeps their accounts in step**: created before their first sign-in, updated when they change, switched off when they leave. This plugin does the first, over SAML. Its companion, [better-auth-scim-provisioning](https://www.npmjs.com/package/better-auth-scim-provisioning), does the second, over SCIM 2.0, Google Workspace's Directory API, or signed webhooks. Together, your Better Auth app does both jobs.

They're separate packages because they're separate concerns: sign-in happens in the moment, while provisioning works in the background with a queue and retries. Each also works alone. Use both when an app needs its accounts to exist ahead of time, or needs them switched off reliably when someone leaves.

## Do you need provisioning?

| Without provisioning | With provisioning |
|---|---|
| The app creates an account at the user's first sign-in, if it can ("just-in-time"); some apps can't, and refuse unknown users | The account exists before the first sign-in, so the user can be shared with, assigned, or added to a group in advance |
| When someone leaves, they can't sign in again, but the app keeps their account, and any session they already have, until it expires | The account is deactivated at once; Cloudflare Access, for example, revokes the live session |
| Groups at the app are managed by hand | Organizations, teams and roles in your app become groups at the app, kept in sync |

## One app, both plugins

```ts title="auth.ts"
import { betterAuth } from "better-auth";
import { admin, organization } from "better-auth/plugins";
import { samlIdp } from "better-auth-saml-idp";
import { awsIamIdentityCenter, scimProvisioning } from "better-auth-scim-provisioning";

export const auth = betterAuth({
  // database, emailAndPassword, … as you have them
  plugins: [
    admin(), // bans: a banned user is refused sign-in and deactivated at every app
    organization({ teams: { enabled: true } }),
    samlIdp({
      entityId: "https://auth.example.com/api/auth/saml2/idp",
      baseURL: "https://auth.example.com",
      loginPage: "/sign-in",
      signing: { privateKey: process.env.SAML_IDP_PRIVATE_KEY!, certificate: process.env.SAML_IDP_CERT! },
      serviceProviders: [
        { id: "cf-access", entityId: "https://<team>.cloudflareaccess.com/cdn-cgi/access/callback", acsUrls: ["https://<team>.cloudflareaccess.com/cdn-cgi/access/callback"] },
        { id: "google-workspace", entityId: "https://accounts.google.com/samlrp/<id>", acsUrls: ["https://accounts.google.com/samlrp/<id>/acs"] },
        // AWS lists several ACS URLs (one per Region and hostname): keep every one from its metadata.
        { id: "aws", entityId: "https://<region>.signin.aws.amazon.com/platform/saml/d-xxxxxxxxxx", acsUrls: ["<every ACS URL in AWS's metadata>"] },
      ],
    }),
    scimProvisioning({
      targets: [
        { id: "cf-access", url: process.env.CF_SCIM_URL!, token: process.env.CF_SCIM_TOKEN!, groups: true },
        {
          id: "google-workspace",
          type: "google-workspace",
          google: { clientEmail: process.env.GOOGLE_CLIENT_EMAIL!, privateKey: process.env.GOOGLE_PRIVATE_KEY!, adminEmail: "admin@example.com" },
          groups: true,
        },
        awsIamIdentityCenter({ id: "aws", url: process.env.AWS_SCIM_URL!, token: process.env.AWS_SCIM_TOKEN!, groups: true }),
      ],
    }),
  ],
});
```

Each SP's entity ID and ACS URL come from the app; each provisioning target's URL and token (or Google's service account) too. The step-by-step guides below say where.

## The one rule: the same identifier on both sides

The SAML NameID the app receives at sign-in must match the account provisioning created, or the app sees two different people. By default they match: this plugin sends the user's email as the NameID (`nameIdFormat: "emailAddress"`), and provisioning uses the email as the SCIM `userName` (Google: the primary email). If you change one (a custom `nameId`, or a custom `mapUser` userName), change the other to the same value.

Provisioning only creates accounts for users whose email is verified, which is also what this plugin requires before it signs anyone in.

## Order of setup

1. **Sign-in first.** Register the app as an SP here, configure the app to use your IdP, and sign in once with a test user. (The app may create that account itself, just in time; provisioning adopts it later, since it's the same email.)
2. **Then provisioning.** Turn on provisioning at the app, give the target its endpoint and token, and run a reconcile (`auth.api.scimProvisioningReconcile`) to create the accounts of everyone who should be there.
3. **Then groups,** if you use them: assign the app's access to the groups provisioning creates.

## When someone leaves

| In your app | Sign-in (this plugin) | Provisioning |
|---|---|---|
| Banned | refused at once ("You have been banned") | deactivated at every app; lifted bans reactivate |
| Deleted | can't sign in | deactivated (or deleted, with `deprovision: "delete"`) |
| Removed from an organization | still signs in to apps that don't depend on it | removed from that organization's group (and, with an organization-scoped target, deactivated there) |

[Single Logout](single-logout.md) ends sessions at the SPs that support it when the user signs out. Provisioning is what reaches apps that keep their own sessions.

## Verified live, both together

| App | Sign-in | Provisioning | Guide |
|---|---|---|---|
| Cloudflare Access | ✓ | ✓ (users and groups) | [SP guide](../sp-cloudflare-access.md) |
| Google Workspace | ✓ | ✓ (users and Google Groups) | [SP guide](../sp-google-workspace.md) |
| AWS IAM Identity Center | ✓ | ✓ (users and groups) | [SP guide](../sp-aws-iam-identity-center.md) |

With Google Workspace both were tested in one run: provisioning created the user in an organizational unit, Google sent their sign-in to this plugin, and banning them suspended the Workspace account and refused the next sign-in. Okta, Auth0 and Salesforce are verified for sign-in; their provisioning hasn't been tested.

For provisioning's own options, profiles for specific apps, groups and retries, see [its README](https://github.com/mmcintosh/better-auth-scim-provisioning#readme).
