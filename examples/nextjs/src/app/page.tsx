import { headers } from "next/headers";
import { getAuth } from "../lib/auth";
import { SignOut } from "./sign-out";

// Reads the session from the request's cookies, so it renders per request.
export default async function Home() {
  const session = await getAuth().api.getSession({ headers: await headers() });
  return (
    <>
      <h1>better-auth-saml-idp example</h1>
      {session ? (
        <p>
          Signed in as {session.user.email}
          {session.user.emailVerified ? "" : " (email not verified: SPs won't receive assertions)"}. <SignOut />
        </p>
      ) : (
        <p>
          Not signed in. <a href="/sign-in">Sign in or create an account</a>
        </p>
      )}
      <p>
        IdP metadata for service providers: <a href="/api/auth/saml2/idp/metadata">/api/auth/saml2/idp/metadata</a>
      </p>
    </>
  );
}
