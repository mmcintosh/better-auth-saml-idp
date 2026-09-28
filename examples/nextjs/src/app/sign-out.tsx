"use client";

import { authClient } from "../lib/auth-client";

export function SignOut() {
  return (
    <button type="button" onClick={() => authClient.signOut().then(() => window.location.reload())}>
      Sign out
    </button>
  );
}
