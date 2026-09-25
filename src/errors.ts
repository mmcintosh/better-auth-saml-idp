import { defineErrorCodes } from "@better-auth/core/utils/error-codes";

export const SAML_IDP_ERROR_CODES = defineErrorCodes({
  UNKNOWN_SERVICE_PROVIDER: "Unknown SAML service provider",
  ACS_URL_NOT_ALLOWED: "AssertionConsumerServiceURL is not registered for this service provider",
  INVALID_SAML_REQUEST: "Invalid SAML request",
  UNSIGNED_SAML_REQUEST: "This service provider requires signed AuthnRequests",
  DUPLICATE_REQUEST_ID: "This AuthnRequest has already been processed",
  RELAY_STATE_TOO_LONG: "RelayState exceeds the allowed length",
  PENDING_REQUEST_NOT_FOUND: "The SAML sign-in request has expired or was already used",
  ACCESS_DENIED: "You are not allowed to sign in to this application",
  ACCOUNT_INACTIVE: "Your account is not active",
  EMAIL_NOT_VERIFIED: "Verify your email address before signing in to this application",
  SESSION_NOT_ALLOWED: "This kind of session cannot be used to sign in to other applications",
  REAUTHENTICATION_REQUIRED: "This application requires you to sign in again",
  PASSIVE_SIGN_IN_NOT_POSSIBLE: "You must sign in before continuing to this application",
  INTERNAL_ERROR: "Sign-in could not be completed",
});

export type SamlIdpErrorCode = keyof typeof SAML_IDP_ERROR_CODES;

export const ERROR_STATUS: Record<SamlIdpErrorCode, number> = {
  UNKNOWN_SERVICE_PROVIDER: 400,
  ACS_URL_NOT_ALLOWED: 400,
  INVALID_SAML_REQUEST: 400,
  UNSIGNED_SAML_REQUEST: 400,
  DUPLICATE_REQUEST_ID: 400,
  RELAY_STATE_TOO_LONG: 400,
  PENDING_REQUEST_NOT_FOUND: 400,
  ACCESS_DENIED: 403,
  ACCOUNT_INACTIVE: 403,
  EMAIL_NOT_VERIFIED: 403,
  SESSION_NOT_ALLOWED: 403,
  REAUTHENTICATION_REQUIRED: 401,
  PASSIVE_SIGN_IN_NOT_POSSIBLE: 401,
  INTERNAL_ERROR: 500,
};
