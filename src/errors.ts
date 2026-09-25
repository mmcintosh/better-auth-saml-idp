import { defineErrorCodes } from "@better-auth/core/utils/error-codes";

export const SAML_IDP_ERROR_CODES = defineErrorCodes({
  UNKNOWN_SERVICE_PROVIDER: "Unknown SAML service provider",
  ACS_URL_NOT_ALLOWED: "AssertionConsumerServiceURL is not registered for this service provider",
  IDP_INITIATED_NOT_ALLOWED: "This application does not accept sign-in started from the identity provider",
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
  INTERNAL_ERROR: "Sign-in could not be completed",
  LOGOUT_NOT_SUPPORTED: "This application isn't set up for single logout",
  LOGOUT_STATE_NOT_FOUND: "The logout has expired or was already completed",
  INVALID_RETURN_TO: "The return address after logout is not allowed",
  // Registry API (D-027)
  REGISTRY_NOT_ALLOWED: "You are not allowed to manage SAML service providers",
  INVALID_SERVICE_PROVIDER: "Invalid service provider configuration",
  SERVICE_PROVIDER_EXISTS: "A service provider with this id or entity ID already exists",
  SERVICE_PROVIDER_NOT_FOUND: "Service provider not found",
  SERVICE_PROVIDER_IN_CODE: "This service provider is defined in code and can't be managed here",
});

export type SamlIdpErrorCode = keyof typeof SAML_IDP_ERROR_CODES;

export const ERROR_STATUS: Record<SamlIdpErrorCode, number> = {
  UNKNOWN_SERVICE_PROVIDER: 400,
  ACS_URL_NOT_ALLOWED: 400,
  IDP_INITIATED_NOT_ALLOWED: 400,
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
  INTERNAL_ERROR: 500,
  LOGOUT_NOT_SUPPORTED: 400,
  LOGOUT_STATE_NOT_FOUND: 400,
  INVALID_RETURN_TO: 400,
  REGISTRY_NOT_ALLOWED: 403,
  INVALID_SERVICE_PROVIDER: 400,
  SERVICE_PROVIDER_EXISTS: 409,
  SERVICE_PROVIDER_NOT_FOUND: 404,
  SERVICE_PROVIDER_IN_CODE: 409,
};
