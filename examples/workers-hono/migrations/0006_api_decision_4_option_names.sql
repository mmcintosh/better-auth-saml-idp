-- API decision 4 (DECISIONS.md D-040): stored SP configs use the new option names.
--   requireSignedAuthnRequests: true      -> requestSignatures: "require"
--   requireSignedAuthnRequests: false     -> removed (the default is derived from the certificates)
--   spCertificate                         -> spCertificates
--   metadata.signingCertificate           -> metadata.signingCertificates
--   signResponse / signAssertion          -> sign: "both" | "response" | "assertion"
-- Rows without the old names are untouched. Safe to run twice.

UPDATE saml_idp_service_providers
SET config = json_remove(json_set(config, '$.requestSignatures', 'require'), '$.requireSignedAuthnRequests')
WHERE json_extract(config, '$.requireSignedAuthnRequests') = 1;

UPDATE saml_idp_service_providers
SET config = json_remove(config, '$.requireSignedAuthnRequests')
WHERE json_type(config, '$.requireSignedAuthnRequests') IS NOT NULL;

UPDATE saml_idp_service_providers
SET config = json_remove(json_set(config, '$.spCertificates', json(config -> '$.spCertificate')), '$.spCertificate')
WHERE json_type(config, '$.spCertificate') IS NOT NULL;

UPDATE saml_idp_service_providers
SET config = json_remove(json_set(config, '$.metadata.signingCertificates', json(config -> '$.metadata.signingCertificate')), '$.metadata.signingCertificate')
WHERE json_type(config, '$.metadata.signingCertificate') IS NOT NULL;

-- Both false was never valid, so only three combinations exist. Unset means true.
UPDATE saml_idp_service_providers
SET config = json_remove(
  json_set(config, '$.sign',
    CASE
      WHEN json_extract(config, '$.signResponse') = 0 THEN 'assertion'
      WHEN json_extract(config, '$.signAssertion') = 0 THEN 'response'
      ELSE 'both'
    END),
  '$.signResponse', '$.signAssertion')
WHERE json_type(config, '$.signResponse') IS NOT NULL OR json_type(config, '$.signAssertion') IS NOT NULL;
