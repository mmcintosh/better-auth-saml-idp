<?php
// SimpleSAMLphp SP pointed at the better-auth-saml-idp example IdP.
$config = [
    'admin' => ['core:AdminPassword'],
    'default-sp' => [
        'saml:SP',
        'entityID' => 'https://ssp.test:8081/simplesaml/module.php/saml/sp/metadata/default-sp',
        'idp' => 'https://idp.test:8787/api/auth/saml2/idp',
        'NameIDPolicy' => ['Format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', 'AllowCreate' => true],
        // Strict: reject anything not signed with RSA-SHA256.
        'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'assertion.encryption' => false,
    ],
];
