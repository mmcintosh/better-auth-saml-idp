<?php
// Protected page on the SimpleSAMLphp SP: requires a SAML login, then reports what the SP got.
require_once '/var/simplesamlphp/src/_autoload.php';
$as = new \SimpleSAML\Auth\Simple('default-sp');
$as->requireAuth();
$nameId = $as->getAuthData('saml:sp:NameID');
header('Content-Type: application/json');
echo json_encode([
    'nameId' => $nameId ? $nameId->getValue() : null,
    'attributes' => $as->getAttributes(),
    'idp' => $as->getAuthData('saml:sp:IdP'),
]);
