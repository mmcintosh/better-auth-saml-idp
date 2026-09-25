<?php
// e2e runs over plain http on localhost.
$config['session.cookie.secure'] = false;
$config['session.cookie.samesite'] = 'Lax';
$config['baseurlpath'] = 'http://localhost:8081/simplesaml/';
