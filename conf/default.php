<?php
/**
 * Configuration defaults for ADFS SAML Auth
*/

$conf['idPEntityID'] = 'set me';
$conf['endpoint']  = '';
$conf['certificate'] = '';
$conf['lowercase'] = 1;
$conf['autoprovisioning'] = 1;
$conf["auto_login"] = "never";
$conf['userid_attr_name'] = 'login';
$conf['fullname_attr_name'] = 'fullname';
$conf['email_attr_name'] = 'email';
$conf['groups_attr_name'] = 'groups';
