<?php
/**
 * Configuration texts for ADFS SAML Auth
 */

$lang['idPEntityID'] = 'The ID of your SAML server. Usually <code>http://<i>&lt;yourserver&gt;</i>/adfs/services/trust</code>';
$lang['endpoint']    = 'The SAML auth API endpoint. Usually <code>https://<i>&lt;yourserver&gt;</i>/adfs/ls/</code>';
$lang['certificate'] = 'The SAML auth certificate';
$lang['lowercase'] = 'Treat user and group names as case insensitive and lower case them automatically?';
$lang['autoprovisioning'] = 'Automatic user provisioning: authenticated users are created automatically and do not need to be added manually by the wiki administrator';
$lang["auto_login"] = "when to enforce auto-login: <code>never</code> will never ask to automatically authenticate; <code>after login</code> will prompt to automatically ask to re-authenticate if the DokuWiki session ends unless explicitly logged out; <code>always</code> will always require login";
$lang['userid_attr_name'] = 'User login name attribute';
$lang['fullname_attr_name'] = 'Full name attribute';
$lang['email_attr_name'] = 'E-mail attribute';
$lang['groups_attr_name'] = 'Groups attribute';


