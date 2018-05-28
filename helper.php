<?php

/**
 * ADFS SAML authentication plugin
 *
 * @author     Andreas Gohr <gohr@cosmocode.de>
 */
class helper_plugin_adfs extends auth_plugin_authplain
{
    /**
     * Get the initialized SAML library
     *
     * @return OneLogin_Saml2_Auth
     */
    public function getSamlLib()
    {
        static $saml = null;
        if ($saml === null) {
            require_once __DIR__ . '/phpsaml/_toolkit_loader.php';
            $saml = new OneLogin_Saml2_Auth($this->createSettings());
        }
        return $saml;
    }

    /**
     * Initializes the settings array for the PHP SAML library
     *
     * @return array
     */
    protected function createSettings()
    {
        global $conf;

        $cert = $this->getConf('certificate');
        $cert = wordwrap($cert, 65, "\n", true);
        $cert = trim($cert);
        if (!preg_match('/^-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----$/s', $cert)) {
            $cert = "-----BEGIN CERTIFICATE-----\n$cert\n-----END CERTIFICATE-----";
        }

        return [
            'strict' => true,
            'debug' => false,
            'baseurl' => DOKU_URL . DOKU_SCRIPT,

            // Our own meta data
            'sp' => [
                'entityId' => DOKU_URL,
                'assertionConsumerService' => [
                    'url' => DOKU_URL . DOKU_SCRIPT,
                    'binding' => OneLogin_Saml2_Constants::BINDING_HTTP_POST,
                ],
                'attributeConsumingService' => [
                    'serviceName' => $conf['title'],
                    "serviceDescription" => 'ADFS auth plugin',
                ],
                'NameIDFormat' => OneLogin_Saml2_Constants::NAMEID_EMAIL_ADDRESS,
            ],

            // The ADFS server we talk to
            'idp' => [
                'entityId' => $this->getConf('endpoint'),
                'singleSignOnService' => [
                    'url' => $this->getConf('endpoint'),
                    'binding' => OneLogin_Saml2_Constants::BINDING_HTTP_REDIRECT,
                ],
                'NameIDFormat' => OneLogin_Saml2_Constants::NAMEID_UNSPECIFIED,
                'x509cert' => $cert,
            ],

            'security' => [
                'requestedAuthnContext' => false, // We let the AD decide what kind of authentication it uses
                'wantNameId' => false // Seems not to work otherwise
            ],

            'organization' => array(
                'en-US' => array(
                    'name' => $conf['title'],
                    'displayname' => $conf['title'],
                    'url' => DOKU_URL
                ),
            ),
        ];
    }
}
