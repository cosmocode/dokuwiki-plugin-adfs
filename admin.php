<?php

/**
 * ADFS SAML authentication plugin
 *
 * @author     Andreas Gohr <gohr@cosmocode.de>
 */
class admin_plugin_adfs extends DokuWiki_Admin_Plugin
{
    protected $xml = '';

    public function handle()
    {
        global $INPUT;
        if ($INPUT->str('url')) {
            $http = new DokuHTTPClient();
            $xml = $http->get($INPUT->str('url'));
            if ($xml === false) {
                msg('Failed to download metadata. ' . hsc($http->error), -1);
            } else {
                $this->xml = $xml;
            }
        } elseif ($INPUT->has('xml')) {
            header("X-XSS-Protection: 0");
            $this->xml = $INPUT->str('xml');
        }

    }

    public function html()
    {
        echo $this->locale_xhtml('intro');

        $form = new \dokuwiki\Form\Form();
        $form->addFieldsetOpen('Federation Metadata');
        $urlinput = $form->addTextInput('url', 'Metadata Endpoint');
        if ($this->xml) $urlinput->val('')->useInput(false);
        $form->addTextarea('xml', 'The XML Metadata')->val($this->xml)->useInput(false);
        $form->addButton('go', 'Submit')->attr('type', 'submit');
        $form->addFieldsetClose();
        echo $form->toHTML();

        if ($this->xml) {
            $data = $this->metaData($this->xml);
            if (count($data)) {
                echo $this->locale_xhtml('found');

                echo '<dl>';
                foreach ($data as $key => $val) {
                    echo '<dt>' . hsc($key) . '</dt>';
                    echo '<dd><code>' . hsc($val) . '</code></dd>';
                }
                echo '</dl>';
            } else {
                echo $this->locale_xhtml('notfound');
            }
        }
    }

    /**
     * Parse the metadata and return the configuration values
     */
    public function metaData($xml)
    {

        $xml = @simplexml_load_string($xml);
        if ($xml === false) {
            msg('Failed to parse the the XML', -1);
            return [];
        }

        $xml->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $xml->registerXPathNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        $proto = '/md:EntityDescriptor/md:IDPSSODescriptor[@protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"]';
        $data['idPEntityID'] = (string)$xml['entityID'];
        $data['endpoint'] = (string)($xml->xpath($proto . '/md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]'))[0]['Location'];
        $data['certificate'] = (string)($xml->xpath($proto . '/md:KeyDescriptor[@use="signing"]/ds:KeyInfo/ds:X509Data/ds:X509Certificate'))[0];

        return $data;
    }


}
