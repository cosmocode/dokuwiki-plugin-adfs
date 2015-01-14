<?php

/**
 * ADFS SAML authentication plugin
 *
 * @author     Andreas Gohr <gohr@cosmocode.de>
 */
class action_plugin_adfs extends DokuWiki_Action_Plugin {

    public function register(Doku_Event_Handler $controller) {
        $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'handle_request');
    }

    /**
     * @param Doku_Event $event
     * @param mixed $param
     */
    public function handle_request(&$event, $param) {
        $act = act_clean($event->data);
        if($act != 'adfs') return;
        $event->preventDefault();
        $event->stopPropagation();

        global $conf;
        $valid    = gmstrftime('%Y-%m-%dT%H:%M:%SZ', strtotime('+4 weeks'));
        $consumer = DOKU_URL.DOKU_SCRIPT;

        header('Content-Type: application/samlmetadata+xml');
        header('Content-Disposition: attachment; filename="saml-metadata.xml"');

        echo '<?xml version="1.0"?>' . DOKU_LF;
        echo '<EntityDescriptor
                    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    entityID="' . DOKU_URL . '"
                    validUntil="' . $valid . '">' . DOKU_LF;
        echo '  <SPSSODescriptor
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                      WantAssertionsSigned="true">' . DOKU_LF;
        echo '    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>' . DOKU_LF;
        echo '    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>' . DOKU_LF;
        echo '    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>' . DOKU_LF;

        echo '    <AssertionConsumerService
                        index="1"
                        isDefault="true"
                        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        Location="' . $consumer . '"/>' . DOKU_LF;
        echo '  </SPSSODescriptor>' . DOKU_LF;

        echo '  <Organization>' . DOKU_LF;
        echo '    <OrganizationName xml:lang="' . $conf['lang'] . '">' . hsc($conf['title']) . '</OrganizationName>' . DOKU_LF;
        echo '    <OrganizationDisplayName xml:lang="' . $conf['lang'] . '">' . hsc($conf['title']) . '</OrganizationDisplayName>' . DOKU_LF;
        echo '    <OrganizationURL xml:lang="' . $conf['lang'] . '">' . DOKU_URL . '</OrganizationURL>' . DOKU_LF;
        echo '  </Organization>' . DOKU_LF;
        echo '</EntityDescriptor>' . DOKU_LF;
        exit;
    }

}