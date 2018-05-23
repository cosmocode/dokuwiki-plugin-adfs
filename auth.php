<?php
/**
 * ADFS SAML authentication plugin
 *
 * @author     Andreas Gohr <gohr@cosmocode.de>
 */

require_once __DIR__ . '/phpsaml/onelogin/saml.php';
require_once DOKU_PLUGIN . '/authplain/auth.php';

class auth_plugin_adfs extends auth_plugin_authplain {
    /** @var \SamlSettings */
    protected $settings;

    public function __construct() {
        parent::__construct();

        $this->cando['external'] = true;
        $this->cando['logoff']   = true;
        /* We only want auth_plain for e-mail tracking and group storage */
        $this->cando['addUser']   = false;
        $this->cando['modLogin']  = false;
        $this->cando['modPass']   = false;
        $this->cando['modName']   = false;
        $this->cando['modMail']   = false;
        $this->cando['modGroups'] = false;

        $cert = $this->getConf('certificate');
        $cert = wordwrap($cert, 65, "\n", true);
        $cert = trim($cert);
        if(!preg_match('/^-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----$/s', $cert)) {
            $cert = "-----BEGIN CERTIFICATE-----\n$cert\n-----END CERTIFICATE-----";
        }

        // prepare settings object
        $this->settings                                 = new SamlSettings();
        $this->settings->idp_sso_target_url             = $this->getConf('endpoint');
        $this->settings->x509certificate                = $cert;
        $this->settings->assertion_consumer_service_url = DOKU_URL . DOKU_SCRIPT;
        $this->settings->issuer                         = DOKU_URL;
        $this->settings->name_identifier_format         = null;

    }

    /**
     * Checks the session to see if the user is already logged in
     *
     * If not logged in, redirects to SAML provider
     */
    public function trustExternal($user, $pass, $sticky = false) {
        global $USERINFO;
        global $ID;
        global $ACT;
        global $conf;

        if(empty($ID)) $ID = getID();

        // trust session info, no need to recheck
        if(isset($_SESSION[DOKU_COOKIE]['auth']) &&
            $_SESSION[DOKU_COOKIE]['auth']['buid'] == auth_browseruid() &&
            isset($_SESSION[DOKU_COOKIE]['auth']['user'])
        ) {

            $_SERVER['REMOTE_USER'] = $_SESSION[DOKU_COOKIE]['auth']['user'];
            $USERINFO               = $_SESSION[DOKU_COOKIE]['auth']['info'];

            return true;
        }

        if(!isset($_POST['SAMLResponse']) && ($ACT == 'login' || get_doku_pref('adfs_autologin', 0))) {
            // Initiate SAML auth request
            $authrequest               = new SamlAuthRequest($this->settings);
            $url                       = $authrequest->create();
            $_SESSION['adfs_redirect'] = wl($ID, '', true, '&'); // remember current page
            send_redirect($url);
        } elseif(isset($_POST['SAMLResponse'])) {
            // consume SAML response
            $samlresponse = new SamlResponse($this->settings, $_POST['SAMLResponse']);
            try {
                if($samlresponse->is_valid()) {
                    // Always read the userid from the saml response
                    $_SERVER['REMOTE_USER'] = $samlresponse->get_attribute($this->getConf('userid_attr_name'));
                    $USERINFO['user'] = $_SERVER['REMOTE_USER'];

                    if($this->getConf('autoprovisioning')){
                        // In case of auto-provisionning we override the local DB info with those retrieve during the SAML negociation
                        $USERINFO['name'] = $samlresponse->get_attribute($this->getConf('fullname_attr_name'));
                        $USERINFO['mail'] = $samlresponse->get_attribute($this->getConf('email_attr_name'));
                        $USERINFO['grps'] = array();
                        if($this->getConf('groups_attr_name') != "")
                            $USERINFO['grps'] = (array) $samlresponse->get_attribute($this->getConf('groups_attr_name'));
                        $USERINFO['grps'][] = $conf['defaultgroup'];
                        $USERINFO['grps'] = array_map(array(
                                $this,
                                'cleanGroup'
                        ), $USERINFO['grps']);

                        // cache user data
                        $changes = array(
                                'user'=>$USERINFO['user'],
                                'name'=>$USERINFO['name'],
                                'mail'=>$USERINFO['mail'],
                                'grps'=>$USERINFO['grps']
                        );

                        if($this->triggerUserMod('modify', array(
                                $USERINFO['user'],
                                $changes
                        )) === false){
                            $this->triggerUserMod('create', array(
                                    $USERINFO['user'],
                                    "\0\0nil\0\0",
                                    $USERINFO['name'],
                                    $USERINFO['mail'],
                                    $USERINFO['grps']
                            ));
                        }
                    }else{
                        // In case the autoprovisionning is disabled we rely on the local DB for the info such as the group and the fullname.
                        // It also means that the user should exists already in the DB
                        $dbUserInfo = $this->getUserData($USERINFO['user']);
                        $USERINFO['name'] = $dbUserInfo["name"];
                        $USERINFO['mail'] = $dbUserInfo["mail"];
                        $USERINFO['grps'] = $dbUserInfo["grps"];
                    }

                    // Store that in the cookie
                    $_SESSION[DOKU_COOKIE]['auth']['user'] = $_SERVER['REMOTE_USER'];
                    $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
                    $_SESSION[DOKU_COOKIE]['auth']['buid'] = auth_browseruid(); // cache login

                    // successful login
                    if(isset($_SESSION['adfs_redirect'])) {
                        $go = $_SESSION['adfs_redirect'];
                        unset($_SESSION['adfs_redirect']);
                    } else {
                        $go = wl($ID, '', true, '&');
                    }
                    set_doku_pref('adfs_autologin', 1);
                    send_redirect($go); // decouple the history from POST
                    return true;
                } else {
                    $this->logOff();
                    msg('The SAML response signature was invalid.', -1);
                    return false;
                }
            } catch(Exception $e) {
                $this->logOff();
                msg('Invalid SAML response: ' . hsc($e->getMessage()), -1);
                return false;
            }
        }
        // no login happened
        return false;
    }



    /** @inheritdoc */
    public function logOff() {
        set_doku_pref('adfs_autologin', 0);
    }

    /** @inheritdoc */
    public function cleanUser($user) {
        // strip disallowed characters
        $user = strtr(
            $user, array(
                     ',' => '',
                     '/' => '',
                     '#' => '',
                     ';' => '',
                     ':' => ''
                 )
        );
        if($this->getConf('lowercase')) {
            return utf8_strtolower($user);
        } else {
            return $user;
        }
    }

    /** @inheritdoc */
    public function cleanGroup($group) {
        return $this->cleanUser($group);
    }
}
