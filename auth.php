<?php
/**
 * ADFS SAML authentication plugin
 *
 * @author     Andreas Gohr <gohr@cosmocode.de>
 */
class auth_plugin_adfs extends auth_plugin_authplain
{
    /** @var OneLogin_Saml2_Auth the SAML authentication library */
    protected $saml;

    /** @inheritdoc */
    public function __construct()
    {
        parent::__construct();

        $this->cando['external'] = true;
        $this->cando['logoff'] = true;
        /* We only want auth_plain for e-mail tracking and group storage */
        $this->cando['addUser'] = false;
        $this->cando['modLogin'] = false;
        $this->cando['modPass'] = false;
        $this->cando['modName'] = false;
        $this->cando['modMail'] = false;
        $this->cando['modGroups'] = false;

        /** @var helper_plugin_adfs $hlp */
        $hlp = plugin_load('helper', 'adfs');
        $this->saml = $hlp->getSamlLib();
    }

    /**
     * Checks the session to see if the user is already logged in
     *
     * If not logged in, redirects to SAML provider
     */
    public function trustExternal($user, $pass, $sticky = false)
    {
        global $USERINFO;
        global $ID;
        global $ACT;
        if (empty($ID)) $ID = getID();

        // trust session info, no need to recheck
        if (isset($_SESSION[DOKU_COOKIE]['auth']) &&
            $_SESSION[DOKU_COOKIE]['auth']['buid'] == auth_browseruid() &&
            isset($_SESSION[DOKU_COOKIE]['auth']['user'])
        ) {

            $_SERVER['REMOTE_USER'] = $_SESSION[DOKU_COOKIE]['auth']['user'];
            $USERINFO = $_SESSION[DOKU_COOKIE]['auth']['info'];

            return true;
        }

        if (!isset($_POST['SAMLResponse']) && ($ACT == 'login' || get_doku_pref('adfs_autologin', 0))) {
            // Initiate SAML auth request
            $url = $this->saml->login(
                null, // returnTo: is configured in our settings
                [], // parameter: we do not send any additional paramters to ADFS
                false, // forceAuthn: would skip any available SSO data, not what we want
                false, // isPassive: would avoid all user interaction, not what we want
                true, // stay: do not redirect, we do that ourselves
                false // setNamedIdPolicy: we need to disable this or ADFS complains about our request
            );
            $_SESSION['adfs_redirect'] = wl($ID, '', true, '&'); // remember current page
            send_redirect($url);
        } elseif (isset($_POST['SAMLResponse'])) {
            // consume SAML response
            try {
                $this->saml->processResponse();
                if ($this->saml->isAuthenticated()) {
                    // Always read the userid from the saml response
                    $USERINFO = $this->getUserDataFromResponse();
                    $_SERVER['REMOTE_USER'] = $USERINFO['user'];

                    if ($this->getConf('autoprovisioning')) {
                        // In case of auto-provisionning we override the local DB info with those retrieve during the SAML negociation

                        // First of all protect existing user from having its group beeing overriden in case group was not requested to the ADFS
                        if ($this->getConf('groups_attr_name') == "") {
                            $dbUserInfo = $this->getUserData($USERINFO['user']);
                            if(is_array($dbUserInfo) === true)
                            {
                                // Do not override group
                                $USERINFO['grps'] = $dbUserInfo["grps"];
                            }
                        }

                        if (
                            $this->triggerUserMod('modify', array(
                                $USERINFO['user'],
                                $USERINFO
                            )) === false
                        ) {
                            $this->triggerUserMod('create', array(
                                $USERINFO['user'],
                                "\0\0nil\0\0",
                                $USERINFO['name'],
                                $USERINFO['mail'],
                                $USERINFO['grps']
                            ));
                        }
                    } else {
                        // In case the autoprovisionning is disabled we rely on the local DB for the info such as the group and the fullname.
                        // It also means that the user should exists already in the DB
                        $dbUserInfo = $this->getUserData($USERINFO['user']);
                        if($dbUserInfo === false) throw new \Exception('This user is not in the local user database and may not login');
                        $USERINFO['name'] = $dbUserInfo["name"];
                        $USERINFO['mail'] = $dbUserInfo["mail"];
                        $USERINFO['grps'] = $dbUserInfo["grps"];
                    }

                    // Store that in the cookie
                    $_SESSION[DOKU_COOKIE]['auth']['user'] = $_SERVER['REMOTE_USER'];
                    $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
                    $_SESSION[DOKU_COOKIE]['auth']['buid'] = auth_browseruid(); // cache login

                    // successful login
                    if (isset($_SESSION['adfs_redirect'])) {
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

                    msg('ADFS: '.hsc($this->saml->getLastErrorReason()), -1);
                    return false;
                }
            } catch (Exception $e) {
                $this->logOff();
                msg('Invalid SAML response: ' . hsc($e->getMessage()), -1);
                return false;
            }
        }
        // no login happened
        return false;
    }


    /** @inheritdoc */
    public function logOff()
    {
        set_doku_pref('adfs_autologin', 0);
    }

    /** @inheritdoc */
    public function cleanUser($user)
    {
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
        if ($this->getConf('lowercase')) {
            return utf8_strtolower($user);
        } else {
            return $user;
        }
    }

    /** @inheritdoc */
    public function cleanGroup($group)
    {
        return $this->cleanUser($group);
    }


    /**
     * Build user data from the response
     *
     * @return array the user data
     * @throws Exception when attributes are missing
     */
    protected function getUserDataFromResponse()
    {
        global $conf;

        // which attributes should be in the response?
        $attributes = [
            'user' => $this->getConf('userid_attr_name')
        ];
        if ($this->getConf('autoprovisioning')) {
            $attributes['name'] = $this->getConf('fullname_attr_name');
            if (empty($attributes['name'])) $attributes['name'] = $attributes['user']; // fall back to login
            $attributes['mail'] = $this->getConf('email_attr_name');
            $attributes['grps'] = $this->getConf('groups_attr_name');
            if (empty($attributes['grps'])) unset($attributes['grps']); // groups are optional
        }

        // get attributes from response
        $userdata = ['user' => '', 'mail' => '', 'name' => '', 'grps' => []];
        foreach ($attributes as $key => $attr) {
            $data = $this->saml->getAttribute($attr);
            if ($data === null) throw new \Exception('SAML Response is missing attribute ' . $attr);
            $userdata[$key] = $data;
        }

        // clean up data
        $userdata['user'] = $this->cleanUser($userdata['user'][0]);
        $userdata['name'] = $userdata['name'][0];
        $userdata['mail'] = $userdata['mail'][0];
        $userdata['grps'] = (array)$userdata['grps'];
        $userdata['grps'][] = $conf['defaultgroup'];
        $userdata['grps'] = array_map([$this, 'cleanGroup'], $userdata['grps']);

        return $userdata;
    }
}
