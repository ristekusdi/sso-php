<?php
defined('BASEPATH') OR exit('No direct script access allowed');

use RistekUSDI\SSO\PHP\Exceptions\CallbackException;
use RistekUSDI\SSO\PHP\Services\SSOService;
use RistekUSDI\SSO\PHP\Auth\Guard\WebGuard;
use RistekUSDI\SSO\PHP\Auth\AccessToken;

class Webauth extends CI_Controller {

    public function __construct()
    {
        parent::__construct();
        $this->CI =& get_instance();
        $this->load->helper('url');
    }

    public function login()
    {
        $sso = new SSOService;
        $url = $sso->getLoginUrl();
        $sso->saveState();

        return redirect($url);
    }

    public function logout()
    {
        $sso = new SSOService;
        $token = $sso->retrieveToken();
        $sso->forgetToken();

        $url = $sso->getLogoutUrl($token['id_token']);
        return redirect($url);
    }

    public function callback()
    {
        if (!empty($_GET['error'])) {
            $error = $_GET['error_description'];
            $error = !empty($error) ? $error : $_GET['error'];

            throw new CallbackException($error);
        }

        $state = $_GET['state'];
        if (empty($state) || ! (new SSOService())->validateState($state)) {
            (new SSOService())->forgetState();

            throw new CallbackException('Invalid state');
        }

        $code = $_GET['code'];
        if (!empty($code)) {
            $token = (new SSOService())->getAccessToken($code);

            try {
                (new WebGuard())->validate($token);

                $roles = (new WebGuard)->roles();

                $role_active = $roles[0];

                // TODO: Add permissions from role active.
                // You can get permissions from database maybe.
                // Return data in array
                $raw_role_permissions = [];

                $role_permissions = [];
                foreach ($raw_role_permissions as $raw_perm) {
                    $role_permissions[] = $raw_perm['perm_desc'];
                }

                // TODO: Maybe you want to add menus.
                $arr_menu = [];
                
                $serialize_session = serialize(array(
                    'roles' => $roles,
                    'role_active' => $role_active,
                    'role_permissions' => $role_permissions,
                    'arr_menu' => $arr_menu
                ));

                // PHP_SESSION_NONE if sessions are enabled, but none exists.
                // https://www.php.net/manual/en/function.session-status.php
                if (session_status() === PHP_SESSION_NONE) {
                    session_start();
                }

                $_SESSION['serialize_session'] = $serialize_session;

                redirect('/home');
            } catch (\Exception $e) {
                throw new CallbackException($e->getMessage(), $e->getCode());
            }
        }
    }

    /**
     * Change role active and get permissions changed role active
     */
    public function change_role_active()
    { 
        // Check if this session active? If not then redirect to login page.
        $this->webguard->authenticated();

        $role_active = $this->input->post('role_active');
        $unserialize_session = unserialize($_SESSION['serialize_session']);
        $unserialize_session['role_active'] = $role_active;

        // Role Permissions
        $raw_role_permissions = [];

        $role_permissions = [];
        foreach ($raw_role_permissions as $raw_perm) {
            $role_permissions[] = $raw_perm['perm_desc'];
        }

        $unserialize_session['role_permissions'] = $role_permissions;

        $serialize_session = serialize($unserialize_session);
        $_SESSION['serialize_session'] = $serialize_session;

        $arr = array(
            'submit' => '1',
            'link' => base_url('home')
        );

        header('Content-Type: application/json');
        echo json_encode($arr);
    }

    /**
     * Change key value (kv) active
     */
    public function change_kv_active()
    { 
        // Check if this session active? If not then redirect to login page.
        $this->webguard->authenticated();

        $value = $this->input->post('value');
        $unserialize_session = unserialize($_SESSION['serialize_session']);
        $unserialize_session[$this->input->post('key')] = $value;
        
        $serialize_session = serialize($unserialize_session);
        $_SESSION['serialize_session'] = $serialize_session;

        $arr = array(
            'submit' => '1',
            'link' => ""
        );

        header('Content-Type: application/json');
        echo json_encode($arr);
    }
}
