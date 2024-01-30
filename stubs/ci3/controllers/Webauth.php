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
        $url = $sso->getLogoutUrl();
        return redirect($url);
    }

    public function callback()
    {
        if (!empty($_GET['error'])) {
            $error = $_GET['error_description'];
            $error = !empty($error) ? $error : $_GET['error'];

            throw new CallbackException(401, $error);
        }

        $state = $_GET['state'];
        if (empty($state) || ! (new SSOService())->validateState($state)) {
            (new SSOService())->forgetState();

            throw new CallbackException(401, 'Invalid state');
        }

        $code = $_GET['code'];
        if (!empty($code)) {
            $token = (new SSOService())->getAccessToken($code);

            try {
                (new WebGuard())->validate($token);

                $client_roles = (new WebGuard)->user()->client_roles;

                // NOTE: You maybe want to get roles from your database by using $client_roles
                // and put permissions to each role.
                // Here's is example of result.
                $roles = json_decode(json_encode([
                    [
                        'id' => 1,
                        'name' => 'Operator',
                        'permissions' => [
                            'user:view',
                            'user:edit',
                        ]
                    ],
                    [
                        'id' => 2,
                        'name' => 'User',
                        'permissions' => [
                            'profile:view',
                            'profile:edit',
                        ]
                    ],
                ]));
                
                $serialize_session = serialize(array(
                    'roles' => $roles,
                    'role' => $roles[0],
                ));

                // PHP_SESSION_NONE if sessions are enabled, but none exists.
                // https://www.php.net/manual/en/function.session-status.php
                if (session_status() === PHP_SESSION_NONE) {
                    session_start();
                }

                $_SESSION['serialize_session'] = $serialize_session;

                redirect('/home');
            } catch (\Exception $e) {
                throw new CallbackException($e->getCode(), $e->getMessage());
            }
        }
    }

    /**
     * Change current role
     */
    public function change_current_role()
    { 
        // Check if this session active? If not then redirect to login page.
        $this->webguard->authenticated();

        $role = $this->input->post('role');
        $unserialize_session = unserialize($_SESSION['serialize_session']);
        $unserialize_session['role'] = $role;

        $serialize_session = serialize($unserialize_session);
        $_SESSION['serialize_session'] = $serialize_session;

        http_response_code(200);
        header('Content-Type: application/json');
        echo json_encode([
            'link' => base_url('home')
        ]);
    }

    /**
     * Change kv (key value)
     */
    public function change_kv()
    { 
        // Check if this session active? If not then redirect to login page.
        $this->webguard->authenticated();

        $value = $this->input->post('value');
        $unserialize_session = unserialize($_SESSION['serialize_session']);
        $unserialize_session[$this->input->post('key')] = $value;
        
        $serialize_session = serialize($unserialize_session);
        $_SESSION['serialize_session'] = $serialize_session;

        http_response_code(200);
        header('Content-Type: application/json');
        echo json_encode([
            'link' => ''
        ]);
    }
}
