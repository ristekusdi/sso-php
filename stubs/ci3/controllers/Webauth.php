<?php
defined('BASEPATH') OR exit('No direct script access allowed');

use RistekUSDI\SSO\PHP\Services\SSOService;
use RistekUSDI\SSO\PHP\Auth\Guard\WebGuard;

class Webauth extends CI_Controller {

    public function __construct()
    {
        parent::__construct();
        $this->load->helper('url');
        $this->load->library('session');
    }

    public function login()
    {
        $sso = new SSOService;
        $url = $sso->getLoginUrl();
        $sso->saveState();

        header('HTTP/1.1 302 Found');
        header('Location: ' . $url);
        exit;
    }

    public function logout()
    {
        $sso = new SSOService;
        $url = $sso->getLogoutUrl();
        // NOTE: forgetToken must be after getLogoutUrl().
        // Otherwise the logout form will show error message: id_token_hint not found!
        $sso->forgetToken();

        header('HTTP/1.1 302 Found');
        header('Location: ' . $url);
        exit;
    }

    public function callback()
    {
        if (!empty($_GET['error'])) {
            $error = $_GET['error_description'];
            $error = !empty($error) ? $error : $_GET['error'];

            echo "SSO Service error: {$error} with HTTP code response 401";
            exit();
        }

        $state = $_GET['state'];
        if (empty($state) || ! (new SSOService())->validateState($state)) {
            (new SSOService())->forgetState();

            echo "SSO Service error: Invalid state with HTTP code response 401";
            exit();
        }

        $code = $_GET['code'];
        if (!empty($code)) {
            $token = (new SSOService())->getAccessToken($code);

            try {
                (new WebGuard())->validate($token);

                // You may need to create a custom session for your internal app
                $this->websession->create((new WebGuard)->user());

                header('HTTP/1.1 301 Moved Permanently');
                header('Location: ' . site_url('/home'));
                exit;
            } catch (\Exception $e) {
                echo "SSO Service error: {$e->getMessage()} with HTTP code response {$e->getCode()}";
                exit();
            }
        }
    }

    public function impersonate()
    {
        $username = $this->input->post('username');
        $credentials = (new SSOService())->retrieveToken();
        try {
            $token = (new SSOService())->impersonate($credentials, $username);

            if (empty($token)) {
                throw new Exception("User with username {$username} not found!", 404);
            }
            
            (new WebGuard())->validate($token);

            $this->createSession();

            header('HTTP/1.1 301 Moved Permanently');
            header('Location: ' . site_url('/home'));
            exit;
        } catch (\Throwable $th) {
            echo "Status code: {$th->getCode()} \n";
            echo "Error message: {$th->getMessage()}\n";
            die();
        }
    }

    public function changeRole()
    { 
        // Check if this session active? If not then redirect to login page.
        $this->webguard->authenticated();

        $response = $this->websession->changeRole();

        http_response_code($response['code']);
        header('Content-Type: application/json');
    }

    /**
     * Change kv (key value)
     */
    public function changeKeyValue()
    { 
        // Check if this session active? If not then redirect to login page.
        $this->webguard->authenticated();

        $response = $this->websession->changeKeyValue();

        http_response_code($response['code']);
        header('Content-Type: application/json');
    }
}
