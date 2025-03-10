<?php

use RistekUSDI\SSO\PHP\Services\SSOService;
use RistekUSDI\SSO\PHP\Auth\Guard\WebGuard;

class Webauth
{
    public function login()
    {
        $sso = new SSOService;
        $url = $sso->getLoginUrl();
        $sso->saveState();
    
        header('Location: ', $url);
        exit();
    }
    
    public function logout()
    {
        $sso = new SSOService;
        $url = $sso->getLogoutUrl();
        // NOTE: forgetToken must be after getLogoutUrl().
        // Otherwise the logout form will show error message: id_token_hint not found!
        $sso->forgetToken();
        header('Location: ', $url);
        exit();
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
                $this->createSession();

                // Change redirect based on your need!
                header('Location: dashboard.php');
                exit();
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

            redirect('/home');
        } catch (\Throwable $th) {
            echo "Status code: {$th->getCode()} \n";
            echo "Error message: {$th->getMessage()}\n";
            die();
        }
    }

    private function createSession()
    {
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
    }
}