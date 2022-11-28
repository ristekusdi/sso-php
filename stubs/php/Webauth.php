<?php

use RistekUSDI\SSO\PHP\Exceptions\CallbackException;
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
        header('Location: ', $url);
        exit();
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
                // Ganti arah redirect sesuai kebutuhan
                header('Location: dashboard.php');
                exit();
            } catch (\Exception $e) {
                throw new CallbackException($e->getCode(), $e->getMessage());
            }
        }
    }   
}