<?php

namespace RistekUSDI\SSO\PHP\Services;

use RistekUSDI\SSO\PHP\Auth\AccessToken;

trait SSOServiceTrait {
    /**
     * The Session key for token
     */
    protected $sso_session = '_sso_token';
    protected $sso_session_impersonate = '_sso_token_impersonate';

    /**
     * The Session key for state
     */
    protected $sso_state = '_sso_state';

    protected function logError($message)
    {
        error_log("SSO Service error: {$message}");
    }

    /**
     * Save Token to Session
     *
     * @return void
     */
    protected function saveToken($credentials)
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $decoded_access_token = (new AccessToken($credentials))->parseAccessToken();
        if (isset($decoded_access_token['impersonator'])) {
            $_SESSION[$this->sso_session_impersonate] = $credentials;
        } else {
            $previous_credentials = $this->retrieveRegularToken();
            // Forget impersonate token session
            // Just in case if impersonate user session revoked even session are not expired
            // Example: impersonate user session revoked from Keycloak Administration console.
            if (!is_null($previous_credentials)) {
                $this->forgetImpersonateToken();
            }
            $_SESSION[$this->sso_session] = $credentials;
        }
    }
    
    /**
     * Retrieve Token from Session
     *
     * @return array|null
     */
    protected function retrieveToken()
    {
        if (isset($_SESSION[$this->sso_session_impersonate])) {
            return $_SESSION[$this->sso_session_impersonate];
        } else if (isset($_SESSION[$this->sso_session])) {
            return $_SESSION[$this->sso_session];
        } else {
            return '';
        }
    }

    /**
     * Remove Token from Session
     *
     * @return void
     */
    protected function forgetToken()
    {
        // Remove all session variables.
        if (isset($_SESSION[$this->sso_session_impersonate])) {
            $this->forgetImpersonateToken();
        } else if (isset($_SESSION[$this->sso_session]))  {
            unset($_SESSION[$this->sso_session]);
        }
        
        // Destroy the session
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }

    protected function retrieveRegularToken()
    {
        return isset($_SESSION[$this->sso_session]) ? $_SESSION[$this->sso_session] : '';
    }

    protected function retrieveImpersonateToken()
    {
        return isset($_SESSION[$this->sso_session_impersonate]) ? $_SESSION[$this->sso_session_impersonate] : '';
    }

     /**
     * Remove Impersonate Token from Session
     *
     * @return void
     */
    protected function forgetImpersonateToken()
    {
        unset($_SESSION[$this->sso_session_impersonate]);
    }

    /**
     * Validate State from Session
     *
     * @return void
     */
    protected function validateState($state)
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $challenge = $_SESSION[$this->sso_state];
        return (! empty($state) && ! empty($challenge) && $challenge === $state);
    }

    /**
     * Save State to Session
     *
     * @return void
     */
    protected function saveState()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $_SESSION[$this->sso_state] = $this->state;
    }

    /**
     * Remove State from Session
     *
     * @return void
     */
    protected function forgetState()
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            // Remove all session variables.
            session_unset();
            
            // Destroy the session
            session_destroy();
        }
    }
}