<?php

namespace RistekUSDI\SSO\PHP\Auth\Guard;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use RistekUSDI\SSO\PHP\Services\SSOService;
use RistekUSDI\SSO\PHP\Auth\WebUserProvider;
use RistekUSDI\SSO\PHP\Auth\AccessToken;

class WebGuard implements Guard
{
    protected $user;

    public function __construct() {
        $this->user = $this->user();
    }

    public function check()
    {
        return (bool) $this->user;
    }

    public function guest()
    {
        return ! $this->check();
    }

    public function user()
    {
        if (empty($this->user)) {
            $this->authenticate();
        }

        return $this->user;
    }

    public function id()
    {
        $user = $this->user();
        return $user->id ?? null;
    }

    public function validate(array $credentials = [])
    {
        if (empty($credentials['access_token']) || empty($credentials['id_token'])) {
            throw new \Exception('Credentials must have access_token and id_token!');
        }

        $token = new AccessToken($credentials);
        if (empty($token->getAccessToken())) {
            throw new \Exception('Access Token is invalid.');
        }

        /**
         * If user doesn't have access to certain client app then throw exception
         */
        $access_token = $token->parseAccessToken();
        if (!in_array($_SERVER['KEYCLOAK_CLIENT_ID'], array_keys($access_token['resource_access']))) {
            throw new \Exception('Unauthorized', 403);
        }

        $token->validateIdToken((new SSOService)->getClaims());

        /**
         * Store the section
         */
        $credentials['refresh_token'] = $credentials['refresh_token'] ?? '';
        (new SSOService)->saveToken($credentials);

        return $this->authenticate();
    }

    /**
     * Try to authenticate the user
     *
     * @throws CallbackException
     * @return null
     */
    public function authenticate()
    {
        // Get Credentials
        $credentials = (new SSOService)->retrieveToken();
        if (empty($credentials)) {
            return null;
        }

        $token = new AccessToken($credentials);
        $user = $token->parseAccessToken();
        
        if ($token->hasExpired()) {
            // NOTE: User needs to log in again in case refresh token has expired.
            if (time() >= $token->getRefreshTokenExpiresAt()) {
                return null;
            }
            (new SSOService)->forgetToken();
            $updated_credentials = (new SSOService)->refreshAccessToken($credentials);
            (new SSOService)->saveToken($updated_credentials);
            $token = new AccessToken($updated_credentials);
            $user = $token->parseAccessToken();
        }

        // Get client roles
        $roles = ['roles' => []];
        $roles = (new AccessToken($credentials))->parseAccessToken()['resource_access'][$_SERVER['KEYCLOAK_CLIENT_ID']];
        
        $user = array_merge($user, ['client_roles' => $roles['roles']]);

        $provider = new WebUserProvider((new \ReflectionClass('RistekUSDI\SSO\PHP\Models\User'))->getName());
        $user = $provider->retrieveByCredentials($user);
        $this->setUser($user);
    }

    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
        return $this;
    }
}
