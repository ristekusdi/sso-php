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

        // Validate token signature
        if (!isset($_SERVER['KEYCLOAK_REALM_PUBLIC_KEY']) || empty($_SERVER['KEYCLOAK_REALM_PUBLIC_KEY'])) {
            throw new \Exception('Please set KEYCLOAK_REALM_PUBLIC_KEY');
        }

        try {
            (new AccessToken($credentials))->validateSignatureWithKey($_SERVER['KEYCLOAK_REALM_PUBLIC_KEY']);
        } catch (\Throwable $th) {
            throw new \Exception($th->getMessage(), $th->getCode());
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
     * @throws Exception
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
            $credentials = (new SSOService)->refreshAccessToken($credentials);
            (new SSOService)->saveToken($credentials);
            $token = new AccessToken($credentials);
            $user = $token->parseAccessToken();
        }

        if (!isset($_SERVER['KEYCLOAK_REALM_PUBLIC_KEY']) || empty($_SERVER['KEYCLOAK_REALM_PUBLIC_KEY'])) {
            throw new \Exception('Please set KEYCLOAK_REALM_PUBLIC_KEY');
        }

        // We validate token signature here after new token is generated.
        // We do this because the token stored in PHP session, the token may expired early before validate and we cannot take advantage of refresh token case.
        try {
            (new AccessToken($credentials))->validateSignatureWithKey($_SERVER['KEYCLOAK_REALM_PUBLIC_KEY']);
        } catch (\Throwable $th) {
            throw new \Exception($th->getMessage(), $th->getCode());
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

    /**
     * Determine if the guard has a user instance.
     *
     * @return bool
     */
    public function hasUser()
    {
        if (!is_null($this->user) && $this->user instanceof \RistekUSDI\SSO\PHP\Models\User) {
            return true;
        }

        return false;
    }
}
