<?php

namespace RistekUSDI\SSO\Auth\Guard;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use RistekUSDI\SSO\Services\SSOService;
use RistekUSDI\SSO\Auth\WebUserProvider;
use RistekUSDI\SSO\Auth\AccessToken;

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
        if (!in_array($_ENV['SSO_CLIENT_ID'], array_keys($access_token['resource_access']))) {
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
     * @return boolean
     */
    public function authenticate()
    {
        // Get Credentials
        $credentials = (new SSOService)->retrieveToken();
        if (empty($credentials)) {
            return false;
        }

        $user = (new SSOService)->getUserProfile($credentials);
        if (empty($user)) {
            (new SSOService)->forgetToken();
            return false;
        }

        $provider = new WebUserProvider((new \ReflectionClass('RistekUSDI\SSO\Models\User'))->getName());
        $user = $provider->retrieveByCredentials($user);
        $this->setUser($user);

        return true;
    }

    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
    }

    public function permissions()
    {
        if (! $this->check()) {
            return [];
        }

        return (new SSOService)->permissions();
    }

     /**
     * Check user is authenticated and has a permission(s)
     *
     * @param array|string $scopes
     *
     * @return boolean
     */
    public function hasPermission($permissions)
    {
        return !empty(array_intersect((array) $permissions, $this->permissions()));
    }

    public function roles()
    {
        if (!$this->check()) {
            return false;
        }

        return $this->user()->roles;
    }

    /**
     * Check user is authenticated and has a role
     *
     * @param array|string $roles
     * @param string $resource Default is empty: point to client_id
     *
     * @return boolean
     */
    public function hasRole($roles)
    {
        if (!$this->check()) {
            return false;
        }

        return empty(array_diff((array) $roles, $this->roles()));
    }
}
