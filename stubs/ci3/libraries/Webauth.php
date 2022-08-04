<?php

use RistekUSDI\SSO\Exceptions\CallbackException;
use RistekUSDI\SSO\Services\SSOService;
use RistekUSDI\SSO\Auth\Guard\WebGuard;
use RistekUSDI\SSO\Auth\AccessToken;

class Webauth {

    private $user;

    public function __construct()
    {
        $this->user = (new WebGuard)->user();
    }

    /**
     * Redirect to url auth/login if not authenticated
     */
    public function authenticated()
    {
        if (! $this->check()) {
            redirect('/sso/login');
        }
    }

    public function check()
    {
        return (new WebGuard())->check();
    }

    public function guest()
    {
        return (new WebGuard())->guest();
    }

    public function user()
    {
        $unserialize_session = unserialize($_SESSION['serialize_session']);
        $this->user->role_active = $unserialize_session['role_active'];
        $this->user->role_permissions = $unserialize_session['role_permissions'];
        $this->user->arr_menu = $unserialize_session['arr_menu'];
        return $this;
    }

    public function get()
    {
        return $this->user;
    }

    public function roles()
    {
        $unserialize_session = unserialize($_SESSION['serialize_session']);
        $this->user->roles = $unserialize_session['roles'];
        return $this->user->roles;
    }
    
    public function hasRole($roles)
    {
        $result = empty(array_diff((array) $roles, $this->roles()));        
        $this->user->hasRole = $result;
        return $this->user->hasRole;
    }

    public function hasPermission($permissions)
    {
        $result = !empty(array_intersect((array) $permissions, $this->user->role_permissions));
        $this->user->hasPermission = $result;
        return $this->user->hasPermission;
    }
}
