<?php

use RistekUSDI\SSO\PHP\Exceptions\CallbackException;
use RistekUSDI\SSO\PHP\Services\SSOService;
use RistekUSDI\SSO\PHP\Auth\Guard\WebGuard as Guard;
use RistekUSDI\SSO\PHP\Auth\AccessToken;

class Webguard {

    private $user;

    public function __construct()
    {
        $this->user = (new Guard)->user();
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
        return (new Guard())->check();
    }

    public function guest()
    {
        return (new Guard())->guest();
    }

    public function user()
    {
        $unserialize_session = unserialize($_SESSION['serialize_session']);
        foreach ($unserialize_session as $key => $value) {
            $this->user->{$key} = $value;
        }
        return $this;
    }

    public function get()
    {
        return $this->user;
    }
    
    /**
     * Check if user has specific role
     * @return boolean
     */
    public function hasRole($role)
    {
        $result = false;
        $roles_attr = $this->user->roles;
        $role_names = array_column($roles_attr, 'name');
        if (is_array($role)) {
            $roles = $role;
            $result = !empty(array_intersect($role_names , (array) $roles));
        } else {
            $result = in_array($role, $role_names) ? true : false;
        }

        $this->user->hasRole = $result;
        return $this->user->hasRole;
    }

    /**
     * Check if user has permission(s) from specific role
     * @return boolean
     */
    public function hasPermission($permission)
    {
        $result = false;
        $role_permissions = [];
        if (isset($this->user->role->permissions)) {
            foreach ($this->user->role->permissions as $perm) {
                array_push($role_permissions, $perm);
            }
        }
        
        if (is_array($permission)) {
            $permissions = $permission;

            $result = !empty(array_intersect((array) $role_permissions, (array) $permissions));
        } else {
            $result = in_array($permission, $role_permissions) ? true : false;
        }

        $this->user->hasPermission = $result;
        return $this->user->hasPermission;
    }
}
