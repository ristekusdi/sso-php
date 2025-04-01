<?php

use RistekUSDI\SSO\PHP\Auth\Guard\WebGuard as Guard;

class Webguard {

    private $user;
    private $ci;

    public function __construct()
    {
        $ci =& get_instance();
        $this->ci = $ci;
        $this->user = (new Guard)->user();
    }

    /**
     * Redirect to url auth/login if not authenticated
     */
    public function authenticated()
    {
        if (! $this->check()) {
            header('HTTP/1.1 301 Moved Permanently');
            header('Location: ' . site_url('/sso/login'));
            exit;
        }
    }

    /**
     * Allow user to access the resources
     * As long as user is instance of \RistekUSDI\SSO\PHP\Models\User and is not null.
     * 
     * @return boolean
     */
    public function check()
    {
        return (new Guard())->hasUser();
    }

    public function guest()
    {
        return (new Guard())->guest();
    }

    public function user()
    {
        if (!isset($_SESSION['serialize_session'])) {
            $this->ci->websession->create((new Guard())->user());
        }
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
    
    public function hasRole($roles)
    {
        $result = empty(array_diff((array) $roles, $this->user()->get()->roles));        
        $this->user->hasRole = $result;
        return $this->user->hasRole;
    }

    public function hasPermission($permissions)
    {
        $result = !empty(array_intersect((array) $permissions, $this->user->role->permissions));
        $this->user->hasPermission = $result;
        return $this->user->hasPermission;
    }
    
    public function restrictAjaxLogin()
    {
        if (!$this->check()) {
            $response['submit'] = 403;
            $response['error'] = 'Your session has been expired, please login again';
            header('Content-Type: application/json; charset=utf-8');
            http_response_code(403);
            echo json_encode($response);
            exit();
        }
        return TRUE;
    }

    public function restrictAjaxDatatable()
    {
        if (! $this->check()) {
            $response = '{
                "iTotalRecords": 0,
                "iTotalDisplayRecords": 0,
                "aaData": [],
                "submit":403,
                "error":"Your session has been expired, please login again"
            }';
            echo $response;
            exit();
        }
        return true;
    }
}
