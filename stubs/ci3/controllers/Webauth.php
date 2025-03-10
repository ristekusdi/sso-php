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

        return redirect($url);
    }

    public function logout()
    {
        $sso = new SSOService;
        $url = $sso->getLogoutUrl();
        // NOTE: forgetToken must be after getLogoutUrl().
        // Otherwise the logout form will show error message: id_token_hint not found!
        $sso->forgetToken();
        return redirect($url);
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

                redirect('home', 'location', 301);
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

            redirect('home', 'location', 301);
        } catch (\Throwable $th) {
            echo "Status code: {$th->getCode()} \n";
            echo "Error message: {$th->getMessage()}\n";
            die();
        }
    }

    /**
     * You may be create a session to get roles and permission that belongs to each role.
     * After user logged in, they may have list of roles based on a client (app) that stored in client_roles property.
     * Use "client_roles" property as parameter to get roles and permissions in your app database.
     * Expected result is a serialize of array that store in a session called serialize session.
     * The array contains:
     * - roles (list of roles with permissions belongs to each role)
     * - role (active or current role)
     */
    private function createSession()
    {
        $client_roles = (new WebGuard)->user()->client_roles;

        $roles = $this->db->query("SELECT role_id AS id, role_name as `name` FROM rbac_roles
        WHERE rbac_roles.role_name IN ?", array($client_roles))->result();

        foreach ($roles as $key => $role) {
            $role_permissions = $this->db->query("SELECT rbac_permissions.perm_desc 
            FROM rbac_permissions
            INNER JOIN rbac_role_perm ON rbac_role_perm.perm_id = rbac_permissions.perm_id
            WHERE rbac_role_perm.`role_id` = ?", array($role->id))->result_array();

            $roles[$key]->permissions = array_column($role_permissions, 'perm_desc');
        }

        // NOTE: You maybe want to get roles from your database by using $client_roles
        // and put permissions to each role.
        // Here's is the expected result.
        // $roles = json_decode(json_encode([
        //     [
        //         'id' => 1,
        //         'name' => 'Operator',
        //         'permissions' => [
        //             'user:view',
        //             'user:edit',
        //         ]
        //     ],
        //     [
        //         'id' => 2,
        //         'name' => 'User',
        //         'permissions' => [
        //             'profile:view',
        //             'profile:edit',
        //         ]
        //     ],
        // ]));
        
        $_SESSION['serialize_session'] = serialize(array(
            'roles' => $roles,
            'role' => $roles[0], // This is a active or current role
        ));       
    }

    /**
     * Change current role
     */
    public function changeRole()
    { 
        // Check if this session active? If not then redirect to login page.
        $this->webguard->authenticated();

        $role = $this->input->post('role');
        $unserialize_session = unserialize($_SESSION['serialize_session']);
        $unserialize_session['role'] = $role;

        $serialize_session = serialize($unserialize_session);
        $_SESSION['serialize_session'] = $serialize_session;

        http_response_code(204);
        header('Content-Type: application/json');
    }

    /**
     * Change kv (key value)
     */
    public function changeKeyValue()
    { 
        // Check if this session active? If not then redirect to login page.
        $this->webguard->authenticated();

        $value = $this->input->post('value');
        $unserialize_session = unserialize($_SESSION['serialize_session']);
        $unserialize_session[$this->input->post('key')] = $value;
        
        $serialize_session = serialize($unserialize_session);
        $_SESSION['serialize_session'] = $serialize_session;

        http_response_code(204);
        header('Content-Type: application/json');
    }
}
