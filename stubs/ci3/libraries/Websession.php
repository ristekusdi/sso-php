<?php

class Websession {

    private $ci;

    public function __construct()
    {
        $ci =& get_instance();
        $this->ci = $ci;
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
    public function create($user)
    {
        $client_roles = $user->client_roles;

        // NOTE: You maybe want to get roles from your database by client_roles name
        // Alongside with permissions related with each role.
        // Here's is example of result.
        $roles = $this->ci->db->query("<PUT-YOUR-QUERY-HERE>", array($client_roles))->result();

        foreach ($roles as $key => $role) {
            $role_permissions = $this->ci->db->query("<PUT-YOUR-QUERY-HERE>", array($role->id))->result_array();

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

    public function changeRole()
    { 
        try {
            // Check if this session active? If not then redirect to login page.
            $this->ci->webguard->authenticated();

            $role = (object) json_decode($this->ci->input->post('role'), true);
            $unserialize_session = unserialize($_SESSION['serialize_session']);
            $unserialize_session['role'] = $role;

            $serialize_session = serialize($unserialize_session);
            $_SESSION['serialize_session'] = $serialize_session;

            return [
                'code' => 204,
                'message' => ''
            ];
        } catch (\Throwable $th) {
            return [
                'code' => 500,
                'message' => 'Error: Cannot change role.'
            ];
        }
    }

    /**
     * Change kv (key value)
     */
    public function changeKeyValue()
    { 
        try {
            // Check if this session active? If not then redirect to login page.
            $this->ci->webguard->authenticated();

            $value = $this->ci->input->post('value');
            $unserialize_session = unserialize($_SESSION['serialize_session']);
            $unserialize_session[$this->ci->input->post('key')] = $value;
            
            $serialize_session = serialize($unserialize_session);
            $_SESSION['serialize_session'] = $serialize_session;

            return [
                'code' => 204,
                'message' => ''
            ];
        } catch (\Throwable $th) {
            return [
                'code' => 500,
                'message' => 'Error: Cannot change key value.'
            ];
        }
    }
}