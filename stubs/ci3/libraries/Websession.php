<?php

class Websession {

    private $ci;

    public function __construct()
    {
        $ci =& get_instance();
        $this->ci = $ci;
    }
    
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

        $role = $roles[0];
        
        $serialize_session = serialize(array(
            'roles' => $roles,
            'role' => $role,
            // NOTE: You may add additional key and value here.
            // Example: Your web app may have feature to display data based on selected or active year
            'selected_year' => date('Y'),
        ));

        $_SESSION['serialize_session'] = $serialize_session;
    }
}