---
title: Konfigurasi CodeIgniter 3.x - SSO PHP - RistekUSDI
description: Konfigurasi Pustaka ristekusdi/sso-php Pada CodeIgniter 3.x
extends: _layouts.documentation
section: content
---

# Konfigurasi CodeIgniter 3.x

1. Isi nilai dari variable `$config['base_url']` di file `application/config/config.php`.

2. Isi nilai dari variable `$config['composer_autoload'] = "./vendor/autoload.php"` di file `application/config/config.php`. Artinya proyek ini akan melakukan autoload composer di direktor `vendor` pada root project.

3. Isi nilai dari variable `$config['enable_hooks'] = TRUE`  di file `application/config/config.php`. Ini digunakan untuk mengaktifkan hooks pada file `application/config/hooks.php`.

4. Untuk mengambil nilai dari file `.env` dengan perintah `$_ENV['nama_key']`, masukkan sintaks berikut di dalam file `application/config/hooks.php`.

```php
$hook['pre_system'] = function () {
    $dotenv = Dotenv\Dotenv::createImmutable(FCPATH);
    $dotenv->load();
};
```

5. Buat sebuah file bernama `Webauth.php` di direktori `application/libraries`. Kemudian, masukkan sintaks di bawah ini ke file tersebut.

```php
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
            redirect('/auth/login');
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
```

**Catatan:**

Berikut ini perintah-perintah yang umumnya digunakan untuk autentikasi:

- `$this->webauth->user()->get()` untuk mendapatkan data pengguna, `role_active`, `role_permissions` (permissions dari role active), `arr_menu`.
- `$this->webauth->user()->roles()` untuk mendapatkan data roles yang melekat pada pengguna.
- `$this->webauth->user()->hasRole($role)` untuk mengecek apakah pengguna memiliki role tertentu atau tidak (role bisa lebih dari 1 dengan format array) dan mengembalikan nilai bertipe boolean.
- `$this->webauth->user()->hasPermission($permission)` untuk mengecek apakah pengguna memiliki permission tertentu atau tidak (permission bisa lebih dari 1 dengan format array) dan mengembalikan nilai booelan.

6. Buat sebuah file bernama `Xauth.php` di direktori `application/controllers`. Masukkan sintaks di bawah ini ke file tersebut.

```php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

use RistekUSDI\SSO\Exceptions\CallbackException;
use RistekUSDI\SSO\Services\SSOService;
use RistekUSDI\SSO\Auth\Guard\WebGuard;
use RistekUSDI\SSO\Auth\AccessToken;

class Xauth extends CI_Controller {

    public function __construct()
    {
        parent::__construct();
        $this->load->helper('url');
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
        $sso->forgetToken();

        $url = $sso->getLogoutUrl();
        return redirect($url);
    }

    public function callback()
    {
        if (!empty($_GET['error'])) {
            $error = $_GET['error_description'];
            $error = !empty($error) ? $error : $_GET['error'];

            throw new CallbackException($error);
        }

        $state = $_GET['state'];
        if (empty($state) || ! (new SSOService())->validateState($state)) {
            (new SSOService())->forgetState();

            throw new CallbackException('Invalid state');
        }

        $code = $_GET['code'];
        if (!empty($code)) {
            $token = (new SSOService())->getAccessToken($code);

            if ((new WebGuard())->validate($token)) {
                $roles = (new WebGuard)->roles();

                $role_active = $roles[0];

                // TODO: Add permissions from role active.
                // You can get permissions from database maybe.
                // Return data in array
                $raw_role_permissions = [];

                $role_permissions = [];
                foreach ($raw_role_permissions as $raw_perm) {
                    $role_permissions[] = $raw_perm['perm_desc'];
                }

                // TODO: Maybe you want to add menus.
                $arr_menu = [];
                
                $serialize_session = serialize(array(
                    'roles' => $roles,
                    'role_active' => $role_active,
                    'role_permissions' => $role_permissions,
                    'arr_menu' => $arr_menu
                ));

                // PHP_SESSION_NONE if sessions are enabled, but none exists.
                // https://www.php.net/manual/en/function.session-status.php
                if (session_status() === PHP_SESSION_NONE) {
                    session_start();
                }

                $_SESSION['serialize_session'] = $serialize_session;

                redirect('/home');
            } else {
                throw new CallbackException('Forbidden access');
            }
        }
    }

    /**
     * Change role active and get permissions changed role active
     */
    public function change_role_active()
    { 
        // Check if this session active? If not then redirect to login page.
        $this->webauth->authenticated();

        $role_active = $this->input->post('role_active');
        $unserialize_session = unserialize($_SESSION['serialize_session']);
        $unserialize_session['role_active'] = $role_active;

        // Role Permissions
        $raw_role_permissions = [];

        $role_permissions = [];
        foreach ($raw_role_permissions as $raw_perm) {
            $role_permissions[] = $raw_perm['perm_desc'];
        }

        $unserialize_session['role_permissions'] = $role_permissions;

        $serialize_session = serialize($unserialize_session);
        $_SESSION['serialize_session'] = $serialize_session;

        $arr = array(
            'submit' => '1',
            'link' => base_url('home')
        );

        header('Content-Type: application/json');
        echo json_encode($arr);
    }
}
```

7. Masukkan sintaks di bawah ini ke dalam `application/config/routes.php`. Hal ini digunakan sebagai routing autentikasi.

```php
$route['auth/login'] = 'xauth/login';
$route['auth/logout'] = 'xauth/logout';
$route['auth/callback'] = 'xauth/callback';
$route['auth/change_role_active'] = 'xauth/change_role_active';
```

8. Agar halaman tertentu di dalam suatu proyek dilindungi oleh autentikasi, tambahkan perintah `$this->webauth->authenticated()` ke dalam `constructor` di suatu controller. Sehingga jika pengguna mengakses halaman tertentu belum terautentikasi maka di arahkan ke halaman login SSO.