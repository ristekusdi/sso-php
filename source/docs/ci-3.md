---
title: Konfigurasi CodeIgniter 3.x - SSO PHP - RistekUSDI
description: Konfigurasi Pustaka ristekusdi/sso-php Pada CodeIgniter 3.x
extends: _layouts.documentation
section: content
---

# Konfigurasi CodeIgniter 3.x

1. Lakukan perubahan nilai pada `base_url`, `composer_autoload` dan `enable_hooks` di file `application/config/config.php`.

```php
<?php
$config['base_url'] = "http://yourapp.test/";

// Ubah lokasi autoload composer di direktori `vendor` pada root project.
$config['composer_autoload'] = "./vendor/autoload.php";

// Aktifkan hooks pada file `application/config/hooks.php`.
$config['enable_hooks'] = TRUE;
```

2. Untuk mengambil nilai dari file `.env` dengan perintah `$_ENV['nama_key']`, masukkan sintaks berikut di dalam file `application/config/hooks.php`.

```php
$hook['pre_system'] = function () {
    $dotenv = Dotenv\Dotenv::createImmutable(FCPATH);
    $dotenv->load();
};
```

3. Buat sebuah file bernama `Webauth.php` di direktori `application/libraries`. Kemudian, masukkan sintaks di bawah ini ke file tersebut.

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
```

4. Tambahkan `webauth` sebagai autoload library di direktori `application/config/autoload.php`

```php
// ... artinya autoload library yang sudah pernah Anda tambahkan sebelumnya
$autoload['libraries'] = array('...','webauth');
```

5. Buat sebuah file bernama `Xauth.php` di direktori `application/controllers`. Masukkan sintaks di bawah ini ke file tersebut.

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

    /**
     * Change key value (kv) active
     */
    public function change_kv_active()
    { 
        // Check if this session active? If not then redirect to login page.
        $this->webauth->authenticated();

        $value = $this->input->post('value');
        $unserialize_session = unserialize($_SESSION['serialize_session']);
        $unserialize_session[$this->input->post('key')] = $value;
        
        $serialize_session = serialize($unserialize_session);
        $_SESSION['serialize_session'] = $serialize_session;

        $arr = array(
            'submit' => '1',
            'link' => ""
        );

        header('Content-Type: application/json');
        echo json_encode($arr);
    }
}
```

5. Masukkan sintaks di bawah ini ke dalam `application/config/routes.php`. Hal ini digunakan sebagai routing autentikasi.

```php
$route['sso/login'] = 'xauth/login';
$route['sso/logout'] = 'xauth/logout';
$route['sso/callback'] = 'xauth/callback';
$route['sso/change_role_active'] = 'xauth/change_role_active';
$route['sso/change_kv_active'] = 'xauth/change_kv_active';
```

6. Agar halaman tertentu di dalam suatu proyek dilindungi oleh autentikasi, tambahkan perintah `$this->webauth->authenticated()` ke dalam `constructor` di suatu controller. Sehingga jika pengguna mengakses halaman tertentu belum terautentikasi maka di arahkan ke halaman login SSO.

**Catatan:**

Berikut ini perintah-perintah yang umumnya digunakan untuk pengecekan otentikasi dan mengambil data otentikasi.

- `$this->webauth->check()` untuk mengecek apakah ada pengguna yang login atau tidak.
- `$this->webauth->authenticated()` untuk mengembalikan pengguna ke halaman login SSO jika belum login.
- `$this->webauth->user()->get()` untuk mendapatkan data pengguna, `role_active`, `role_permissions` (permissions dari role active), `arr_menu` dan data-data lainnya yang diambil dari `$_SESSION`.
- `$this->webauth->user()->roles()` untuk mendapatkan data roles yang melekat pada pengguna.
- `$this->webauth->user()->hasRole($role)` untuk mengecek apakah pengguna memiliki role tertentu atau tidak (role bisa lebih dari 1 dengan format array) dan mengembalikan nilai bertipe boolean.
- `$this->webauth->user()->hasPermission($permission)` untuk mengecek apakah pengguna memiliki permission tertentu atau tidak (permission bisa lebih dari 1 dengan format array) dan mengembalikan nilai booelan.