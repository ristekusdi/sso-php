# SSO PHP

PHP package untuk memudahkan otentikasi pengguna di aplikasi Universitas Udayana.

## Prasyarat

- PHP versi >= 7.1

## Instalasi

Via Composer

```bash
composer require ristekusdi/sso-php
```

## Konfigurasi

Buatlah file bernama `.env` di root project dan isian dari file .env sebagai berikut.

```env
SSO_BASE_URL=
SSO_REALM=
SSO_REALM_PUBLIC_KEY=
SSO_CLIENT_ID=
SSO_CLIENT_SECRET=
SSO_CALLBACK=
```

- `SSO_BASE_URL`

SSO server Url. Contoh: `https://your-sso-domain.com/auth`

- `SSO_REALM`

SSO realm. Nilai bawaan adalah `master`.

- `SSO_REALM_PUBLIC_KEY`

SSO server realm public key. Dari dashboard menuju **Realm Settings** >> **Keys** >> **RS256** >> **Public key**

- `SSO_CLIENT_ID`

Dari dashboard **klik edit Client ID yang dipilih** >> **Settings** >> **salin nama Client ID di field Client ID**

- `SSO_CLIENT_SECRET`

> Pastikan pengaturan **Access Type** adalah **confidential** agar memperoleh nilai Secret

Dari dashboard **klik edit Client ID yang dipilih** >> **Credentials** >> **salin isian Secret di field Secret**

- `SSO_CALLBACK`

Callback url setelah berhasil melakukan autentikasi. Umumnya dengan format `http://yourproject.tld/auth/callback` atau `http://yourproject.tld/auth/callback.php`.

## Penggunaan Dasar

### Non Framework

<details>
    <summary>Klik untuk memperluas</summary>

```php
<?php

require('vendor/autoload');

use RistekUSDI\SSO\Exceptions\CallbackException;
use RistekUSDI\SSO\Services\SSOService;
use RistekUSDI\SSO\Auth\Guard\WebGuard;

function login() {
    $sso = new SSOService;
    $url = $sso->getLoginUrl();
    $sso->saveState();

    header('Location: ', $url);
    exit();
}

function callback() {
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
            // Ganti arah redirect sesuai kebutuhan
            header('Location: dashboard.php');
            exit();
        }
    }
}
```
</details>

### CodeIgniter

<details>
    <summary>Klik untuk memperluas</summary>

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
</details>

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
                
                $token = (new AccessToken($token))->parseAccessToken();
                if (empty($token['resource_access'][$_ENV['SSO_CLIENT_ID']])) {
                    show_error('Akses ditolak', 403);
                }
                
                $roles = [];
                if (!empty($_ENV['SSO_CLIENT_ID'])) {
                    $resource_access = $token['resource_access'];
                    $roles = $resource_access[$_ENV['SSO_CLIENT_ID']]['roles'];
                }

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

> TODO: dokumentasi cara menggunakan $this->webauth dan perintah-perintah yang sering digunakan pada class $this->webauth.

## Data Pengguna

Import class `WebGuard` dengan perintah `use RistekUSDI\SSO\Auth\Guard\WebGuard;`

- `(new WebGuard())->check()` untuk mengecek apakah pengguna sudah terotentikasi atau login.
- `(new WebGuard())->guest()` untuk mengecek apakah pengguna adalah "tamu" (belum login atau terotentikasi).
- `(new WebGuard())->user()` untuk mendapatkan data pengguna yang terotentikasi.

Atribut pengguna yang tersedia antara lain:

- `sub`
- `unud_identifier_id`
- `full_identity` => NIP - Nama Pengguna
- `unud_type_id`
- `username`
- `identifier` => adalah NIP atau NIM.
- `name`
- `email`

## Permission

Import class `WebGuard` dengan perintah `use RistekUSDI\SSO\Auth\Guard\WebGuard;`

Gunakan perintah `(new WebGuard())->permissions()` untuk mendapatkan daftar permission dalam bentuk array.

## Mengecek Permission Pengguna

Import class `WebGuard` dengan perintah `use RistekUSDI\SSO\Auth\Guard\WebGuard;`

Gunakan perintah `(new WebGuard())->user()->hasPermission($permissions)` dengan `$permissions` sebagai parameter. Tipe data parameter yang diterima adalah `string` dan `array`. Hasil yang diterima adalah `true` atau `false`.

Contoh:

- `(new WebGuard())->user()->hasPermission('view-mahasiswa')`
- `(new WebGuard())->user()->hasPermission(['view-mahasiswa', 'store-mahasiswa'])`

## Di mana access token dan refresh token disimpan?

Import class `SSOService` dengan perintah `use RistekUSDI\SSO\Services\SSOService;`

Gunakan perintah `(new SSOService())->retrieveToken()` untuk mendapatkan access token dan refresh token.