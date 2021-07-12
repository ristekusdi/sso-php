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

## Penggunaan Dasar

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

### Data Pengguna

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

### Data Permission

Import class `WebGuard` dengan perintah `use RistekUSDI\SSO\Auth\Guard\WebGuard;`

Gunakan perintah `(new WebGuard())->permissions()` untuk mendapatkan daftar permission dalam bentuk array.

### Mengecek Permission Pengguna

Import class `WebGuard` dengan perintah `use RistekUSDI\SSO\Auth\Guard\WebGuard;`

Gunakan perintah `(new WebGuard())->user()->hasPermission($permissions)` dengan `$permissions` sebagai parameter. Tipe data parameter yang diterima adalah `string` dan `array`. Hasil yang diterima adalah `true` atau `false`.

Contoh:

- `(new WebGuard())->user()->hasPermission('view-mahasiswa')`
- `(new WebGuard())->user()->hasPermission(['view-mahasiswa', 'store-mahasiswa'])`

## Di mana access token dan refresh token disimpan?

Import class `SSOService` dengan perintah `use RistekUSDI\SSO\Services\SSOService;`

Gunakan perintah `(new SSOService())->retrieveToken()` untuk mendapatkan access token dan refresh token.