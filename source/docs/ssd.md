---
title: SSD - SSO Laravel - RistekUSDI
description: Soal Sering Ditanya pada SSO Laravel - RistekUSDI
extends: _layouts.documentation
section: content
---

# Soal Sering Ditanya (SSD)

## Bagaimana cara mendapatkan access token dan refresh token?

Ada dua cara untuk mendapatkan access token dan refresh token:

1. Mengimpor facade `SSOWeb` dengan perintah `use RistekUSDI\SSO\Facades\SSOWeb;`, kemudian jalankan perintah `SSOWeb::retrieveToken()`.

2. Menggunakan session. Gunakan perintah `session()->get('_sso_token.access_token')` untuk mendapatkan access token dan `session()->get('_sso_token.refresh_token')`.

## Bagaimana cara saya meng-extend User model dengan User model dari RistekUSDI?

Pada User model extend class User model dari RistekUSDI dengan sintaks berikut.

```php
use RistekUSDI\SSO\Models\User as SSOUser;

class User extends SSOUser
{

}
```

Berikutnya, pada file `auth.php` ubah User model seperti berikut.

```php
'providers' => [
    'users' => [
        'driver' => 'sso-users',
        'model' => App\User::class, // sesuaikan dengan lokasi User model Anda.
    ],
],
```

## Bagaimana cara menyisipkan atribut lain ke dalam User model?

Agar Anda bisa menyisipkan atribut lain ke dalam User model maka Anda perlu melakukan proses extend class User model dari RistekUSDI yang ada pada langkah sebelumnya. Setelah itu, Anda bisa menambahkan atribut-atribut lain pada properti `$custom_fillable`.

```php
use RistekUSDI\SSO\Models\User as SSOUser;

class User extends SSOUser
{
    public $custom_fillable = [
        'unud_identifier_id',
        'unud_user_type_id',
        'role_active',
        'role_permissions',
        // dan lain-lain...
    ]
}
```

Setelah Anda menambahkan atribut-atribut tersebut maka Anda bisa memanggilnya dengan perintah `auth()->user()`. Misal: `auth()->user()->unud_identifier_id`, `auth()->user()->unud_user_type_id`, dan seterusnya.

## Bagaimana cara saya meng-extend WebGuard?

Anda bisa melakukan extend WebGuard dengan membuat file WebGuard baru dan mengubah nilai `guards.web` pada file `sso.php`.

```php
/**
 * Load guard class.
 */
'guards' => [
    'web' => RistekUSDI\SSO\Auth\Guard\WebGuard::class,
],
```

**Catatan:** Extend WebGuard berguna jika Anda ingin menyisipkan session aplikasi Anda ke dalam property user saat berhasil melakukan otentikasi.