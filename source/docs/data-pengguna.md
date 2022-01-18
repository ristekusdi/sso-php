---
title: Data Pengguna - SSO PHP - RistekUSDI
description: Data Pengguna SSO PHP - RistekUSDI
extends: _layouts.documentation
section: content
---

# Data Pengguna

Pustaka ini mengimplementasikan `Illuminate\Contracts\Auth\Guard` dari Laravel sehingga seolah-olah Anda seperti menggunakan Laravel.

Caranya adalah dengan mengimpor class `WebGuard` dengan perintah `use RistekUSDI\SSO\Auth\Guard\WebGuard;` maka Anda akan memiliki beberapa fungsi berikut.

- `(new WebGuard())->check()` untuk mengecek apakah pengguna sudah terotentikasi atau login.
- `(new WebGuard())->guest()` untuk mengecek apakah pengguna adalah "tamu" (belum login atau terotentikasi).
- `(new WebGuard())->user()` untuk mendapatkan data pengguna yang terotentikasi.

Atribut pengguna yang tersedia antara lain:

- `sub`
- `full_identity` => NIP - Nama Pengguna
- `username`
- `identifier` => adalah NIP atau NIM.
- `name`
- `email`
- `roles`
- `unud_identifier_id`
- `unud_type_id`

Cara mengakses atribut tersebut dengan perintah `(new WebGuard())->user()-><nama_atribut>`. Seperti `(new WebGuard())->user()->name`.