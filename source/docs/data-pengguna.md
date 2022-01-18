---
title: Data Pengguna - SSO Laravel - RistekUSDI
description: Data Pengguna pada SSO Laravel - RistekUSDI
extends: _layouts.documentation
section: content
---

# Data Pengguna

Package ini mengimplementasikan `Illuminate\Contracts\Auth\Guard`. Sehingga, semua method bawaan Laravel tersedia.

Contoh: 

- `Auth::user()` untuk mendapatkan data pengguna yang terotentikasi.
- `Auth::user()->roles()` untuk mendapatkan daftar peran user pada aplikasi yang aktif.
- `Auth::check()` untuk mengecek apakah pengguna sudah terotentikasi atau login.
- `Auth::guest()` untuk mengecek apakah pengguna adalah "tamu" (belum login atau terotentikasi).

Atribut pengguna yang tersedia antara lain:

- `sub`.
- `full_identity`. Format: `NIP Nama Pengguna`.
- `username`.
- `identifier`. `identifier` adalah NIP atau NIM.
- `name`.
- `email`.
- `roles`.