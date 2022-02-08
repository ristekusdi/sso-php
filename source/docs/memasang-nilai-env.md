---
title: Memasang Nilai di Environment File - SSO PHP - RistekUSDI
description: Memasang nilai di environment file pada SSO PHP - RistekUSDI
extends: _layouts.documentation
section: content
---

# Memasang nilai di Environment file

Anda akan mendapatkan isian konfigurasi berikut setelah membuat client app dan menyalin environment client app di IMISSU Dashboard.

```bash
SSO_BASE_URL=https://your-sso-domain.com/auth
SSO_REALM=master
SSO_REALM_PUBLIC_KEY=xxxxxxxxxx
SSO_CLIENT_ID=xxxxxxx
SSO_CLIENT_SECRET=xxxxxx
SSO_CALLBACK=http://yourapp.test/sso/callback
```

Isian konfigurasi tersebut dipasang pada file `.env`.

- `SSO_BASE_URL` adalah URL server SSO.
- `SSO_REALM` adalah "realm" tempat client app Anda berada yang didapatkan dari IMISSU Dashboard.
- `SSO_REALM_PUBLIC_KEY` adalah realm public key server SSO yang didapatkan dari IMISSU Dashboard.
- `SSO_CLIENT_ID` adalah client id yang didapatkan dari IMISSU Dashboard.
- `SSO_CLIENT_SECRET` adalah client secret yang didapatkan dari IMISSU Dashboard.
- `SSO_CALLBACK` adalah callback URL yang berfungsi ketika proses login berhasil dari SSO.