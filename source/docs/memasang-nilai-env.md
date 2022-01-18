---
title: Memasang Nilai di Environment File - SSO PHP - RistekUSDI
description: Memasang nilai di environment file pada SSO PHP - RistekUSDI
extends: _layouts.documentation
section: content
---

# Memasang nilai di Environment file

Salin format di bawah ini ke dalam file `.env`

```bash
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