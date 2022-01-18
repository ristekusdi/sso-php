---
title: SSD - SSO PHP - RistekUSDI
description: Soal Sering Ditanya pada SSO PHP - RistekUSDI
extends: _layouts.documentation
section: content
---

# Soal Sering Ditanya (SSD)

## Bagaimana cara mendapatkan access token dan refresh token?

Impor class `SSOService` dengan perintah `use RistekUSDI\SSO\Services\SSOService;`

Gunakan perintah `(new SSOService())->retrieveToken()` untuk mendapatkan access token dan refresh token.