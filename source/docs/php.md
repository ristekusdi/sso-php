---
title: Konfigurasi PHP - SSO PHP - RistekUSDI
description: Konfigurasi Pustaka ristekusdi/sso-php Pada PHP
extends: _layouts.documentation
section: content
---

# Konfigurasi

Berikut adalah kode gambaran umum untuk pengaturan SSO dengan PHP non-framework.

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