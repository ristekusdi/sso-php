---
title: Modifikasi Halaman Error - SSO Laravel - RistekUSDI
description: Modifikasi Halaman Error pada SSO Laravel - RistekUSDI
extends: _layouts.documentation
section: content
---

# Modifikasi Halaman Error

Pada file `Handler.php` di folder `app/Exceptions` impor class `CallbackException` dan gunakan class tersebut di method `render`.

```php
<?php

// ....
use RistekUSDI\SSO\Exceptions\CallbackException;

class Handler extends ExceptionHandler
{
    // ...

    public function render($request, Exception $e)
    {
        // Hubungkan CallbackException ke dalam method render
        if ($e instanceof CallbackException) {
            return $e->render($request);
        }
        return parent::render($request, $e);
    }
}
```