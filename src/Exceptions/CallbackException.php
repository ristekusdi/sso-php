<?php

namespace RistekUSDI\SSO\PHP\Exceptions;

class CallbackException extends \RuntimeException
{
    /**
     * Callback Error
     *
     * @param int|integer     $code     [description]
     * @param string|null     $message  [description]
     */
    public function __construct(int $code = 401, string $error = '')
    {
        echo "SSO Service error: {$error} with HTTP code response {$code}";
    }
}
