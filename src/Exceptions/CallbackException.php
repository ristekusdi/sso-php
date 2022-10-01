<?php

namespace RistekUSDI\SSO\PHP\Exceptions;

class CallbackException extends \RuntimeException
{
    /**
     * Callback Error
     *
     * @param string|null     $message  [description]
     * @param \Throwable|null $previous [description]
     * @param array           $headers  [description]
     * @param int|integer     $code     [description]
     */
    public function __construct(string $error = '', int $code = 401)
    {
        echo "[SSO Error] {$error} with HTTP code response {$code}";
    }
}
