<?php

namespace RistekUSDI\SSO\PHP\Support;

trait OpenIDConfigTrait {
    
    protected $cache = [];
    protected $expiry = [];

    public function getCache($key, $default = null)
    {
        if ($this->hasCache($key)) {
            return $this->cache[$key];
        }
        return $default;
    }

    public function putCache($key, $value, $ttl = 3600)
    {
        $this->cache[$key] = $value;
        $this->expiry[$key] = time() + $ttl;
    }
}