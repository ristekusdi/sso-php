<?php

namespace RistekUSDI\SSO\PHP\Support;

trait OpenIDConfigTrait {
    
    protected $cache = [];
    protected $expiry = [];

    public function hasCache($key)
    {
        if (!array_key_exists($key, $this->cache)) {
            return false;
        }

        if (time() > $this->expiry[$key]) {
            $this->forgetCache($key);
            return false;
        }

        return true;
    }

    // Delete item from cache
    public function forgetCache($key)
    {
        if (array_key_exists($key, $this->cache)) {
            unset($this->cache[$key]);
            unset($this->expiry[$key]);
            return true;
        }
        return false;
    }

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