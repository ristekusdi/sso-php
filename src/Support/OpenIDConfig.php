<?php

namespace RistekUSDI\SSO\Support;

class OpenIDConfig
{
    /**
     * Keycloak URL
     *
     * @var string
     */
    protected $baseUrl;

    /**
     * Keycloak Realm
     *
     * @var string
     */
    protected $realm;

    /**
     * Keycloak OpenId Configuration
     *
     * @var array
     */
    protected $openid;

    /**
     * Keycloak OpenId Cache Configuration
     *
     * @var array
     */
    protected $cacheOpenid;

    public function __construct()
    {
        if (is_null($this->baseUrl)) {
            $this->baseUrl = trim($_ENV['SSO_BASE_URL'], '/');
        }

        if (is_null($this->realm)) {
            $this->realm = $_ENV['SSO_REALM'];
        }

        if (is_null($this->cacheOpenid)) {
            $this->cacheOpenid = isset($_ENV['SSO_CACHE_OPENID']) ? $_ENV['SSO_CACHE_OPENID'] : false;
        }
    }

    protected function config()
    {
        $cacheKey = 'sso_web_guard_openid-' . $this->realm . '-' . md5($this->baseUrl);

        // From cache?
        // if ($this->cacheOpenid) {
        //     $configuration = Cache::get($cacheKey, []);

        //     if (! empty($configuration)) {
        //         return $configuration;
        //     }
        // }

        // Request if cache empty or not using
        $url = $this->baseUrl . '/realms/' . $this->realm;
        $url = $url . '/.well-known/openid-configuration';

        $configuration = [];

        $response = (new \GuzzleHttp\Client())->request('GET', $url);

        if ($response->getStatusCode() !== 200) {
            throw new Exception('[SSO Error] It was not possible to load OpenId configuration: ' . $response->throw());
        }

        $configuration = json_decode($response->getBody()->getContents(), true);

        // Save cache
        // if ($this->cacheOpenid) {
        //     Cache::put($cacheKey, $configuration);
        // }

        return $configuration;
    }

    public function get($name)
    {
        if (! $this->openid) {
            $this->openid = $this->config();
        }

        $result = null;
        foreach ($this->openid as $key => $value) {
            if ($key === $name) {
                $result = $value;
            }
        }

        return $result;
    }
}
