<?php

namespace RistekUSDI\SSO\PHP\Support;

class OpenIDConfig
{
    use OpenIDConfigTrait;

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

    public function __construct()
    {
        if (is_null($this->baseUrl)) {
            $this->baseUrl = trim($_SERVER['KEYCLOAK_BASE_URL'], '/');
        }

        if (is_null($this->realm)) {
            $this->realm = $_SERVER['KEYCLOAK_REALM'];
        }
    }

    protected function config()
    {
        $cacheKey = 'sso_openid-' . $this->realm . '-' . md5($this->baseUrl);

        // From cache?
        if ($this->hasCache($cacheKey)) {
            $configuration = $this->getCache($cacheKey);

            if (!empty($configuration)) {
                return $configuration;
            }
        }

        // Request if cache empty or not using
        $url = $this->baseUrl . '/realms/' . $this->realm;
        $url = $url . '/.well-known/openid-configuration';

        $configuration = [];

        $response = (new \GuzzleHttp\Client())->request('GET', $url, [
            // Timeout if the client fails to connect to the server in 10 seconds.
            'connect_timeout' => 10,
            // Allow a total of 30 seconds for the complete request/response cycle.
            'timeout' => 30
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new \Exception('[SSO Error] It was not possible to load OpenId configuration: ' . $response->getStatusCode());
        }

        $configuration = json_decode($response->getBody()->getContents(), true);

        // Save cache
        $this->putCache($cacheKey, $configuration);

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