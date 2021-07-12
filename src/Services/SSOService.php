<?php

namespace RistekUSDI\SSO\Services;

use Exception;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Response;
use RistekUSDI\SSO\Auth\AccessToken;
use RistekUSDI\SSO\Support\OpenIDConfig;
use RistekUSDI\SSO\Support\Url;

class SSOService
{
    /**
     * The Session key for token
     */
    const SSO_SESSION = '_sso_token';

    /**
     * The Session key for state
     */
    const SSO_SESSION_STATE = '_sso_state';

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
     * Keycloak Client ID
     *
     * @var string
     */
    protected $clientId;

    /**
     * Keycloak Client Secret
     *
     * @var string
     */
    protected $clientSecret;

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

    /**
     * CallbackUrl
     *
     * @var array
     */
    protected $callbackUrl;

    /**
     * RedirectLogout
     *
     * @var array
     */
    protected $redirectLogout;

    /**
     * The state for authorization request
     *
     * @var string
     */
    protected $state;

    public function __construct()
    {
        if (is_null($this->baseUrl)) {
            $this->baseUrl = trim($_ENV['SSO_BASE_URL'], '/');
        }

        if (is_null($this->realm)) {
            $this->realm = $_ENV['SSO_REALM'];
        }

        if (is_null($this->clientId)) {
            $this->clientId = $_ENV['SSO_CLIENT_ID'];
        }

        if (is_null($this->clientSecret)) {
            $this->clientSecret = $_ENV['SSO_CLIENT_SECRET'];
        }

        if (is_null($this->cacheOpenid)) {
            $this->cacheOpenid = isset($_ENV['SSO_CACHE_OPENID']) ? $_ENV['SSO_CACHE_OPENID'] : false;
        }

        if (is_null($this->callbackUrl)) {
            $this->callbackUrl = $_ENV['SSO_CALLBACK'];
        }

        if (is_null($this->redirectLogout)) {
            // Later
            // $this->redirectLogout = Config::get('sso.redirect_logout');
        }

        $this->state = generate_random_state();
    }

    /**
     * Return the client id for requests
     *
     * @return string
     */
    protected function getClientId()
    {
        return $this->clientId;
    }

    /**
     * Return the state for requests
     *
     * @return string
     */
    protected function getState()
    {
        return $this->state;
    }

    /**
     * Return the login URL
     *
     * @link https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
     *
     * @return string
     */
    public function getLoginUrl()
    {
        $url = (new OpenIDConfig)->get('authorization_endpoint');
        $params = [
            'scope' => 'openid',
            'response_type' => 'code',
            'client_id' => $this->getClientId(),
            'redirect_uri' => $this->callbackUrl,
            'state' => $this->getState(),
        ];

        return build_url($url, $params);
    }

    /**
     * Return the logout URL
     *
     * @return string
     */
    public function getLogoutUrl()
    {
        $url = (new OpenIDConfig)->get('end_session_endpoint');

        if (empty($this->redirectLogout)) {
            $this->redirectLogout = url('/');
        }
        
        $params = [
            'client_id' => $this->getClientId(),
            'redirect_uri' => $this->redirectLogout,
        ];

        return build_url($url, $params);
    }

    /**
     * Get access token from Code
     *
     * @param  string $code
     * @return array
     */
    public function getAccessToken($code)
    {
        $url = (new OpenIDConfig)->get('token_endpoint');
        $params = [
            'code' => $code,
            'client_id' => $this->getClientId(),
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->callbackUrl,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = (new \GuzzleHttp\Client())->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            echo 'Message: '.$e->getMessage();
        }

        return $token;
    }

    /**
     * Refresh access token
     *
     * @param  string $refreshToken
     * @return array
     */
    public function refreshAccessToken($credentials)
    {
        if (empty($credentials['refresh_token'])) {
            return [];
        }

        $url = (new OpenIDConfig)->get('token_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'grant_type' => 'refresh_token',
            'refresh_token' => $credentials['refresh_token'],
            'redirect_uri' => $this->callbackUrl,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = (new \GuzzleHttp\Client())->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            log_exception($e);
        }

        return $token;
    }

    /**
     * Invalidate Refresh
     *
     * @param  string $refreshToken
     * @return array
     */
    public function invalidateRefreshToken($refreshToken)
    {
        $url = (new OpenIDConfig)->get('end_session_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'refresh_token' => $refreshToken,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        try {
            $response = (new \GuzzleHttp\Client())->request('POST', $url, ['form_params' => $params]);
            return $response->getStatusCode() === 204;
        } catch (GuzzleException $e) {
            log_exception($e);
        }

        return false;
    }

    /**
     * Get access token from Code
     * @param  array $credentials
     * @return array
     */
    public function getUserProfile($credentials)
    {
        $credentials = $this->refreshTokenIfNeeded($credentials);

        $user = [];
        try {
            // Validate JWT Token
            $token = new AccessToken($credentials);

            if (empty($token->getAccessToken())) {
                throw new Exception('Access Token is invalid.');
            }

            $claims = array(
                'aud' => $this->getClientId(),
                'iss' => $url = (new OpenIDConfig)->get('issuer'),
            );

            $token->validateIdToken($claims);

            // Get userinfo
            $url = (new OpenIDConfig)->get('userinfo_endpoint');
            $headers = [
                'Authorization' => 'Bearer ' . $token->getAccessToken(),
                'Accept' => 'application/json',
            ];

            $response = (new \GuzzleHttp\Client())->request('GET', $url, ['headers' => $headers]);

            if ($response->getStatusCode() !== 200) {
                throw new Exception('Was not able to get userinfo (not 200)');
            }

            $user = $response->getBody()->getContents();
            $user = json_decode($user, true);

            // Validate retrieved user is owner of token
            $token->validateSub($user['sub'] ?? '');
        } catch (GuzzleException $e) {
            log_exception($e);
        } catch (Exception $e) {
            return '[Keycloak Service] '.print_r($e->getMessage(), true);
        }

        return $user;
    }

    public function permissions()
    {
        $token = $this->retrieveToken();
        
        if (empty($token) || empty($token['access_token'])) {
            return [];
        }

        $token = new AccessToken($token);

        $response = (new \GuzzleHttp\Client())->request('POST', (new OpenIDConfig)->get('token_endpoint'), [
                'headers' => [
                    'Authorization' => 'Bearer '.$token->getAccessToken()
                ],
                'form_params' => [
                    'grant_type' => 'urn:ietf:params:oauth:grant-type:uma-ticket',
                    'audience' => $_ENV['SSO_CLIENT_ID']
                ]
            ]
        );

        if ($response->getStatusCode() !== 200) {
            return [];
        }

        $raw_token = $response->getBody()->getContents();
        
        $token = new AccessToken(json_decode($raw_token, true));
        
        // Introspection permissions
        $response = (new \GuzzleHttp\Client())->request('POST', (new OpenIDConfig)->get('token_introspection_endpoint'), [
            'auth' => [
                $_ENV['SSO_CLIENT_ID'], $_ENV['SSO_CLIENT_SECRET']
            ],
            'form_params' => [
                'token_type_hint' => 'requesting_party_token',
                'token' => $token->getAccessToken()
            ]
        ]);
        
        if ($response->getStatusCode() !== 200) {
            return [];
        }

        $raw_result = $response->getBody()->getContents();
        $result = json_decode($raw_result, true);
        
        // If permissions don't active then return false
        if (!$result['active']) {
            return [];
        }

        $resourcePermissions = [];
        foreach ($result['permissions'] as $permission) {
            if (!empty($permission['resource_scopes'])) {
                foreach ($permission['resource_scopes'] as $value) {
                    $resourcePermissions[] = $value;
                }
            }
        }

        return $resourcePermissions;
    }

    /**
     * Retrieve Token from Session
     *
     * @return array|null
     */
    public function retrieveToken()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start(); 
        }
        return $_SESSION[self::SSO_SESSION];
    }

    /**
     * Save Token to Session
     *
     * @return void
     */
    public function saveToken($credentials)
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start(); 
        }
        $_SESSION[self::SSO_SESSION] = $credentials;
    }

    /**
     * Remove Token from Session
     *
     * @return void
     */
    public function forgetToken()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start(); 
        }

        // Remove all session variables.
        session_unset();
        
        // Destroy the session
        session_destroy();
        
        // session()->forget(self::SSO_SESSION);
        // session()->save();
    }

    /**
     * Validate State from Session
     *
     * @return void
     */
    public function validateState($state)
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start(); 
        }
        $challenge = $_SESSION[self::SSO_SESSION_STATE];
        return (! empty($state) && ! empty($challenge) && $challenge === $state);
    }

    /**
     * Save State to Session
     *
     * @return void
     */
    public function saveState()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start(); 
        }
        $_SESSION[self::SSO_SESSION_STATE] = $this->state;
        
        // session()->put(self::SSO_SESSION_STATE, $this->state);
        // session()->save();
    }

    /**
     * Remove State from Session
     *
     * @return void
     */
    public function forgetState()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start(); 
        }

        // Remove all session variables.
        session_unset();
        
        // Destroy the session
        session_destroy();

        // session()->forget(self::SSO_SESSION_STATE);
        // session()->save();
    }

    /**
     * Check we need to refresh token and refresh if needed
     *
     * @param  array $credentials
     * @return array
     */
    protected function refreshTokenIfNeeded($credentials)
    {
        if (! is_array($credentials) || empty($credentials['access_token']) || empty($credentials['refresh_token'])) {
            return $credentials;
        }

        $token = new AccessToken($credentials);
        if (! $token->hasExpired()) {
            return $credentials;
        }

        $credentials = $this->refreshAccessToken($credentials);

        if (empty($credentials['access_token'])) {
            $this->forgetToken();
            return [];
        }

        $this->saveToken($credentials);
        return $credentials;
    }
}