<?php

namespace RistekUSDI\SSO\PHP\Services;

use Exception;
use RistekUSDI\SSO\PHP\Auth\AccessToken;
use RistekUSDI\SSO\PHP\Support\OpenIDConfig;

class SSOService
{
    use SSOServiceTrait {
        saveToken as private traitSaveToken;
        retrieveToken as private traitRetrieveToken;
        forgetToken as private traitForgetToken;
    }

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
     * RedirectUrl
     *
     * @var array
     */
    protected $redirectUrl;

    /**
     * The state for authorization request
     *
     * @var string
     */
    protected $state;

    public function __construct()
    {
        if (is_null($this->baseUrl)) {
            $this->baseUrl = trim($_SERVER['KEYCLOAK_BASE_URL'], '/');
        }

        if (is_null($this->realm)) {
            $this->realm = $_SERVER['KEYCLOAK_REALM'];
        }

        if (is_null($this->clientId)) {
            $this->clientId = $_SERVER['KEYCLOAK_CLIENT_ID'];
        }

        if (is_null($this->clientSecret)) {
            $this->clientSecret = $_SERVER['KEYCLOAK_CLIENT_SECRET'];
        }

        if (is_null($this->cacheOpenid)) {
            $this->cacheOpenid = isset($_SERVER['KEYCLOAK_CACHE_OPENID']) ? $_SERVER['KEYCLOAK_CACHE_OPENID'] : false;
        }

        if (is_null($this->callbackUrl)) {
            $this->callbackUrl = $_SERVER['KEYCLOAK_CALLBACK'];
        }

        if (is_null($this->redirectUrl)) {
            $this->redirectUrl = $_SERVER['KEYCLOAK_REDIRECT_URL'];
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
     * Return the client secret
     *
     * @return string
     */
    protected function getClientSecret()
    {
        return $this->clientSecret;
    }

    /**
     * Return the callback url
     *
     * @return string
     */
    public function getCallbackUrl()
    {
        return $this->callbackUrl;
    }

    /**
     * Return the redirect url
     *
     * @return string
     */
    public function getRedirectUrl()
    {
        return $this->redirectUrl;
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

    public function saveToken($credentials)
    {
        return $this->traitSaveToken($credentials);
    }

    public function retrieveToken()
    {
        return $this->traitRetrieveToken();
    }

    public function forgetToken()
    {
        return $this->traitForgetToken();
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
            'redirect_uri' => $this->getCallbackUrl(),
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
        $token = $this->retrieveToken();

        $decoded_access_token = (new AccessToken($token))->parseAccessToken();
        
        $this->invalidateRefreshToken($token['refresh_token']);

        if (isset($decoded_access_token['impersonator'])) {
            return $this->getRedirectUrl();
        } else {
            $id_token = isset($token['id_token']) ? $token['id_token'] : null;
            
            $url = (new OpenIDConfig)->get('end_session_endpoint');
            $params = [
                'client_id' => $this->getClientId(),
            ];

            if ($id_token !== null) {
                $params['id_token_hint'] = $id_token;
                $params['post_logout_redirect_uri'] = url('/');
            }

            return build_url($url, $params);
        }
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
            'redirect_uri' => $this->getCallbackUrl(),
        ];

        if (! empty($this->getClientSecret())) {
            $params['client_secret'] = $this->getClientSecret();
        }

        $token = [];

        try {
            $response = (new \GuzzleHttp\Client())->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (\Throwable $th) {
            $this->logError($th->getMessage());
        }

        return $token;
    }

    /**
     * Refresh access token
     *
     * @param array $credentials
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
            'redirect_uri' => $this->getCallbackUrl(),
        ];

        if (! empty($this->getClientSecret())) {
            $params['client_secret'] = $this->getClientSecret();
        }

        $token = [];

        try {
            $response = (new \GuzzleHttp\Client())->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (\Throwable $th) {
            $this->logError($th->getMessage());
        }

        return $token;
    }

    /**
     * Invalidate Refresh
     *
     * @param  string $refreshToken
     * @return void
     */
    public function invalidateRefreshToken($refreshToken)
    {
        $url = (new OpenIDConfig)->get('end_session_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'refresh_token' => $refreshToken,
        ];

        if (! empty($this->getClientSecret())) {
            $params['client_secret'] = $this->getClientSecret();
        }

        try {
            (new \GuzzleHttp\Client())->request('POST', $url, ['form_params' => $params]);
        } catch (\Throwable $th) {
            $this->logError($th->getMessage());
        }
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
                return [];
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
                return [];
            }

            $user = $response->getBody()->getContents();
            $user = json_decode($user, true);

            // Validate retrieved user is owner of token
            $token->validateSub($user['sub'] ?? '');
        } catch (\Throwable $th) {
            $this->logError($th->getMessage());
        }

        return $user;
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

    /**
     * Get credentials (access_token, refresh_token, id_token) of impersonate user.
     * 
     * Notes: 
     * 1. Enable feature Token Exchange, Fine-Grained Admin Permissions, and Account Management REST API in Keycloak.
     * 2. Register user(s) as impersonator in impersonate scope user permissions.
     * 
     * @param username, credentials (access token of impersonator)
     * @return array|exception
     */
    public function impersonate($username, $credentials = array())
    {
        $token = [];
        
        try {
            $credentials = $this->refreshTokenIfNeeded($credentials);
            
            $url = (new OpenIDConfig)->get('token_endpoint');
            
            $headers = [
                'Content-Type' => 'application/x-www-form-urlencoded',
            ];
            
            $form_params = [
                'client_id' => $this->getClientId(),
                'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
                'requested_token_type' => 'urn:ietf:params:oauth:token-type:refresh_token',
                'requested_subject' => $username,
                'subject_token' => (new AccessToken($credentials))->getAccessToken(),
                // Set scope value to openid to get id_token
                'scope' => 'openid',
            ];

            if (!empty($this->getClientSecret())) {
                $form_params['client_secret'] = $this->getClientSecret();
            }
            
            $response = (new \GuzzleHttp\Client())->request('POST', $url, ['headers' => $headers, 'form_params' => $form_params]);
            
            if ($response->getStatusCode() !== 200) {
                throw new Exception('User not allowed to impersonate', 403);
            }

            $response_body = $response->getBody()->getContents();
            $token = json_decode($response_body, true);
        } catch (\Throwable $th) {
            $this->logError($th->getMessage());
        }

        // Revoke previous impersonate user session if $token is not empty
        if (!empty($token)) {
            $impersonate_user_token = $this->retrieveImpersonateToken();
            if (!empty($impersonate_user_token)) {
                $this->invalidateRefreshToken($impersonate_user_token['refresh_token']);
            }
        }

        return $token;
    }

    /**
     * Get claims based on client id and issuer
     */
    public function getClaims()
    {
        return array(
            'aud' => $this->getClientId(),
            'iss' => (new OpenIDConfig)->get('issuer'),
        );
    }
}