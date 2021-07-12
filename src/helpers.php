<?php

use Illuminate\Support\Arr;
use GuzzleHttp\Exception\GuzzleException;

/**
 * Return a random state parameter for authorization
 *
 * @return string
 */
if (!function_exists('generate_random_state')) {
    function generate_random_state()
    {
        return bin2hex(random_bytes(16));
    }
}


/**
 * Log a GuzzleException
 *
 * @param  GuzzleException $e
 * @return void
 */
if (!function_exists('log_exception')) {
    function log_exception(GuzzleException $e)
    {
        // Guzzle 7
        if (! method_exists($e, 'getResponse') || empty($e->getResponse())) {
            return '[Keycloak Service] ' . $e->getMessage();
        }

        $error = [
            'request' => method_exists($e, 'getRequest') ? $e->getRequest() : '',
            'response' => $e->getResponse()->getBody()->getContents(),
        ];

        return '[Keycloak Service] ' . print_r($error, true);
    }
}

/**
 * Build a URL with params
 *
 * @param  string $url
 * @param  array $params
 * @return string
 */
if (!function_exists('build_url')) {
    function build_url($url, $params)
    {
        $parsedUrl = parse_url($url);
        if (empty($parsedUrl['host'])) {
            return trim($url, '?') . '?' . Arr::query($params);
        }

        if (! empty($parsedUrl['port'])) {
            $parsedUrl['host'] .= ':' . $parsedUrl['port'];
        }

        $parsedUrl['scheme'] = (empty($parsedUrl['scheme'])) ? 'https' : $parsedUrl['scheme'];
        $parsedUrl['path'] = (empty($parsedUrl['path'])) ? '' : $parsedUrl['path'];

        $url = $parsedUrl['scheme'] . '://' . $parsedUrl['host'] . $parsedUrl['path'];
        $query = [];

        if (! empty($parsedUrl['query'])) {
            $parsedUrl['query'] = explode('&', $parsedUrl['query']);

            foreach ($parsedUrl['query'] as $value) {
                $value = explode('=', $value);

                if (count($value) < 2) {
                    continue;
                }

                $key = array_shift($value);
                $value = implode('=', $value);

                $query[$key] = urldecode($value);
            }
        }

        $query = array_merge($query, $params);

        return $url . '?' . Arr::query($query);
    }
}

if (!function_exists('url')) {
    function url($params = '')
    {
        $link = '';
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
            $link = 'https';
        } else {
            $link = 'http';
        }

        // Append common URL characters
        $link .= '://';

        // Append the host (domain name, ip) to the URL.
        $link .= $_SERVER['HTTP_HOST'];

        // Append the requested resource location to the URL.
        $link .= !empty($params) ? $params : $_SERVER['REQUEST_URI'];

        return $link;
    }
}