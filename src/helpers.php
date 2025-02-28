<?php

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

if (!function_exists('build_http_query')) {
    function build_http_query($array)
    {
        return http_build_query($array, '', '&', PHP_QUERY_RFC3986);
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
            return trim($url, '?') . '?' . build_http_query($params);
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

        return $url . '?' . build_http_query($query);
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