<?php

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
 * @param  string  $url
 * @param  array  $params
 * @return string
 */
if (!function_exists('build_url')) {
    function build_url($url, $params)
    {
        $parsedUrl = parse_url($url);
        if (empty($parsedUrl['host'])) {
            return trim($url, '?').'?'.build_http_query($params);
        }

        if (!empty($parsedUrl['port'])) {
            $parsedUrl['host'] .= ':'.$parsedUrl['port'];
        }

        $parsedUrl['scheme'] = (empty($parsedUrl['scheme'])) ? 'https' : $parsedUrl['scheme'];
        $parsedUrl['path'] = (empty($parsedUrl['path'])) ? '' : $parsedUrl['path'];

        $url = $parsedUrl['scheme'].'://'.$parsedUrl['host'].$parsedUrl['path'];
        $query = [];

        if (!empty($parsedUrl['query'])) {
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

        return $url.'?'.build_http_query($query);
    }
}

if (!function_exists('url')) {
    function url($params = '')
    {
        // Passing preg_match and trim is deprecated.
        // Fallback to REQUEST_URI on empty
        if (empty($params)) {
            $params = $_SERVER['REQUEST_URI'] ?? '';
        }

        // Determine if the given path is a valid URL.
        if (preg_match('~^(#|//|https?://|(mailto|tel|sms):)~', $params)) {
            if (filter_var($params, FILTER_VALIDATE_URL) !== false) {
                return $params;
            }
        }

        // Get the default scheme for a raw URL.
        $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
        $scheme = $secure ? 'https://' : 'http://';

        // Get the base URL for the request.
        $root = $scheme.$_SERVER['HTTP_HOST'];

        // Extract the query string from the given path.
        if (($queryPosition = strpos($params, '?')) !== false) {
            [$path, $query] = [
                substr($params, 0, $queryPosition),
                substr($params, $queryPosition),
            ];
        } else {
            [$path, $query] = [$params, ''];
        }

        // Format the given URL segments into a single URL.
        return trim($root.'/'.trim($path, '/'), '/').$query;
    }
}
