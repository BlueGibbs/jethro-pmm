<?php

function oidc_cache_get($key) {
    if (!is_dir(OIDC_CACHE_DIR)) @mkdir(OIDC_CACHE_DIR, 0770, true);
    $file = OIDC_CACHE_DIR . '/' . sha1($key) . '.json';
    if (!file_exists($file)) return null;
    $raw = file_get_contents($file);
    if (!$raw) return null;
    $data = json_decode($raw, true);
    if (!$data) return null;
    if (time() > $data['expires_at']) return null;
    return $data['value'];
}

function oidc_cache_set($key, $value, $ttl = OIDC_CACHE_TTL) {
    if (!is_dir(OIDC_CACHE_DIR)) @mkdir(OIDC_CACHE_DIR, 0770, true);
    $file = OIDC_CACHE_DIR . '/' . sha1($key) . '.json';
    $payload = json_encode(['expires_at' => time() + $ttl, 'value' => $value]);
    file_put_contents($file, $payload, LOCK_EX);
}

function http_get_json($url, $timeout = 8) {
    $ctx = stream_context_create([
        'http' => ['method' => 'GET', 'timeout' => $timeout, 'ignore_errors' => true],
        'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true]
    ]);
    $raw = @file_get_contents($url, false, $ctx);
    if ($raw === false) return null;
    $data = json_decode($raw, true);
    return is_array($data) ? $data : null;
}

function oidc_discover($issuer) {
    // Prefer cached
    $cacheKey = "discovery:$issuer";
    if ($d = oidc_cache_get($cacheKey)) return $d;

    $wellKnown = rtrim($issuer, '/') . '/.well-known/openid-configuration';
    $doc = http_get_json($wellKnown);
    if (!$doc) return null;

    // Minimal fields we care about
    $discovered = [
        'issuer'        => $doc['issuer']        ?? null,
        'authorization_endpoint' => $doc['authorization_endpoint'] ?? null,
        'token_endpoint'         => $doc['token_endpoint']         ?? null,
        'userinfo_endpoint'      => $doc['userinfo_endpoint']      ?? null,
        'jwks_uri'               => $doc['jwks_uri']               ?? null,
    ];
    // Basic sanity
    if (!$discovered['issuer'] || !$discovered['authorization_endpoint'] || !$discovered['token_endpoint'] || !$discovered['jwks_uri']) {
        return null;
    }

    oidc_cache_set($cacheKey, $discovered);
    return $discovered;
}

function oidc_get_jwks($jwksUri) {
    $cacheKey = "jwks:$jwksUri";
    if ($jwks = oidc_cache_get($cacheKey)) return $jwks;

    $doc = http_get_json($jwksUri);
    if (!$doc || empty($doc['keys']) || !is_array($doc['keys'])) return null;

    oidc_cache_set($cacheKey, $doc, OIDC_CACHE_TTL);
    return $doc;
}

function jwk_to_pem($jwk) {
    // Supports RSA/EC public keys
    if (($jwk['kty'] ?? '') === 'RSA') {
        $n = isset($jwk['n']) ? base64url_decode($jwk['n']) : null;
        $e = isset($jwk['e']) ? base64url_decode($jwk['e']) : null;
        if (!$n || !$e) return null;
        // Build RSA public key in PEM
        $components = [
            'modulus' => $n,
            'publicExponent' => $e,
        ];
        return pem_from_rsa($components);
    } elseif (($jwk['kty'] ?? '') === 'EC') {
        $crv = $jwk['crv'] ?? null;
        $x   = isset($jwk['x']) ? base64url_decode($jwk['x']) : null;
        $y   = isset($jwk['y']) ? base64url_decode($jwk['y']) : null;
        if (!$crv || !$x || !$y) return null;
        return pem_from_ec($crv, $x, $y);
    }
    return null;
}

function base64url_decode($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) $data .= str_repeat('=', 4 - $remainder);
    return base64_decode(strtr($data, '-_', '+/'));
}

// --- Helpers to build PEMs (RSA & EC) without external libs ---

function pem_from_rsa($components) {
    // ASN.1 structure: RSAPublicKey SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    $mod = asn1_integer($components['modulus']);
    $exp = asn1_integer($components['publicExponent']);
    $rsapub = asn1_sequence($mod . $exp);

    // AlgorithmIdentifier for rsaEncryption: 1.2.840.113549.1.1.1 with NULL params
    $algo = asn1_sequence(asn1_object_id("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01") . asn1_null());
    $bitString = asn1_bitstring("\x00" . $rsapub);

    $spki = asn1_sequence($algo . $bitString);
    return "-----BEGIN PUBLIC KEY-----\n" .
           chunk_split(base64_encode($spki), 64, "\n") .
           "-----END PUBLIC KEY-----\n";
}

function pem_from_ec($crv, $x, $y) {
    // Only for named curves P-256, P-384, P-521
    $curveOid = [
        'P-256' => "\x2A\x86\x48\xCE\x3D\x03\x01\x07",
        'P-384' => "\x2B\x81\x04\x00\x22",
        'P-521' => "\x2B\x81\x04\x00\x23",
    ][$crv] ?? null;
    if (!$curveOid) return null;

    // AlgorithmIdentifier: id-ecPublicKey 1.2.840.10045.2.1 + curve OID
    $algo = asn1_sequence(
        asn1_object_id("\x2A\x86\x48\xCE\x3D\x02\x01") . // id-ecPublicKey
        asn1_object_id($curveOid)
    );

    // Uncompressed form 0x04 || X || Y
    $pub = "\x04" . $x . $y;
    $bitString = asn1_bitstring($pub);
    $spki = asn1_sequence($algo . $bitString);

    return "-----BEGIN PUBLIC KEY-----\n" .
           chunk_split(base64_encode($spki), 64, "\n") .
           "-----END PUBLIC KEY-----\n";
}

// --- Tiny ASN.1 helpers ---
function asn1_len($len) {
    if ($len < 0x80) return chr($len);
    $out = '';
    while ($len > 0) { $out = chr($len & 0xff) . $out; $len >>= 8; }
    return chr(0x80 | strlen($out)) . $out;
}
function asn1_sequence($val) { return "\x30" . asn1_len(strlen($val)) . $val; }
function asn1_integer($val)  {
    // Ensure positive INTEGER (prepend 0x00 if high bit set)
    if (strlen($val) && (ord($val[0]) & 0x80)) $val = "\x00" . $val;
    return "\x02" . asn1_len(strlen($val)) . $val;
}
function asn1_null() { return "\x05\x00"; }
function asn1_bitstring($val) { return "\x03" . asn1_len(strlen($val)) . $val; }
function asn1_object_id($oid)  { return "\x06" . asn1_len(strlen($oid)) . $oid; }


// Build HTTP Basic "Authorization" header value from client_id/secret
function oidc_basic_auth_header(string $clientId, string $clientSecret): string {
    // Per RFC 6749 + OIDC, client_id and client_secret must be url-encoded before base64
    $user = rawurlencode($clientId);
    $pass = rawurlencode($clientSecret);
    return 'Authorization: Basic ' . base64_encode($user . ':' . $pass);
}

/**
 * POST application/x-www-form-urlencoded and return [status, headers[], body, meta]
 *
 * Uses file_get_contents() + $http_response_header (no stream handle),
 * so it works on standard PHP builds without curl.
 */
function http_post_form_with_meta(string $url, array $data, array $extraHeaders = [], int $timeout = 12): array {
    $headers = array_merge([
        'Content-Type: application/x-www-form-urlencoded',
    ], $extraHeaders);

    $opts = [
        'http' => [
            'method'        => 'POST',
            'header'        => implode("\r\n", $headers) . "\r\n",
            'content'       => http_build_query($data),
            'timeout'       => $timeout,
            'ignore_errors' => true, // read body even on 4xx/5xx
        ],
        'ssl'  => [
            'verify_peer'      => true,
            'verify_peer_name' => true,
        ],
    ];

    $ctx = stream_context_create($opts);

    // Capture the body; headers are exposed via $http_response_header
    $body = @file_get_contents($url, false, $ctx);

    // Copy headers and compute status from the first header line
    $respHeaders = [];
    if (isset($http_response_header) && is_array($http_response_header)) {
        $respHeaders = $http_response_header;
    }

    $status = 0;
    if (!empty($respHeaders) && preg_match('#HTTP/\\S+\\s+(\\d{3})#', $respHeaders[0], $m)) {
        $status = (int) $m[1];
    }

    // Return a tiny meta object; include last error (redacted) for debugging connectivity failures
    $lastErr = error_get_last();
    if (isset($lastErr['message'])) {
        // Avoid leaking secrets; nothing sensitive should be here, but keep it conservative
        $lastErr['message'] = preg_replace('/(client_secret=)[^&]+/i', '$1***redacted***', $lastErr['message']);
    }

    return [
        $status,
        $respHeaders,
        ($body === false ? '' : $body),
        ['last_error' => $lastErr]
    ];
}
