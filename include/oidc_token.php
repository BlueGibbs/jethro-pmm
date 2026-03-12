<?php

require_once __DIR__ . '/oidc_helpers.php';

function oidc_parse_jwt($jwt) {
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) return null;
    [$h, $p, $s] = $parts;
    $header  = json_decode(base64url_decode($h), true);
    $payload = json_decode(base64url_decode($p), true);
    $sig     = base64url_decode($s);
    if (!is_array($header) || !is_array($payload) || $sig === false) return null;
    return ['header' => $header, 'payload' => $payload, 'signature' => $sig, 'signed' => $h . '.' . $p];
}

function oidc_validate_id_token($idToken, $issuer, $audience, $nonce = null) {
    $jwt = oidc_parse_jwt($idToken);
    if (!$jwt) return [false, 'Malformed ID token'];
    $h = $jwt['header']; $p = $jwt['payload'];

    // Required header/payload fields
    $alg = $h['alg'] ?? null; $kid = $h['kid'] ?? null;
    if (!$alg || !$kid) return [false, 'Missing alg/kid'];

    $now = time();
    $iss = $p['iss'] ?? null;
    $aud = $p['aud'] ?? null;
    $exp = $p['exp'] ?? null;
    $iat = $p['iat'] ?? null;

    if (!$iss || !$aud || !$exp || !$iat) return [false, 'Missing iss/aud/exp/iat'];
    if (!hash_equals(rtrim($issuer, '/'), rtrim($iss, '/'))) return [false, 'Issuer mismatch'];
    // audience may be string or array
    if ((is_array($aud) && !in_array($audience, $aud, true)) || (is_string($aud) && $aud !== $audience)) {
        return [false, 'Audience mismatch'];
    }

    if ($now + OIDC_CLOCK_SKEW < $iat)  return [false, 'Token used before issued'];
    if ($now - OIDC_CLOCK_SKEW > $exp)  return [false, 'Token expired'];

    if ($nonce !== null) {
        $nonceClaim = $p['nonce'] ?? null;
        if (!$nonceClaim || !hash_equals($nonce, $nonceClaim)) return [false, 'Nonce mismatch'];
    }

    // Get keys
    $discovery = oidc_discover($issuer);
    $jwksUri = OIDC_URL_JWKS ?: ($discovery['jwks_uri'] ?? null);
    if (!$jwksUri) return [false, 'No JWKS URI'];

    $jwks = oidc_get_jwks($jwksUri);
    if (!$jwks) return [false, 'Unable to fetch JWKS'];

    // Find matching key by kid
    $key = null;
    foreach ($jwks['keys'] as $k) {
        if (($k['kid'] ?? null) === $kid) { $key = $k; break; }
    }
    if (!$key) return [false, 'Key not found for kid'];

    $pem = jwk_to_pem($key);
    if (!$pem) return [false, 'Could not construct PEM from JWK'];

    $ok = openssl_verify($jwt['signed'], $jwt['signature'], $pem, openssl_algo_from_jwa($alg));
    if ($ok !== 1) return [false, 'Signature verification failed'];

    return [true, $p];
}

function openssl_algo_from_jwa($alg) {
    // RS256/RS384/RS512, PS256/384/512, ES256/384/512
    static $map = [
        'RS256' => OPENSSL_ALGO_SHA256,
        'RS384' => OPENSSL_ALGO_SHA384,
        'RS512' => OPENSSL_ALGO_SHA512,
        // PHP’s OpenSSL supports PSS via flags; we’ll rely on defaults here.
        'PS256' => OPENSSL_ALGO_SHA256,
        'PS384' => OPENSSL_ALGO_SHA384,
        'PS512' => OPENSSL_ALGO_SHA512,
        // For ECDSA, OpenSSL also uses these constants
        'ES256' => OPENSSL_ALGO_SHA256,
        'ES384' => OPENSSL_ALGO_SHA384,
        'ES512' => OPENSSL_ALGO_SHA512,
    ];
    return $map[$alg] ?? null;
}
