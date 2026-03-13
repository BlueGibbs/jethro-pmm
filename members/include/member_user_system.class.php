<?php
/**
 * member_user_system.class.php
 *
 * Hardened member auth system with generic OIDC support (discovery + ID token validation)
 * and safe, session-scoped password bypass only after successful OIDC verification.
 *
 * NOTE: This file expects the following to exist in your app environment:
 *  - Constants from your config (see OIDC_* constants and others used below)
 *  - Global $db with methods: queryRow, queryAll, queryOne, exec, quote, setCurrentUserID
 *  - Helper functions: array_get, generate_random_string, jethro_password_hash,
 *                      jethro_password_verify, add_message
 *  - Classes: Emailer, Staff_Member
 *  - Templates referenced under TEMPLATE_DIR
 *
 * Dependencies added:
 *  - include/oidc_helpers.php  (discovery, JWKS cache, JWK->PEM)
 *  - include/oidc_token.php    (JWT parse + signature + claim validation)
 *  - league::oauth2-client     (PHP League OAuth 2 client)
 */

declare(strict_types=1);

require_once JETHRO_ROOT.'/include/general.php';
require_once JETHRO_ROOT.'/include/abstract_user_system.class.php';

/**
 * Mask a string keeping the first $keepStart and last $keepEnd characters.
 * Uses mbstring if available for proper UTF-8 handling.
 * Used for enhanced (But still secure) debug logging
 *
 * TODO: Move to helper file
 */
if (!function_exists('mask_value')) {
    function mask_value($value, int $keepStart = 3, int $keepEnd = 3, string $mask = '***', string $encoding = 'UTF-8') {
        if (!is_string($value)) {
            // Decide how you want to handle non-strings:
            // return $value; // or cast to string
            $value = (string)$value;
        }

        // Prefer mb_* if available
        $len = function_exists('mb_strlen') ? mb_strlen($value, $encoding) : strlen($value);
        $sub = function($str, $start, $length = null) use ($encoding) {
            if (function_exists('mb_substr')) {
                return $length === null ? mb_substr($str, $start, null, $encoding)
                                        : mb_substr($str, $start, $length, $encoding);
            } else {
                return $length === null ? substr($str, $start)
                                        : substr($str, $start, $length);
            }
        };

        // If the string is short, avoid over-exposing content.
        if ($len <= 0) {
            return $mask;
        }

        // If total keep exceeds length, compress the strategy:
        if ($keepStart + $keepEnd >= $len) {
            // Keep just the first character and last character when possible.
            if ($len <= 2) {
                // Too short - fully mask
                return $mask;
            }
            return $sub($value, 0, 1) . $mask . $sub($value, -1);
        }

        $start = $sub($value, 0, $keepStart);
        $end   = $sub($value, -$keepEnd);
        return $start . $mask . $end;
    }
}

/**
 * OIDC diagnostics helper
 * Simple handler for logging arrays. Includes sanitisation/masking
 * for well-known sensitive values
 *
 * TODO: Move to helper file
 */
if (!function_exists('oidc_diag')) {
    function oidc_diag(string $msg, array $context = []): void {
        $prefix = '[OIDC] ';
        if (!empty($context)) {
            // Avoid logging secrets verbatim
            $safe = $context;
            foreach (['client_secret', 'password', 'Authorization'] as $k) {
                if (isset($safe[$k])) $safe[$k] = mask_value($safe[$k], 3, 3, '****');
            }
            $msg .= ' | ' . json_encode($safe);
        }
        error_log($prefix . $msg);
        if (defined('OIDC_DEBUG') && OIDC_DEBUG) {
            $_SESSION['_oidc_debug'][] = $msg;
        }
    }
}

class Member_User_System extends Abstract_User_System
{
    /**
     * Process classic username/password login request
     */
    private function handleLoginRequest(): void
    {
        if (array_get($_SESSION, 'login_key', null) != ($_POST['login_key'] ?? null)) {
            $this->_error = 'Login form expired. Please try again.';
            return;
        }

        $email = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';
        $user_details = $this->_findAuthMember($email, $password);

        if (is_null($user_details)) {
            $this->_error = 'Incorrect email address or password';
            return;
        } elseif ($user_details === false) {
            $this->_error = 'Sorry, your account has been archived';
            return;
        }

        // Log the member in
        $this->_setAuthMember($user_details);
    }

    /**
     * Basic checks of OIDC config constants
     * Attempts to auto-detect missing details using IdP's /.well-known/openid-configuration endpoint
     */
    private function _checkOidcConfigAndDiscover(): array
    {
        if (session_status() !== PHP_SESSION_ACTIVE) { session_start(); }

        $cfg = [
            'enable'   => defined('OIDC_ENABLE') ? OIDC_ENABLE : null,
            'issuer'   => defined('OIDC_ISSUER') ? OIDC_ISSUER : null,
            'clientId' => defined('OIDC_CLIENT_ID') ? OIDC_CLIENT_ID : null,
            'redir'    => defined('OIDC_REDIRECT_URI') ? OIDC_REDIRECT_URI : null,
            // optional overrides:
            'auth'     => (defined('OIDC_URL_AUTHORIZE') && OIDC_URL_AUTHORIZE) ? OIDC_URL_AUTHORIZE : null,
            'token'    => (defined('OIDC_URL_TOKEN') && OIDC_URL_TOKEN) ? OIDC_URL_TOKEN : null,
            'jwks'     => (defined('OIDC_URL_JWKS') && OIDC_URL_JWKS) ? OIDC_URL_JWKS : null,
        ];

        // Basic presence checks
        if (!$cfg['enable']) {
            oidc_diag('OIDC_ENABLE is false or undefined');
            return ['ok' => false, 'error' => 'OIDC is disabled'];
        }
        if (empty($cfg['clientId'])) {
            oidc_diag('OIDC_CLIENT_ID missing');
            return ['ok' => false, 'error' => 'Missing OIDC_CLIENT_ID'];
        }
        if (empty($cfg['redir'])) {
            oidc_diag('OIDC_REDIRECT_URI missing');
            return ['ok' => false, 'error' => 'Missing OIDC_REDIRECT_URI'];
        }

        // Discovery if issuer provided (preferred)
        $resolvedIssuer = null;
        $auth = $cfg['auth']; $token = $cfg['token']; $jwks = $cfg['jwks'];
        if (!empty($cfg['issuer'])) {
            require_once JETHRO_ROOT . '/include/oidc_helpers.php';
            oidc_diag('Attempting discovery', ['issuer' => $cfg['issuer']]);

            $disc = oidc_discover($cfg['issuer']);
            if (!$disc) {
                oidc_diag('Discovery failed for issuer', ['issuer' => $cfg['issuer']]);
                // If you supplied explicit endpoints, we can still continue.
            } else {
                $resolvedIssuer = $disc['issuer'] ?? null;
                $auth  = $auth  ?: ($disc['authorization_endpoint'] ?? null);
                $token = $token ?: ($disc['token_endpoint'] ?? null);
                $jwks  = $jwks  ?: ($disc['jwks_uri'] ?? null);
                oidc_diag('Discovery succeeded', [
                    'issuer'  => $resolvedIssuer,
                    'auth'    => $auth,
                    'token'   => $token,
                    'jwks'    => $jwks
                ]);
            }
        }

        // If no issuer (non-standard provider), require all endpoints
        if (!$resolvedIssuer && empty($cfg['issuer'])) {
            if (!$auth || !$token || !$jwks) {
                oidc_diag('No issuer and endpoints incomplete', ['auth' => $auth, 'token' => $token, 'jwks' => $jwks]);
                return ['ok' => false, 'error' => 'Endpoints incomplete without issuer/discovery'];
            }
            // You may still supply an issuer-like value for validation if your IdP requires.
            $resolvedIssuer = 'urn:issuer:manual';
        }

        // Final sanity
        if (!$auth || !$token || !$jwks) {
            oidc_diag('Missing one or more endpoints', ['auth' => $auth, 'token' => $token, 'jwks' => $jwks]);
            return ['ok' => false, 'error' => 'OIDC endpoints are incomplete'];
        }

        return [
            'ok'      => true,
            'issuer'  => $resolvedIssuer ?: $cfg['issuer'],
            'auth'    => $auth,
            'token'   => $token,
            'jwks'    => $jwks,
            'clientId'=> $cfg['clientId'],
            'redir'   => $cfg['redir'],
        ];
    }

    /**
     * Generic OIDC (OpenID Connect) login flow with discovery + ID token validation.
     *
     * Entry points:
     *   - Initial call without ?code starts authorization by redirecting to the IdP
     *   - Callback with ?code handles token exchange and login completion
     */
    private function handleOidcLoginRequest(): void
    {
        if (!defined('OIDC_ENABLE') || !OIDC_ENABLE) {
            $this->_error = 'OIDC is disabled.';
            oidc_diag('handleOidcLoginRequest called but OIDC disabled');
            return;
        }

        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
	}

        require_once JETHRO_ROOT . '/include/oidc_helpers.php';
        require_once JETHRO_ROOT . '/include/oidc_token.php';


        // 0) Config & discovery diagnostics
        $check = $this->_checkOidcConfigAndDiscover();
        if (empty($check['ok'])) {
            $this->_error = 'OIDC is not configured properly.';
            // Show a concise summary to the user in DEBUG mode
            if (defined('OIDC_DEBUG') && OIDC_DEBUG) {
                $details = implode('<br>', array_map('htmlspecialchars', $_SESSION['_oidc_debug'] ?? []));
                $this->_error .= '<br><small>' . $details . '</small>';
            }
            return;
        }

        // Use the resolved endpoints
        $resolvedIssuer = $check['issuer'];
        $authorizeUrl   = $check['auth'];
        $tokenUrl       = $check['token'];

	$redirect = defined('OIDC_REDIRECT_URI') ? OIDC_REDIRECT_URI : '';
        $issuer = defined('OIDC_ISSUER') ? OIDC_ISSUER : null;
        $discover = $issuer ? oidc_discover($issuer) : null;
        $jwksUrl      = (defined('OIDC_URL_JWKS') && OIDC_URL_JWKS) ? OIDC_URL_JWKS : ($discover['jwks_uri'] ?? null);

        if (!$authorizeUrl || !$tokenUrl || !$jwksUrl || !$resolvedIssuer || !defined('OIDC_CLIENT_ID') || !defined('OIDC_REDIRECT_URI')) {
            $this->_error = 'OIDC is not configured properly.';
            return;
	}

        if (defined('OIDC_DEBUG') && OIDC_DEBUG) {
            oidc_diag('Authorize redirect_uri', ['redirect' => $redirect]);
        }

        // 1) Start authorization
        if (!isset($_GET['code']) && !isset($_GET['error'])) {
            $state = bin2hex(random_bytes(16));
            $nonce = bin2hex(random_bytes(16));
            $_SESSION['oauth2state'] = $state;
            $_SESSION['oidc_nonce']  = $nonce;

            $scope = defined('OIDC_SCOPES') ? OIDC_SCOPES : 'openid email profile';
            $params = [
                'client_id'     => OIDC_CLIENT_ID,
                'redirect_uri'  => $redirect,
                'response_type' => 'code',
                'scope'         => $scope,
                'state'         => $state,
                'nonce'         => $nonce,
            ];
            $sep = (strpos($authorizeUrl, '?') === false) ? '?' : '&';
            header('Location: ' . $authorizeUrl . $sep . http_build_query($params));
            exit;
        }

        // 2) Handle provider error
        if (isset($_GET['error'])) {
            $this->_error = 'We could not sign you in. Please try again.';
            return;
        }

        // 3) Validate state (CSRF)
        if (empty($_GET['state']) || empty($_SESSION['oauth2state']) || !hash_equals($_SESSION['oauth2state'], $_GET['state'])) {
            unset($_SESSION['oauth2state'], $_SESSION['oidc_nonce']);
            exit('Invalid state');
        }


        // 4) Exchange code for tokens (instrumented)
        oidc_diag('Token redirect_uri (must match authorize)', ['redirect' => $redirect]);

        $post = [
            'grant_type'   => 'authorization_code',
            'code'         => $_GET['code'],
            'redirect_uri' => $redirect,
            'client_id'    => OIDC_CLIENT_ID,
        ];


        // First attempt: client_secret_post (in body)
        $bodyAuth = $post;
        if (defined('OIDC_CLIENT_SECRET') && OIDC_CLIENT_SECRET) {
            $bodyAuth['client_secret'] = OIDC_CLIENT_SECRET;
        }

        [$status1, $hdrs1, $raw1] = http_post_form_with_meta($tokenUrl, $bodyAuth);
        $tok1 = $raw1 ? json_decode($raw1, true) : null;

        // If 401/400 or no id_token, try client_secret_basic (header), with client_id only in body
        $needFallback = ($status1 >= 400) || !$tok1 || empty($tok1['id_token']);
        if ($needFallback && defined('OIDC_CLIENT_SECRET') && OIDC_CLIENT_SECRET) {
            $basic = oidc_basic_auth_header(OIDC_CLIENT_ID, OIDC_CLIENT_SECRET);
            $bodyBasic = [
                'grant_type'   => 'authorization_code',
                'code'         => $_GET['code'],
                'redirect_uri' => $redirect,
                // client_id optional in body for Basic; some IdPs accept it either way
                'client_id'    => OIDC_CLIENT_ID,
            ];
            [$status2, $hdrs2, $raw2] = http_post_form_with_meta($tokenUrl, $bodyBasic, [$basic]);
            $tok2 = $raw2 ? json_decode($raw2, true) : null;
        }

        // Decide which response to use
        $use = null;
        if (!$needFallback) {
            $use = ['status' => $status1, 'headers' => $hdrs1, 'raw' => $raw1, 'json' => $tok1, 'auth' => 'client_secret_post'];
        } else {
            $use = ['status' => $status2 ?? $status1, 'headers' => $hdrs2 ?? $hdrs1, 'raw' => $raw2 ?? $raw1, 'json' => $tok2 ?? $tok1, 'auth' => 'client_secret_basic'];
        }

        // Log diagnostics (redact)
        $logBody = $use['raw'];
        if (strlen($logBody) > 800) $logBody = substr($logBody, 0, 800) . '…';
        oidc_diag('Token exchange response', [
            'auth_style' => $use['auth'],
            'status'     => $use['status'],
            // show the first header line (status) + a couple of relevant headers
            'headers'    => array_values(array_filter($use['headers'], function($h) {
                static $keep = ['HTTP/', 'content-type', 'cache-control', 'pragma', 'www-authenticate'];
                foreach ($keep as $k) {
                    if (stripos($h, $k) === 0) return true;
                }
                return false;
            })),
            'body'       => $logBody,
        ]);

        $tokenResp = is_array($use['json']) ? $use['json'] : null;
        if (!$tokenResp || empty($tokenResp['id_token'])) {
            // Provide a concise on-screen hint in debug mode
            $this->_error = 'Token exchange failed.';
            if (defined('OIDC_DEBUG') && OIDC_DEBUG) {
                $hint = 'status=' . ($use['status'] ?? 0);
                // If the body looks like JSON with error fields, surface them
                $jsonErr = json_decode($use['raw'], true);
                if (is_array($jsonErr) && !empty($jsonErr['error'])) {
                    $hint .= ' error=' . htmlspecialchars($jsonErr['error'], ENT_QUOTES);
                    if (!empty($jsonErr['error_description'])) {
                        $hint .= ' desc=' . htmlspecialchars($jsonErr['error_description'], ENT_QUOTES);
                    }
                }
                $this->_error .= '<br><small>' . $hint . '</small>';
            }
            return;
        }

        // Success path continues
        $idToken = $tokenResp['id_token'];

	// 5) Validate ID token
	$nonce = $_SESSION['oidc_nonce'];
        $aud = defined('OIDC_AUDIENCE') ? OIDC_AUDIENCE : (defined('OIDC_CLIENT_ID') ? OIDC_CLIENT_ID : null);
        [$ok, $payloadOrErr] = oidc_validate_id_token($idToken, $resolvedIssuer, $aud, $nonce);
        if (!$ok) {
            $this->_error = 'Unable to verify your identity (' . $payloadOrErr . ').';
            return;
        }

        $claims = $payloadOrErr;

        // 6) Extract email
        $emailClaim = defined('OIDC_EMAIL_CLAIM') ? OIDC_EMAIL_CLAIM : 'email';
        $email = $claims[$emailClaim] ?? ($claims['preferred_username'] ?? null);
        if (!$email) {
            $this->_error = 'No email claim present in your identity.';
            return;
        }

        // 7) Short-lived proof for passwordless local login
        $_SESSION['oidc_verified_email'] = $email;
        $_SESSION['oidc_verified_at']    = time();

        // Clean one-time values
        unset($_SESSION['oauth2state'], $_SESSION['oidc_nonce']);

        // 8) Complete local login
        $user = $this->_findAuthMember($email, '');
        if (is_null($user)) {
            if (defined('OIDC_REQUIRE_EXISTING_ACCOUNT') && OIDC_REQUIRE_EXISTING_ACCOUNT) {
                $this->_error = 'No local account is linked to your email.';
                return;
            } else {
                $this->_error = 'Auto-provisioning is not implemented.';
                return;
            }
        } elseif ($user === false) {
            if (!defined('OIDC_DENY_ARCHIVED_USERS') || OIDC_DENY_ARCHIVED_USERS) {
                $this->_error = 'Your account is archived.';
                return;
            }
        }

        $this->_setAuthMember($user);
        header('Location: ' . BASE_URL . '/members/');
        exit;
    }

    /**
     * Send activation email to a person record
     */
    public function sendActivationEmail($person)
    {
        $hash = generate_random_string(32);
        $SQL = 'UPDATE _person SET resethash=' . $GLOBALS['db']->quote($hash) . ', resetexpires = NOW() + INTERVAL 24 HOUR WHERE id = ' . (int)$person['id'];
        $res = $GLOBALS['db']->exec($SQL);

        $url = BASE_URL . '/members/?email=' . rawurlencode($person['email']) . '&verify=' . rawurlencode($hash);
        $body = "Hi %s, To activate your %s account, please %s If you didn't request an account, you can just ignore this email";

        $text = sprintf($body, $person['first_name'], SYSTEM_NAME, 'go to ' . $url);
        $html = sprintf(nl2br($body), $person['first_name'], SYSTEM_NAME, '[click here](' . $url . ').');

        $message = Emailer::newMessage()
            ->setSubject(MEMBER_REGO_EMAIL_SUBJECT)
            ->setFrom([MEMBER_REGO_EMAIL_FROM_ADDRESS => MEMBER_REGO_EMAIL_FROM_NAME])
            ->setTo([$person['email'] => $person['first_name'] . ' ' . $person['last_name']])
            ->setBody($text)
            ->addPart($html, 'text/html');

        return Emailer::send($message);
    }

    /**
     * Handle an account request by email
     */
    private function handleAccountRequest(): void
    {
        $person = $this->findCandidateMember($_REQUEST['email'] ?? '');
        require_once 'include/emailer.class.php';
        $failureEmail = defined('MEMBER_REGO_FAILURE_EMAIL') ? MEMBER_REGO_FAILURE_EMAIL : '';

        if (is_array($person)) {
            $res = $this->sendActivationEmail($person);
            if (true == $res) {
                require_once 'templates/account_request_received.template.php';
                exit;
            } else {
                $this->_error = 'Could not send to the specified address. Your email server may be experiencing problems.';
                return;
            }
        } elseif (!Emailer::validateAddress($_REQUEST['email'] ?? '')) {
            $this->_error = 'You have entered an invalid email address. Please check the address and try again.';
        } elseif (($person == -1) && !empty($failureEmail)) {
            $message = Emailer::newMessage()
                ->setSubject('Member Account request from multi-family email')
                ->setFrom([MEMBER_REGO_EMAIL_FROM_ADDRESS => SYSTEM_NAME . ' Jethro System'])
                ->setTo(MEMBER_REGO_FAILURE_EMAIL)
                ->setBody("Hi, \n\nThis is an automated message from the Jethro system at " . BASE_URL . ".\n\n"
                        . "Somebody has used the form at " . BASE_URL . "/members to request member-access to this Jethro system. \n\n"
                        . "The email address they specified was " . ($_REQUEST['email'] ?? '') . " but this address belongs to SEVERAL persons from DIFFERENT families. It therefore can't be used for member access.\n\n"
                        . "Please look up this email address in Jethro and contact the relevant persons to help them solve this problem.\n\n");
            $res = Emailer::send($message);
            require_once 'templates/account_request_received.template.php';
            exit;
        } elseif (!empty($failureEmail)) {
            $message = Emailer::newMessage()
                ->setSubject('Member Account request from unknown email')
                ->setFrom([MEMBER_REGO_EMAIL_FROM_ADDRESS => SYSTEM_NAME . ' Jethro System'])
                ->setTo(MEMBER_REGO_FAILURE_EMAIL)
                ->setBody("Hi, \n\nThis is an automated message from the Jethro system at " . BASE_URL . ".\n\n"
                        . "Somebody has used the form at " . BASE_URL . "/members to request member-access to this Jethro system. \n\n"
                        . "The email address they specified was " . ($_REQUEST['email'] ?? '') . " but there is no current person record in the Jethro system with that address. (There could be an archived record).\n\n"
                        . "If you believe this person is a church member, please add their email address to their person record and then ask them to try registering again.\n\n");
            $res = Emailer::send($message);
            require_once 'templates/account_request_received.template.php';
            exit;
        } else {
            require_once 'templates/account_request_received.template.php';
            exit;
        }
    }

    /**
     * Verify email link handler
     */
    private function processEmailVerification(): void
    {
        $email = $_REQUEST['email'] ?? '';
        $verify = $_REQUEST['verify'] ?? '';
        if ($person = $this->_findPendingMember($email, $verify)) {
            $this->_setAuthMember($person);
            require_once 'templates/set_password.template.php';
            exit;
        } else {
            $this->_error = 'The account request is not valid. You may have used an out-of-date link. Please try registering again.';
        }
    }

    /**
     * Handle set-password form
     */
    private function processSetPassword(): void
    {
        $db = $GLOBALS['db'];
        $val1 = $_REQUEST['password1'] ?? '';
        $val2 = $_REQUEST['password2'] ?? '';

        if ($val1 !== $val2) {
            $this->_error = 'Password and password confirmation do not match. Try again.';
            require_once 'templates/set_password.template.php';
            exit;
        } elseif (strlen($val1) < (defined('MEMBER_PASSWORD_MIN_LENGTH') ? MEMBER_PASSWORD_MIN_LENGTH : 8)) {
            $minLen = defined('MEMBER_PASSWORD_MIN_LENGTH') ? MEMBER_PASSWORD_MIN_LENGTH : 8;
            $this->_error = 'Password is too short - must be at least ' . $minLen . ' characters; Password not saved.';
            require_once 'templates/set_password.template.php';
            exit;
        } elseif (!(preg_match('/[0-9]+/', $val1) && preg_match('/[^0-9]+/', $val1))) {
            $this->_error = 'Password is too simple - it must contain letters and numbers; Password not saved.';
            require_once 'templates/set_password.template.php';
            exit;
        } else {
            $sql = 'UPDATE _person '
                 . 'SET `member_password` = ' . $db->quote(jethro_password_hash($val1)) . ', '
                 . 'resethash = NULL, '
                 . 'resetexpires = NULL '
                 . 'WHERE id = ' . (int)array_get($_SESSION, 'member.id', array_get($_SESSION['member'] ?? [], 'id', 0));
            $res = $db->exec($sql);
            if (!empty($_REQUEST['isreset'])) {
                add_message('Your password has been successfully changed.');
            } else {
                add_message('Welcome! Your account is complete and you are now logged in.');
            }
        }
    }

    /**
     * Render login form
     */
    public function printLogin(): void
    {
        $_SESSION['login_key'] = $login_key = generate_random_string(32);
        require TEMPLATE_DIR . '/login_form.template.php';
        exit;
    }

    /**
     * Get current authorised member (all fields or one field)
     */
    public function getCurrentMember($field = '')
    {
        if (empty($_SESSION['member'])) return null;
        if ($field === '' || $field === null) return $_SESSION['member'];
        return array_get($_SESSION['member'], $field, '');
    }

    /**
     * Alias
     */
    public function getCurrentPerson($field = '')
    {
        return $this->getCurrentMember($field);
    }

    /**
     * Establish the authenticated session for the specified member
     */
    private function _setAuthMember($member_details): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
        session_regenerate_id(true);

        // Do NOT wipe entire session; selectively set values
        unset($_SESSION['member'], $_SESSION['login_time'], $_SESSION['last_activity_time']);

        $_SESSION['member'] = $member_details;
        $_SESSION['login_time'] = time();
        $_SESSION['last_activity_time'] = time();

        // Clear one-time OIDC markers once logged in
        unset($_SESSION['oidc_verified_email'], $_SESSION['oidc_verified_at']);
    }

    /**
     * Clear the authenticated session
     */
    private function _clearAuthMember(): void
    {
        $_SESSION['member'] = null;
        $_SESSION['login_time'] = null;
        $_SESSION['last_activity_time'] = null;
    }

    /**
     * Find a person record suitable for attaching a member account
     *
     * @return mixed array|int|null   array for single candidate, -1 if email used by multiple families, null if none
     */
    public function findCandidateMember($email)
    {
        $db = $GLOBALS['db'];

        $sql = 'SELECT COUNT(DISTINCT familyid) '
             . 'FROM _person p '
             . 'JOIN person_status ps ON ps.id = p.status '
             . 'WHERE email = ' . $db->quote($email) . ' '
             . 'AND (NOT ps.is_archived)';
        $familyCount = $db->queryOne($sql);
        if ($familyCount > 1) return -1;

        $sql = 'SELECT p.* FROM _person p '
             . 'JOIN person_status ps ON ps.id = p.status '
             . 'JOIN age_bracket ab ON ab.id = p.age_bracketid '
             . 'WHERE p.email = ' . $db->quote($email) . ' '
             . 'AND (NOT ps.is_archived) '
             . 'ORDER BY (IF(p.member_password IS NOT NULL, 0, 1)), ab.`rank` ASC, p.gender DESC';
        return $db->queryRow($sql);
    }

    /**
     * Find a pending member by email + hash
     */
    private function _findPendingMember($email, $hash)
    {
        $db = $GLOBALS['db'];
        $sql = 'SELECT p.* FROM _person p WHERE p.email = ' . $db->quote($email)
             . ' AND resethash = ' . $db->quote($hash)
             . ' AND resetexpires > NOW()';
        return $db->queryRow($sql);
    }

    /**
     * Find a person matching the given email and password (or OIDC proof)
     * Returns array on success, FALSE if only archived match, NULL if no match
     */
    private function _findAuthMember($email, $password)
    {
        $db = $GLOBALS['db'];
        $sql = 'SELECT p.*, sm.password, ps.is_archived as status_archived '
             . 'FROM _person p '
             . 'LEFT JOIN staff_member sm ON sm.id = p.id '
             . 'JOIN person_status ps ON ps.id = p.status '
             . 'WHERE p.email = ' . $db->quote($email) . ' '
             . 'AND ((member_password IS NOT NULL) OR (sm.password IS NOT NULL))';
        $res = $db->queryAll($sql);

        $found_archived = false;
        foreach ($res as $row) {
            if (!empty($row['status_archived'])) {
                $found_archived = true;
                continue;
            }

            // Short-lived OIDC proof
            $oidcOk = (defined('OIDC_ENABLE') && OIDC_ENABLE &&
                       !empty($_SESSION['oidc_verified_email']) &&
                       hash_equals($_SESSION['oidc_verified_email'], $row['email']) &&
                       !empty($_SESSION['oidc_verified_at']) &&
                       (time() - $_SESSION['oidc_verified_at'] < 60));

            if ($oidcOk) {
                unset($row['member_password'], $row['history']);
                if (defined('OIDC_DEBUG') && OIDC_DEBUG) {
                    oidc_diag('authMember', $row);
                }
                return $row;
            }

            // Password (member area)
            if (!empty($row['member_password']) && jethro_password_verify($password, $row['member_password'])) {
                unset($row['member_password'], $row['history']);
                return $row;
            }

            // Control centre password fallback (if available)
            if (!empty($row['password']) && jethro_password_verify($password, $row['password'])) {
                unset($row['member_password'], $row['history']);
                return $row;
            }
        }

        if ($found_archived) return false;
        return null;
    }

    /**
     * Guard 2FA mobile change for staff who require 2FA
     */
    public function handle2FAMobileTelChange($person, $old_mobile): void
    {
        $staff_member = new Staff_Member($person->id);
        if (!$staff_member) return;
        if ($staff_member->requires2FA()) {
            throw new \RuntimeException('Attempt to change 2FA user\'s mobile number via the members interface');
        }
    }

    // --- Example request dispatcher (optional, adapt to your controller) ---
    public function run(): void
    {
        // Ensure a session exists early
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();

        // Logout and clear session
        if (!empty($_REQUEST['logout'])) {
		$this->_clearAuthMember();
        // Handle OIDC SSO login (User started, or callback)
	} elseif (defined('OIDC_ENABLE') && OIDC_ENABLE && (
                  !empty($_REQUEST['oidc-login']) ||
                  !empty($_REQUEST['oidc-callback']) ||
                  isset($_GET['code']) // belt-and-braces: any return with ?code should go here
	) ) {
          $this->handleOidcLoginRequest();
        // Traditional (Non-SSO) login
        } elseif (empty($_SESSION['member']) && !empty($_REQUEST['login-request'])) {
            $this->handleLoginRequest();
        } elseif (!empty($_REQUEST['password-request']) && !empty($_REQUEST['email'])) {
            $this->handleAccountRequest();
        } elseif (!empty($_REQUEST['verify'])) {
            $this->processEmailVerification();
        } elseif (!empty($_REQUEST['set-password'])) {
            $this->processSetPassword();
        }

        // Session timeout / max length enforcement
        if (!empty($_SESSION['member'])) {
            if (defined('SESSION_TIMEOUT_MINS') && constant('SESSION_TIMEOUT_MINS')) {
                if ((time() - ($_SESSION['last_activity_time'] ?? time())) / 60 > SESSION_TIMEOUT_MINS) {
                    $this->_clearAuthMember();
                    $this->printLogin();
                }
            }
            if (defined('SESSION_MAXLENGTH_MINS') && constant('SESSION_MAXLENGTH_MINS')) {
                if ((time() - ($_SESSION['login_time'] ?? time())) / 60 > SESSION_MAXLENGTH_MINS) {
                    $this->_clearAuthMember();
                    $this->printLogin();
                }
            }

            $_SESSION['last_activity_time'] = time();
            $GLOBALS['db']->setCurrentUserID((int)($_SESSION['member']['id'] ?? 0));
            $this->_loadPermissionLevels();
            return;
        } else {
            $this->printLogin();
        }
    }

    /**
     * Error holder used by various handlers
     *
     * TODO: Move to Abstract_User_System ???
     *       Should there be some more generic error logging/handling?
    */
    private $_error = '';
}
