<?php
/**
 * VulnProbe — scanner.php
 * Core scanning engine:
 *   1. cURL fetch of target page
 *   2. DOM parsing for forms & fields
 *   3. XSS payload injection + reflection detection
 *   4. SQLi payload injection + error pattern matching
 *   5. JSON response with findings
 *
 * ⚠ Educational/authorized testing use only.
 */

declare(strict_types=1);
set_time_limit(0);
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

require_once __DIR__ . '/payloads.php';

// ─── Security Headers ───────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Content-Security-Policy: default-src \"none\"; frame-ancestors \"none\"');

// ─── Input Validation ─────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    json_exit(false, 'Method not allowed.');
}

$raw_url     = trim((string)($_POST['url'] ?? ''));
$scan_xss    = !empty($_POST['scan_xss']);
$scan_sqli   = !empty($_POST['scan_sqli']);
$allow_local = false; // public deployment: disable private/local scanning by default
$intensity   = in_array($_POST['intensity'] ?? '', ['low','medium','high'], true)
               ? (string)$_POST['intensity']
               : 'low';
$timeout     = max(5, min(30, (int)($_POST['timeout'] ?? 10)));

if ($raw_url === '' || strlen($raw_url) > 2048) {
    http_response_code(400);
    json_exit(false, 'A valid target URL is required.');
}

if (!filter_var($raw_url, FILTER_VALIDATE_URL)) {
    http_response_code(400);
    json_exit(false, 'Invalid URL format. Please include http:// or https://.');
}

$parsed_url = parse_url($raw_url);
$scheme = strtolower((string)($parsed_url['scheme'] ?? ''));
if (!in_array($scheme, ['http', 'https'], true)) {
    http_response_code(400);
    json_exit(false, 'Only http and https protocols are allowed.');
}

if (isset($parsed_url['user']) || isset($parsed_url['pass'])) {
    http_response_code(400);
    json_exit(false, 'URL credentials are not allowed.');
}

$host = strtolower((string)($parsed_url['host'] ?? ''));
if ($host === '') {
    http_response_code(400);
    json_exit(false, 'The target URL must include a hostname.');
}

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$expected_origin = get_expected_origin();
if ($origin !== '' && $origin !== $expected_origin) {
    http_response_code(403);
    json_exit(false, 'Forbidden origin.');
}

if (!enforce_rate_limit($_SERVER['REMOTE_ADDR'] ?? 'unknown')) {
    http_response_code(429);
    json_exit(false, 'Too many requests. Please wait a moment and try again.');
}

if (!$allow_local && is_private_host($host)) {
    http_response_code(400);
    json_exit(false, 'Scanning localhost or private/internal IPs is blocked by default. Check "Allow localhost / private IPs" in the options to scan local pages (e.g. your demo-target.php).');
}

// ─── Step 1: Fetch the target page ───────────────────────────────────────────
$page_html = curl_get($raw_url, $timeout);

if ($page_html === false || $page_html === '') {
    json_exit(false, "Could not fetch the target URL. Check that the URL is accessible and the server is reachable. (cURL timeout: {$timeout}s)");
}

// ─── Step 2: DOM Parse — extract forms ───────────────────────────────────────
$forms = parse_forms($page_html, $raw_url);

if (empty($forms)) {
    // Return success but zero forms — still useful info
    echo json_encode([
        'success'     => true,
        'target_url'  => $raw_url,
        'forms_found' => 0,
        'fields_found'=> 0,
        'xss_tests'   => 0,
        'sqli_tests'  => 0,
        'xss_count'   => 0,
        'sqli_count'  => 0,
        'forms'       => [],
        'findings'    => [],
        'message'     => 'No HTML forms found on this page. Try a page with a login form, search box, or contact form.',
    ]);
    exit;
}

$total_fields = array_sum(array_map(fn($f) => count($f['fields']), $forms));
$xss_payloads  = $scan_xss  ? get_xss_payloads($intensity)  : [];
$sqli_payloads = $scan_sqli ? get_sqli_payloads($intensity)  : [];
$sqli_patterns = get_sqli_error_patterns();

$findings   = [];
$xss_count  = 0;
$sqli_count = 0;
$xss_tests  = 0;
$sqli_tests = 0;

// ─── Step 3 & 4: Inject payloads into each form field ────────────────────────
foreach ($forms as $form) {
    $form_action = $form['action'];
    $form_method = strtoupper($form['method']);
    $fields      = $form['fields'];

    // Only test text-like fields
    $testable = array_filter($fields, function($f) {
        return in_array(strtolower($f['type'] ?? 'text'), [
            'text','search','email','url','tel','password',
            'number','hidden','textarea',''
        ]);
    });

    if (empty($testable)) continue;

    foreach ($testable as $field) {
        $field_name = $field['name'];
        if (empty($field_name)) continue;

        // ── XSS Tests ────────────────────────────────────────────────────────
        foreach ($xss_payloads as $payload) {
            $xss_tests++;
            $post_data = build_form_data($fields, $field_name, $payload);
            $response  = submit_form($form_action, $form_method, $post_data, $timeout);

            if ($response === false) continue;

            // Check if payload is reflected verbatim in response
            if (is_xss_reflected($payload, $response)) {
                $xss_count++;
                $findings[] = [
                    'type'            => 'xss',
                    'title'           => 'Reflected XSS — Payload Not Sanitized',
                    'field'           => $field_name,
                    'form_action'     => $form_action,
                    'form_method'     => $form_method,
                    'payload'         => $payload,
                    'evidence'        => 'Payload was found verbatim in the server response without HTML encoding.',
                    'response_snippet'=> get_response_snippet($payload, $response),
                ];
                break; // one confirmed XSS per field is enough
            }
        }

        // ── SQLi Tests ───────────────────────────────────────────────────────
        foreach ($sqli_payloads as $payload) {
            $sqli_tests++;
            $post_data = build_form_data($fields, $field_name, $payload);
            $response  = submit_form($form_action, $form_method, $post_data, $timeout);

            if ($response === false) continue;

            $matched_pattern = detect_sqli_error($response, $sqli_patterns);
            if ($matched_pattern) {
                $sqli_count++;
                $findings[] = [
                    'type'            => 'sqli',
                    'title'           => 'SQL Injection — Database Error Exposed',
                    'field'           => $field_name,
                    'form_action'     => $form_action,
                    'form_method'     => $form_method,
                    'payload'         => $payload,
                    'evidence'        => $matched_pattern,
                    'response_snippet'=> get_response_snippet($matched_pattern, $response, 200),
                ];
                break; // one confirmed SQLi per field is enough
            }
        }
    }
}

// ─── Response ─────────────────────────────────────────────────────────────────
echo json_encode([
    'success'      => true,
    'target_url'   => $raw_url,
    'forms_found'  => count($forms),
    'fields_found' => $total_fields,
    'xss_tests'    => $xss_tests,
    'sqli_tests'   => $sqli_tests,
    'xss_count'    => $xss_count,
    'sqli_count'   => $sqli_count,
    'forms'        => $forms,
    'findings'     => $findings,
]);
exit;


// =============================================================================
// Helper Functions
// =============================================================================

/**
 * cURL GET — fetch page HTML
 */
function curl_get(string $url, int $timeout): string|false {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_HTTPHEADER     => [
            'Accept: text/html,application/xhtml+xml,*/*',
            'Accept-Language: en-US,en;q=0.9',
        ],
    ]);
    $result = curl_exec($ch);
    $error  = curl_error($ch);
    curl_close($ch);

    if ($error || $result === false) return false;
    return (string)$result;
}

/**
 * cURL form submission (GET or POST)
 */
function submit_form(string $action, string $method, array $data, int $timeout): string|false {
    $ch = curl_init();
    $query = http_build_query($data);

    $opts = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => max(5, (int)($timeout * 0.4)),
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
        CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
    ];

    if ($method === 'POST') {
        $opts[CURLOPT_URL]        = $action;
        $opts[CURLOPT_POST]       = true;
        $opts[CURLOPT_POSTFIELDS] = $query;
        $opts[CURLOPT_HTTPHEADER] = [
            'Content-Type: application/x-www-form-urlencoded',
        ];
    } else {
        // GET — append query string
        $sep = str_contains($action, '?') ? '&' : '?';
        $opts[CURLOPT_URL] = $action . $sep . $query;
    }

    curl_setopt_array($ch, $opts);
    $result = curl_exec($ch);
    curl_close($ch);

    return ($result !== false) ? (string)$result : false;
}

/**
 * Parse all HTML forms from page source using PHP's DOMDocument
 */
function parse_forms(string $html, string $base_url): array {
    $dom = new DOMDocument();
    libxml_use_internal_errors(true);
    $dom->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING);
    libxml_clear_errors();

    $forms  = [];
    $base   = rtrim($base_url, '/');
    $parsed = parse_url($base_url);
    $origin = ($parsed['scheme'] ?? 'http') . '://' . ($parsed['host'] ?? '');

    foreach ($dom->getElementsByTagName('form') as $formEl) {
        $action = trim($formEl->getAttribute('action'));
        $method = strtoupper($formEl->getAttribute('method') ?: 'GET');

        // Resolve action URL safely and reject dangerous schemes
        if (empty($action) || $action === '#') {
            $action = $base_url;
        } else {
            $action_parts = parse_url($action);
            $scheme_check = strtolower((string)($action_parts['scheme'] ?? ''));
            if (isset($action_parts['scheme']) && !in_array($scheme_check, ['http', 'https'], true)) {
                $action = $base_url;
            } elseif (str_starts_with($action, '//')) {
                $action = ($parsed['scheme'] ?? 'https') . ':' . $action;
            } elseif (str_starts_with($action, '/')) {
                $action = $origin . $action;
            } elseif (!str_starts_with($action, 'http')) {
                $dir    = dirname($base_url);
                $action = $dir . '/' . $action;
            }
        }

        $fields = [];

        // Collect <input> fields
        foreach ($formEl->getElementsByTagName('input') as $input) {
            $name  = $input->getAttribute('name');
            $type  = strtolower($input->getAttribute('type') ?: 'text');
            $value = $input->getAttribute('value');
            if ($type === 'submit' || $type === 'button' || $type === 'image' || $type === 'reset') continue;
            if (!empty($name)) {
                $fields[] = ['name' => $name, 'type' => $type, 'value' => $value];
            }
        }

        // Collect <textarea> fields
        foreach ($formEl->getElementsByTagName('textarea') as $ta) {
            $name = $ta->getAttribute('name');
            if (!empty($name)) {
                $fields[] = ['name' => $name, 'type' => 'textarea', 'value' => $ta->textContent];
            }
        }

        // Collect <select> fields
        foreach ($formEl->getElementsByTagName('select') as $sel) {
            $name = $sel->getAttribute('name');
            if (!empty($name)) {
                // Get first option value
                $opts   = $sel->getElementsByTagName('option');
                $val    = $opts->length > 0 ? $opts->item(0)->getAttribute('value') : '';
                $fields[] = ['name' => $name, 'type' => 'select', 'value' => $val];
            }
        }

        $forms[] = [
            'action' => $action,
            'method' => $method,
            'fields' => $fields,
        ];
    }

    return $forms;
}

/**
 * Build POST/GET data array — inject payload into target field
 */
function build_form_data(array $fields, string $target_field, string $payload): array {
    $data = [];
    foreach ($fields as $field) {
        if ($field['name'] === $target_field) {
            $data[$field['name']] = $payload;
        } else {
            // Fill other fields with harmless defaults
            $data[$field['name']] = match($field['type'] ?? 'text') {
                'email'    => 'test@example.com',
                'password' => 'TestPass123!',
                'number'   => '1',
                'url'      => 'https://example.com',
                default    => 'test',
            };
        }
    }
    return $data;
}

/**
 * Check if XSS payload is reflected verbatim (not HTML-encoded) in response
 */
function is_xss_reflected(string $payload, string $response): bool {
    // Check raw reflection
    if (str_contains($response, $payload)) return true;

    // Check case-insensitive for tag-based payloads
    if (preg_match('/<script|onerror|onload|onfocus|ontoggle/i', $payload)) {
        // Look for the key dangerous attribute/tag in response without encoding
        $tag_match = preg_match('/<script[\s>]|onerror\s*=|onload\s*=|onfocus\s*=/i', $response);
        if ($tag_match && str_contains(strtolower($response), strtolower(substr($payload, 0, 10)))) {
            return true;
        }
    }

    return false;
}

/**
 * Detect SQL error patterns in response
 * Returns the matched description or false
 */
function detect_sqli_error(string $response, array $patterns): string|false {
    foreach ($patterns as $pattern => $description) {
        if (preg_match($pattern, $response)) {
            return $description;
        }
    }
    return false;
}

/**
 * Extract a snippet of the response around the found string
 */
function get_response_snippet(string $needle, string $haystack, int $context = 150): string {
    $pos = stripos($haystack, $needle);
    if ($pos === false) {
        $body_start = stripos($haystack, '<body');
        $str = substr(strip_tags($haystack), $body_start > 0 ? $body_start : 0, 300);
        return mb_convert_encoding($str, 'UTF-8', 'UTF-8');
    }
    $start  = max(0, $pos - $context);
    $length = strlen($needle) + ($context * 2);
    $str = substr($haystack, $start, $length);
    return mb_convert_encoding($str, 'UTF-8', 'UTF-8');
}

/**
 * Block private/localhost hosts (basic SSRF protection)
 */
function is_private_host(string $host): bool {
    $host = strtolower(trim($host));

    if (in_array($host, ['localhost', '::1', '[::1]'], true)) return true;

    $ip = gethostbyname($host);
    if ($ip === $host && !filter_var($ip, FILTER_VALIDATE_IP)) return false;

    return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}

function get_expected_origin(): string {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
    return $scheme . '://' . $host;
}

/**
 * Basic file-backed rate limit to reduce abuse.
 */
function enforce_rate_limit(string $remote_addr): bool {
    $dir = __DIR__ . '/storage';
    if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) {
        return true;
    }

    $key = hash('sha256', $remote_addr ?: 'unknown');
    $path = $dir . '/rate-limit-' . substr($key, 0, 16) . '.json';
    $now = time();
    $entries = [];

    if (is_file($path)) {
        $raw = @file_get_contents($path);
        if ($raw !== false) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $entries = array_values(array_filter($decoded, fn($ts): bool => is_int($ts) && $ts > $now - 60));
            }
        }
    }

    $entries[] = $now;
    if (count($entries) > 10) {
        return false;
    }

    @file_put_contents($path, json_encode($entries, JSON_PRETTY_PRINT), LOCK_EX);
    return true;
}

/**
 * Output JSON error and exit
 */
function json_exit(bool $success, string $error): never {
    echo json_encode(['success' => $success, 'error' => $error], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}
