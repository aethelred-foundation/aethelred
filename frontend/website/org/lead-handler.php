<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('X-Robots-Tag: noindex, nofollow', true);

const ALLOWED_TYPES = [
    'Venture Capital',
    'Private Equity',
    'Family Office',
    'Corporate Development',
    'Sovereign / Strategic Capital'
];

const ALLOWED_REGIONS = [
    '',
    'North America',
    'Europe',
    'MENA',
    'APAC',
    'Global / Multi-region'
];

function env_string(string $key, string $default = ''): string
{
    $value = getenv($key);
    if ($value === false || $value === null) {
        return $default;
    }
    return trim((string)$value);
}

function env_int(string $key, int $default): int
{
    $value = env_string($key);
    if ($value === '' || !is_numeric($value)) {
        return $default;
    }
    return (int)$value;
}

function normalize_text($value, int $maxLength = 0): string
{
    $text = preg_replace('/\s+/u', ' ', trim((string)($value ?? '')));
    if (!is_string($text)) {
        $text = '';
    }
    if ($maxLength > 0 && strlen($text) > $maxLength) {
        $text = substr($text, 0, $maxLength);
    }
    return $text;
}

function normalize_origin(string $origin): string
{
    $origin = trim($origin);
    if ($origin === '') {
        return '';
    }
    $parts = parse_url($origin);
    if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
        return '';
    }
    $normalized = strtolower($parts['scheme']) . '://' . strtolower($parts['host']);
    if (!empty($parts['port'])) {
        $normalized .= ':' . (int)$parts['port'];
    }
    return $normalized;
}

function parse_allowed_origins(): array
{
    $raw = env_string('AETHELRED_ALLOWED_ORIGINS');
    if ($raw === '') {
      return [];
    }

    $origins = array_map('trim', explode(',', $raw));
    $origins = array_filter($origins, static function ($origin) {
        return $origin !== '';
    });

    return array_values(array_map('normalize_origin', $origins));
}

function apply_origin_headers(array $allowedOrigins): void
{
    $origin = normalize_origin((string)($_SERVER['HTTP_ORIGIN'] ?? ''));
    if ($origin === '' || empty($allowedOrigins) || !in_array($origin, $allowedOrigins, true)) {
        return;
    }

    header('Access-Control-Allow-Origin: ' . $origin);
    header('Vary: Origin', false);
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
}

function json_response(int $status, array $payload): void
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function parse_payload(): array
{
    $contentType = strtolower((string)($_SERVER['CONTENT_TYPE'] ?? ''));
    $raw = file_get_contents('php://input');

    if (strpos($contentType, 'application/json') !== false) {
        $decoded = json_decode((string)$raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    if (!empty($_POST)) {
        return $_POST;
    }

    $parsed = [];
    parse_str((string)$raw, $parsed);
    return is_array($parsed) ? $parsed : [];
}

function client_ip(): string
{
    $forwarded = normalize_text($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '', 255);
    if ($forwarded !== '') {
        $parts = explode(',', $forwarded);
        return normalize_text($parts[0] ?? '', 120);
    }
    return normalize_text($_SERVER['REMOTE_ADDR'] ?? 'unknown', 120);
}

function hash_value(string $value): string
{
    $salt = env_string('AETHELRED_PII_SALT');
    return hash('sha256', $value . ($salt !== '' ? '|' . $salt : ''));
}

function append_jsonl(string $path, array $payload): bool
{
    $line = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($line === false) {
        return false;
    }
    return file_put_contents($path, $line . PHP_EOL, FILE_APPEND | LOCK_EX) !== false;
}

function ensure_directory(string $path): bool
{
    if (is_dir($path)) {
        return true;
    }
    return mkdir($path, 0755, true) || is_dir($path);
}

function check_rate_limit(string $storageDir, string $ipHash): ?array
{
    $windowSeconds = env_int('AETHELRED_LEAD_WINDOW_SECONDS', 600);
    $windowLimit = env_int('AETHELRED_LEAD_RATE_LIMIT', 10);
    $dailyLimit = env_int('AETHELRED_LEAD_DAILY_LIMIT', 50);
    $path = $storageDir . DIRECTORY_SEPARATOR . 'lead-rate-limit.json';
    $handle = fopen($path, 'c+');

    if ($handle === false) {
        return null;
    }

    if (!flock($handle, LOCK_EX)) {
        fclose($handle);
        return null;
    }

    $raw = stream_get_contents($handle);
    $state = json_decode($raw !== false && $raw !== '' ? $raw : '{}', true);
    if (!is_array($state)) {
        $state = [];
    }

    $now = time();
    $today = gmdate('Y-m-d');

    foreach ($state as $key => $bucket) {
        if (!is_array($bucket)) {
            unset($state[$key]);
            continue;
        }

        $hits = array_values(array_filter($bucket['hits'] ?? [], static function ($ts) use ($now, $windowSeconds) {
            return is_numeric($ts) && ($now - (int)$ts) < $windowSeconds;
        }));

        $bucket['hits'] = $hits;
        if (($bucket['day'] ?? '') !== $today) {
            $bucket['day'] = $today;
            $bucket['dayCount'] = 0;
        }

        if (empty($bucket['hits']) && (int)($bucket['dayCount'] ?? 0) === 0) {
            unset($state[$key]);
            continue;
        }

        $state[$key] = $bucket;
    }

    $bucket = $state[$ipHash] ?? [
        'day' => $today,
        'dayCount' => 0,
        'hits' => []
    ];

    if (($bucket['day'] ?? '') !== $today) {
        $bucket['day'] = $today;
        $bucket['dayCount'] = 0;
        $bucket['hits'] = [];
    }

    $bucket['hits'] = array_values(array_filter($bucket['hits'] ?? [], static function ($ts) use ($now, $windowSeconds) {
        return is_numeric($ts) && ($now - (int)$ts) < $windowSeconds;
    }));

    $result = null;

    if (count($bucket['hits']) >= $windowLimit) {
        $retryAfter = max(1, $windowSeconds - ($now - (int)$bucket['hits'][0]));
        $result = [
            'status' => 429,
            'message' => 'Too many submissions from this source. Try again shortly.',
            'retryAfter' => $retryAfter
        ];
    } elseif ((int)($bucket['dayCount'] ?? 0) >= $dailyLimit) {
        $result = [
            'status' => 429,
            'message' => 'Daily submission limit reached for this source.',
            'retryAfter' => 3600
        ];
    } else {
        $bucket['hits'][] = $now;
        $bucket['dayCount'] = (int)($bucket['dayCount'] ?? 0) + 1;
        $state[$ipHash] = $bucket;
    }

    rewind($handle);
    ftruncate($handle, 0);
    fwrite($handle, json_encode($state, JSON_UNESCAPED_SLASHES));
    fflush($handle);
    flock($handle, LOCK_UN);
    fclose($handle);

    return $result;
}

function notify_webhook(array $record): array
{
    $url = env_string('AETHELRED_LEAD_WEBHOOK_URL');
    if ($url === '') {
        return ['configured' => false, 'ok' => false, 'status' => 0];
    }

    $headers = [
        'Content-Type: application/json; charset=UTF-8'
    ];
    $token = env_string('AETHELRED_LEAD_WEBHOOK_TOKEN');
    if ($token !== '') {
        $headers[] = 'Authorization: Bearer ' . $token;
    }

    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => implode("\r\n", $headers),
            'content' => json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            'timeout' => 5,
            'ignore_errors' => true
        ]
    ]);

    $response = @file_get_contents($url, false, $context);
    $status = 0;
    $responseHeaders = function_exists('http_get_last_response_headers') ? http_get_last_response_headers() : [];
    if (!empty($responseHeaders[0]) && preg_match('/\s(\d{3})\s/', (string)$responseHeaders[0], $matches)) {
        $status = (int)$matches[1];
    }

    return [
        'configured' => true,
        'ok' => $status >= 200 && $status < 300,
        'status' => $status,
        'error' => $response === false ? 'Webhook delivery failed.' : ''
    ];
}

function notify_mail(array $record): array
{
    $to = env_string('AETHELRED_LEAD_NOTIFY_EMAIL');
    if ($to === '') {
        return ['configured' => false, 'ok' => false];
    }

    $replyTo = normalize_text($record['lead']['email'] ?? '', 150);
    $from = env_string('AETHELRED_LEAD_FROM_EMAIL');
    $headers = [
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8'
    ];

    if ($from !== '') {
        $headers[] = 'From: ' . $from;
    }
    if ($replyTo !== '') {
        $headers[] = 'Reply-To: ' . $replyTo;
    }

    $subject = '[Aethelred] New institutional access request: ' . normalize_text($record['lead']['institution'] ?? 'Unknown', 120);
    $body = implode("\n", [
        'Lead ID: ' . ($record['id'] ?? ''),
        'Created At: ' . ($record['createdAt'] ?? ''),
        'Name: ' . ($record['lead']['name'] ?? ''),
        'Email: ' . ($record['lead']['email'] ?? ''),
        'Institution: ' . ($record['lead']['institution'] ?? ''),
        'Investor Type: ' . ($record['lead']['type'] ?? ''),
        'Region: ' . ($record['lead']['region'] ?? ''),
        'Timeline: ' . ($record['lead']['timeline'] ?? ''),
        'Source URL: ' . ($record['lead']['sourceUrl'] ?? ''),
        'Message:',
        (string)($record['lead']['message'] ?? '')
    ]);

    return [
        'configured' => true,
        'ok' => @mail($to, $subject, $body, implode("\r\n", $headers))
    ];
}

$allowedOrigins = parse_allowed_origins();
apply_origin_headers($allowedOrigins);

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Allow: POST, OPTIONS');
    http_response_code(204);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(405, [
        'ok' => false,
        'message' => 'Method not allowed'
    ]);
}

$origin = normalize_origin((string)($_SERVER['HTTP_ORIGIN'] ?? ''));
if ($origin !== '' && !empty($allowedOrigins) && !in_array($origin, $allowedOrigins, true)) {
    json_response(403, [
        'ok' => false,
        'message' => 'Origin not allowed'
    ]);
}

$payload = parse_payload();
$lead = [
    'name' => normalize_text($payload['name'] ?? '', 120),
    'email' => normalize_text($payload['email'] ?? '', 150),
    'institution' => normalize_text($payload['institution'] ?? '', 160),
    'type' => normalize_text($payload['type'] ?? '', 120),
    'region' => normalize_text($payload['region'] ?? '', 120),
    'timeline' => normalize_text($payload['timeline'] ?? '', 120),
    'message' => normalize_text($payload['message'] ?? '', 2400),
    'website' => normalize_text($payload['website'] ?? '', 200),
    'startedAt' => normalize_text($payload['startedAt'] ?? '', 64),
    'sourcePath' => normalize_text($payload['sourcePath'] ?? '', 240),
    'sourceUrl' => normalize_text($payload['sourceUrl'] ?? '', 512),
    'consent' => filter_var($payload['consent'] ?? false, FILTER_VALIDATE_BOOLEAN)
];

if ($lead['website'] !== '') {
    json_response(200, [
        'ok' => true,
        'message' => 'Submission received'
    ]);
}

$errors = [];

if ($lead['name'] === '' || strlen($lead['name']) < 2) {
    $errors[] = 'Enter your full name.';
}

if ($lead['email'] === '' || !filter_var($lead['email'], FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'Enter a valid work email.';
}

if ($lead['institution'] === '' || strlen($lead['institution']) < 2) {
    $errors[] = 'Enter your institution.';
}

if ($lead['type'] === '' || !in_array($lead['type'], ALLOWED_TYPES, true)) {
    $errors[] = 'Select a valid investor type.';
}

if (!in_array($lead['region'], ALLOWED_REGIONS, true)) {
    $errors[] = 'Select a valid jurisdiction focus.';
}

if (!$lead['consent']) {
    $errors[] = 'Accept the consent notice to continue.';
}

if ($lead['startedAt'] !== '') {
    $started = strtotime($lead['startedAt']);
    if ($started === false) {
        $errors[] = 'Submission metadata is invalid.';
    } else {
        $age = time() - $started;
        if ($age < 2) {
            json_response(200, [
                'ok' => true,
                'message' => 'Submission received'
            ]);
        }
        if ($age > 86400) {
            $errors[] = 'Form session expired. Reload and try again.';
        }
    }
}

if (!empty($errors)) {
    json_response(422, [
        'ok' => false,
        'message' => $errors[0],
        'errors' => $errors
    ]);
}

$storageDir = __DIR__ . DIRECTORY_SEPARATOR . 'data';
if (!ensure_directory($storageDir)) {
    json_response(500, [
        'ok' => false,
        'message' => 'Unable to initialize storage'
    ]);
}

$ipHash = hash_value(client_ip());
$rateLimit = check_rate_limit($storageDir, $ipHash);
if (is_array($rateLimit)) {
    header('Retry-After: ' . (string)$rateLimit['retryAfter']);
    json_response((int)$rateLimit['status'], [
        'ok' => false,
        'message' => (string)$rateLimit['message']
    ]);
}

$leadId = 'lead_' . base_convert((string)time(), 10, 36) . '_' . bin2hex(random_bytes(4));
$record = [
    'id' => $leadId,
    'createdAt' => gmdate('c'),
    'lead' => $lead,
    'meta' => [
        'ipHash' => $ipHash,
        'origin' => $origin,
        'userAgent' => normalize_text($_SERVER['HTTP_USER_AGENT'] ?? '', 300),
        'referer' => normalize_text($_SERVER['HTTP_REFERER'] ?? '', 300)
    ]
];

$storageFile = $storageDir . DIRECTORY_SEPARATOR . 'leads.jsonl';
if (!append_jsonl($storageFile, $record)) {
    json_response(500, [
        'ok' => false,
        'message' => 'Unable to store request right now'
    ]);
}

$deliveryLog = [
    'leadId' => $leadId,
    'createdAt' => gmdate('c'),
    'webhook' => notify_webhook($record),
    'mail' => notify_mail($record)
];
append_jsonl($storageDir . DIRECTORY_SEPARATOR . 'lead-delivery.jsonl', $deliveryLog);

json_response(201, [
    'ok' => true,
    'id' => $leadId,
    'message' => 'Lead request captured'
]);
