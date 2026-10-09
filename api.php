<?php
// Server-side proxy: logs in to the Expo API and returns sessions or speakers,
// so credentials never reach the browser.
// Usage: api.php?type=sessions | api.php?type=speakers

header('Content-Type: application/json');

$configFile = __DIR__ . '/config.php';
if (!is_file($configFile)) {
    http_response_code(500);
    echo json_encode(['error' => 'config.php missing. Copy config.example.php to config.php.']);
    exit;
}
$config = require $configFile;

$endpoints = [
    'sessions' => '/session/GetSessionsWeb',
    'speakers' => '/session/GetAllSpeakerInfo',
];

$type = $_GET['type'] ?? '';
if (!isset($endpoints[$type])) {
    http_response_code(400);
    echo json_encode(['error' => 'type must be "sessions" or "speakers"']);
    exit;
}

function request(string $method, string $url, array $headers, ?string $body = null): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 30,
    ]);
    if ($body !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }
    $response = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $error = curl_error($ch);

    if ($response === false) {
        return [502, json_encode(['error' => 'Upstream request failed: ' . $error])];
    }
    return [$status, $response];
}

// Mirrors findToken() from the front end: accepts a raw JWT string or
// looks for common token keys, recursing into nested objects.
function findToken($payload): string
{
    if (is_string($payload)) {
        $trimmed = trim($payload, " \t\n\r\"");
        return (count(explode('.', $trimmed)) === 3 || strlen($trimmed) > 30) ? $trimmed : '';
    }
    if (!is_array($payload)) {
        return '';
    }

    $keys = ['token', 'accesstoken', 'access_token', 'jwttoken', 'jwt', 'authtoken', 'bearertoken', 'idtoken'];
    foreach ($payload as $key => $value) {
        if (is_string($key) && in_array(strtolower($key), $keys, true) && is_string($value) && trim($value) !== '') {
            return trim($value);
        }
    }
    foreach ($payload as $value) {
        if (is_array($value) && ($nested = findToken($value)) !== '') {
            return $nested;
        }
    }
    return '';
}

[$status, $body] = request('POST', $config['api_base'] . '/login', [
    'Accept: application/json',
    'Content-Type: application/json',
], json_encode(['username' => $config['username'], 'password' => $config['password']]));

if ($status < 200 || $status >= 300) {
    http_response_code($status ?: 502);
    echo json_encode(['error' => "Login failed (HTTP $status)"]);
    exit;
}

$loginData = json_decode($body, true);
$token = findToken($loginData ?? $body);
if ($token === '') {
    http_response_code(502);
    echo json_encode(['error' => 'Login succeeded but no token found in response']);
    exit;
}
if (stripos($token, 'bearer ') !== 0) {
    $token = 'Bearer ' . $token;
}

$url = $config['api_base'] . $endpoints[$type] . '?conferenceid=' . urlencode((string) $config['conference_id']);
[$status, $body] = request('GET', $url, [
    'Accept: application/json',
    'Authorization: ' . $token,
]);

http_response_code($status);
echo $body;
