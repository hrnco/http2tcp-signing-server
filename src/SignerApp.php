<?php
declare(strict_types=1);

final class SignerApp
{
    private string $keysDir;
    private int $ttlSeconds;
    private string $appEnv;

    public function __construct(string $envPath)
    {
        $env = $this->loadEnv($envPath);
        $this->keysDir = rtrim($this->getEnvValue($env, 'KEYS_DIR', '/keys'), '/');
        $this->ttlSeconds = (int)$this->getEnvValue($env, 'TTL_SECONDS', 300);
        $this->appEnv = strtolower((string)$this->getEnvValue($env, 'APP_ENV', 'prod'));
    }

    public function handle(): void
    {
        $this->sendCors();

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(204);
            return;
        }

        $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
        if ($path === '/') {
            $this->handleRoot();
            return;
        }
        if ($path !== '/api/sign') {
            $this->respondJson(404, ['error' => 'not_found']);
            return;
        }

        $debug = false;
        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            $payloadHex = trim((string)($_GET['payloadHex'] ?? ''));
            $payloadBase64 = trim((string)($_GET['payloadBase64'] ?? ''));
            $deviceIp = trim((string)($_GET['deviceIp'] ?? ''));
            $devicePort = (int)($_GET['devicePort'] ?? 0);
            $deviceId = trim((string)($_GET['deviceId'] ?? ''));
            $debug = ((string)($_GET['debug'] ?? '')) === '1';
        } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $inputRaw = file_get_contents('php://input') ?: '';
            $input = json_decode($inputRaw, true);
            if (!is_array($input)) {
                $this->respondJson(400, ['error' => 'invalid_json']);
                return;
            }
            $payloadHex = trim((string)($input['payloadHex'] ?? ''));
            $payloadBase64 = trim((string)($input['payloadBase64'] ?? ''));
            $deviceIp = trim((string)($input['deviceIp'] ?? ''));
            $devicePort = (int)($input['devicePort'] ?? 0);
            $deviceId = trim((string)($input['deviceId'] ?? ''));
            $debug = ((string)($input['debug'] ?? '')) === '1';
        } else {
            $this->respondJson(405, ['error' => 'method_not_allowed']);
            return;
        }
        $debug = $debug && $this->appEnv === 'dev';

        if ($payloadHex === '' && $payloadBase64 === '') {
            $this->respondJson(400, ['error' => 'payload_required']);
            return;
        }
        if ($payloadHex !== '' && $payloadBase64 !== '') {
            $this->respondJson(400, ['error' => 'payload_conflict']);
            return;
        }
        if ($payloadHex !== '' && !ctype_xdigit($payloadHex)) {
            $this->respondJson(400, ['error' => 'invalid_payload_hex']);
            return;
        }
        if ($payloadBase64 !== '' && $this->decodeBase64($payloadBase64) === null) {
            $this->respondJson(400, ['error' => 'invalid_payload_base64']);
            return;
        }
        if (!filter_var($deviceIp, FILTER_VALIDATE_IP)) {
            $this->respondJson(400, ['error' => 'invalid_device_ip']);
            return;
        }
        if ($devicePort < 1 || $devicePort > 65535) {
            $this->respondJson(400, ['error' => 'invalid_device_port']);
            return;
        }
        if ($deviceId !== '' && !preg_match('/^[A-Za-z0-9_-]{1,64}$/', $deviceId)) {
            $this->respondJson(400, ['error' => 'invalid_device_id']);
            return;
        }

        if ($deviceId !== '') {
            [$kid, $privatePemPath] = $this->ensureDeviceKey($this->keysDir, $deviceId);
        } else {
            [$kid, $privatePemPath] = $this->ensureDefaultKey($this->keysDir);
        }

        $instructionsPayload = [
            'deviceIp' => $deviceIp,
            'devicePort' => $devicePort,
        ];
        if ($payloadHex !== '') {
            $instructionsPayload['payloadHex'] = $payloadHex;
        } else {
            $instructionsPayload['payloadBase64'] = $payloadBase64;
        }
        if ($deviceId !== '') {
            $instructionsPayload['deviceId'] = $deviceId;
        }
        $instructions = $this->base64urlEncode(
            json_encode($instructionsPayload, JSON_UNESCAPED_SLASHES)
        );

        $exp = time() + max(1, $this->ttlSeconds);
        $nonce = $this->base64urlEncode(random_bytes(16));

        $params = $this->buildParamsString([
            'instructions' => $instructions,
            'kid' => $kid,
            'exp' => (string)$exp,
            'nonce' => $nonce,
        ]);

        $sig = $this->opensslSignEd25519($params, $privatePemPath);
        $response = $params . '&sig=' . rawurlencode($sig);

        if ($debug) {
            header('Content-Type: text/html; charset=utf-8');
            $this->renderDebug($response, [
                'instructions_url_decoded' => $instructionsPayload,
                'instructions_url_base64' => $instructions,
                'kid' => $kid,
                'exp' => $exp,
                'nonce' => $nonce,
                'sig_base64url' => $sig,
                'params' => $params,
            ]);
            return;
        }

        header('Content-Type: text/plain; charset=utf-8');
        echo $response;
    }

    private function sendCors(): void
    {
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Headers: Content-Type');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    }

    private function handleRoot(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
            $this->respondJson(405, ['error' => 'method_not_allowed']);
            return;
        }

        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html><head><meta charset="utf-8"><title>http2tcp-signing-server</title></head><body>';
        echo '<h1>http2tcp-signing-server</h1>';
        echo '<p>Server is running. You can use GET or POST on <code>/api/sign</code>.</p>';
        echo '<h2>Quick test</h2>';
        echo '<form method="get" action="/api/sign">';
        echo '<label>payloadHex <input name="payloadHex" size="40" value="48656c6c6f207072696e746572"></label><br>';
        echo '<label>deviceIp <input name="deviceIp" value="192.168.1.50"></label><br>';
        echo '<label>devicePort <input name="devicePort" value="9100"></label><br>';
        echo '<label>deviceId <input name="deviceId" value=""></label><br>';
        echo '<label><input type="checkbox" name="debug" value="1" checked> debug</label><br>';
        echo '<button type="submit">Sign</button>';
        echo '</form>';
        echo '<h2>cURL</h2>';
        echo '<pre>curl -s -X POST "http://localhost:8080/api/sign" \\' . "\n";
        echo '  -H "Content-Type: application/json" \\' . "\n";
        echo '  -d \'{"payloadHex":"48656c6c6f207072696e746572","deviceIp":"192.168.1.50","devicePort":9100}\'</pre>';
        echo '</body></html>';
    }

    private function renderDebug(string $response, array $details): void
    {
        echo '<!doctype html><html><head><meta charset="utf-8"><title>Debug</title></head><body>';
        echo '<h1>Result</h1>';
        echo '<pre>' . htmlspecialchars($response, ENT_QUOTES, 'UTF-8') . '</pre>';
        echo '<hr>';
        echo '<h2>Details</h2>';
        echo '<pre>' . htmlspecialchars(json_encode($details, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), ENT_QUOTES, 'UTF-8') . '</pre>';
        echo '</body></html>';
    }

    private function respondJson(int $status, array $payload): void
    {
        http_response_code($status);
        header('Content-Type: application/json');
        echo json_encode($payload);
    }

    private function loadEnv(string $path): array
    {
        if (!is_file($path)) {
            return [];
        }
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        $env = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $parts = explode('=', $line, 2);
            if (count($parts) !== 2) {
                continue;
            }
            $key = trim($parts[0]);
            $value = trim($parts[1]);
            $env[$key] = $value;
        }
        return $env;
    }

    private function getEnvValue(array $fileEnv, string $key, $default)
    {
        if (array_key_exists($key, $_ENV)) {
            return $_ENV[$key];
        }
        if (array_key_exists($key, $fileEnv)) {
            return $fileEnv[$key];
        }
        return $default;
    }

    private function ensureDefaultKey(string $keysDir): array
    {
        $defaultDir = $keysDir . '/default';
        $privatePem = $defaultDir . '/private.pem';
        $publicPem = $defaultDir . '/public.pem';
        $kidFile = $defaultDir . '/kid';

        if (!is_dir($defaultDir)) {
            mkdir($defaultDir, 0700, true);
        }

        if (!is_file($privatePem)) {
            $tmpDir = $defaultDir . '/.tmp';
            if (!is_dir($tmpDir)) {
                mkdir($tmpDir, 0700, true);
            }
            $tmpPrivate = $tmpDir . '/private.pem';
            $tmpPublic = $tmpDir . '/public.pem';
            $this->runCmd(sprintf('openssl genpkey -algorithm ED25519 -out %s', escapeshellarg($tmpPrivate)));
            $this->runCmd(sprintf('openssl pkey -in %s -pubout -out %s', escapeshellarg($tmpPrivate), escapeshellarg($tmpPublic)));
            rename($tmpPrivate, $privatePem);
            rename($tmpPublic, $publicPem);
        }

        if (!is_file($publicPem)) {
            $this->runCmd(sprintf('openssl pkey -in %s -pubout -out %s', escapeshellarg($privatePem), escapeshellarg($publicPem)));
        }

        $kid = is_file($kidFile) ? trim((string)file_get_contents($kidFile)) : '';
        if ($kid === '') {
            $raw = $this->rawPublicKeyFromPem($publicPem);
            $kid = $this->base64urlEncode($raw);
            file_put_contents($kidFile, $kid);
        }

        $kidDir = $keysDir . '/' . $kid;
        if (!is_dir($kidDir)) {
            mkdir($kidDir, 0700, true);
        }
        if (!is_file($kidDir . '/private.pem')) {
            copy($privatePem, $kidDir . '/private.pem');
        }
        if (!is_file($kidDir . '/public.pem')) {
            copy($publicPem, $kidDir . '/public.pem');
        }

        return [$kid, $kidDir . '/private.pem'];
    }

    private function ensureDeviceKey(string $keysDir, string $deviceId): array
    {
        $deviceDir = $keysDir . '/devices/' . $deviceId;
        $privatePem = $deviceDir . '/private.pem';
        $publicPem = $deviceDir . '/public.pem';
        $kidFile = $deviceDir . '/kid';

        if (!is_dir($deviceDir)) {
            mkdir($deviceDir, 0700, true);
        }

        if (!is_file($privatePem)) {
            $tmpDir = $deviceDir . '/.tmp';
            if (!is_dir($tmpDir)) {
                mkdir($tmpDir, 0700, true);
            }
            $tmpPrivate = $tmpDir . '/private.pem';
            $tmpPublic = $tmpDir . '/public.pem';
            $this->runCmd(sprintf('openssl genpkey -algorithm ED25519 -out %s', escapeshellarg($tmpPrivate)));
            $this->runCmd(sprintf('openssl pkey -in %s -pubout -out %s', escapeshellarg($tmpPrivate), escapeshellarg($tmpPublic)));
            rename($tmpPrivate, $privatePem);
            rename($tmpPublic, $publicPem);
        }

        if (!is_file($publicPem)) {
            $this->runCmd(sprintf('openssl pkey -in %s -pubout -out %s', escapeshellarg($privatePem), escapeshellarg($publicPem)));
        }

        $kid = is_file($kidFile) ? trim((string)file_get_contents($kidFile)) : '';
        if ($kid === '') {
            $raw = $this->rawPublicKeyFromPem($publicPem);
            $kid = $this->base64urlEncode($raw);
            file_put_contents($kidFile, $kid);
        }

        $kidDir = $keysDir . '/' . $kid;
        if (!is_dir($kidDir)) {
            mkdir($kidDir, 0700, true);
        }
        if (!is_file($kidDir . '/private.pem')) {
            copy($privatePem, $kidDir . '/private.pem');
        }
        if (!is_file($kidDir . '/public.pem')) {
            copy($publicPem, $kidDir . '/public.pem');
        }

        return [$kid, $kidDir . '/private.pem'];
    }

    private function rawPublicKeyFromPem(string $publicPemPath): string
    {
        $tmpDer = tempnam(sys_get_temp_dir(), 'pubder_');
        $this->runCmd(sprintf(
            'openssl pkey -pubin -in %s -outform DER -out %s',
            escapeshellarg($publicPemPath),
            escapeshellarg($tmpDer)
        ));
        $der = file_get_contents($tmpDer) ?: '';
        unlink($tmpDer);
        if (strlen($der) < 32) {
            $this->respondJson(500, ['error' => 'invalid_public_key']);
            exit;
        }
        return substr($der, -32);
    }

    private function buildParamsString(array $params): string
    {
        $parts = [];
        foreach ($params as $key => $value) {
            $parts[] = $key . '=' . rawurlencode((string)$value);
        }
        return implode('&', $parts);
    }

    private function opensslSignEd25519(string $data, string $privatePemPath): string
    {
        $tmpIn = tempnam(sys_get_temp_dir(), 'sig_in_');
        $tmpOut = tempnam(sys_get_temp_dir(), 'sig_out_');
        file_put_contents($tmpIn, $data);

        $this->runCmd(sprintf(
            'openssl pkeyutl -sign -inkey %s -rawin -in %s -out %s',
            escapeshellarg($privatePemPath),
            escapeshellarg($tmpIn),
            escapeshellarg($tmpOut)
        ));

        $sig = file_get_contents($tmpOut) ?: '';
        unlink($tmpIn);
        unlink($tmpOut);

        return $this->base64urlEncode($sig);
    }

    private function base64urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function decodeBase64(string $data): ?string
    {
        $decoded = base64_decode($data, true);
        if ($decoded !== false) {
            return $decoded;
        }
        $url = strtr($data, '-_', '+/');
        $pad = strlen($url) % 4;
        if ($pad !== 0) {
            $url .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($url, true);
        return $decoded === false ? null : $decoded;
    }

    private function runCmd(string $cmd): void
    {
        exec($cmd . ' 2>&1', $output, $status);
        if ($status !== 0) {
            $this->respondJson(500, ['error' => 'command_failed']);
            exit;
        }
    }
}
