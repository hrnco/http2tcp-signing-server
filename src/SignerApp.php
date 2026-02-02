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
            $payloadHexRaw = $_GET['payloadHex'] ?? '';
            $payloadBase64Raw = $_GET['payloadBase64'] ?? '';
            $payloadAsciiRaw = $_GET['payloadAscii'] ?? '';
            $deviceIp = trim((string)($_GET['deviceIp'] ?? ''));
            $devicePort = (int)($_GET['devicePort'] ?? 0);
            $deviceId = trim((string)($_GET['deviceId'] ?? ''));
            $debug = ((string)($_GET['debug'] ?? '')) === '1';
            $agentUrl = trim((string)($_GET['agentUrl'] ?? ''));
        } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $inputRaw = file_get_contents('php://input') ?: '';
            $input = json_decode($inputRaw, true);
            if (!is_array($input)) {
                $this->respondJson(400, ['error' => 'invalid_json']);
                return;
            }
            $payloadHexRaw = $input['payloadHex'] ?? '';
            $payloadBase64Raw = $input['payloadBase64'] ?? '';
            $payloadAsciiRaw = $input['payloadAscii'] ?? '';
            $deviceIp = trim((string)($input['deviceIp'] ?? ''));
            $devicePort = (int)($input['devicePort'] ?? 0);
            $deviceId = trim((string)($input['deviceId'] ?? ''));
            $debug = ((string)($input['debug'] ?? '')) === '1';
            $agentUrl = trim((string)($input['agentUrl'] ?? ''));
        } else {
            $this->respondJson(405, ['error' => 'method_not_allowed']);
            return;
        }
        $debug = $debug && $this->appEnv === 'dev';

        $payloadHexList = $this->normalizeStringList($payloadHexRaw);
        $payloadBase64List = $this->normalizeStringList($payloadBase64Raw);
        $payloadAsciiList = $this->normalizeStringList($payloadAsciiRaw);

        if ($payloadHexList === [] && $payloadBase64List === [] && $payloadAsciiList === []) {
            $this->respondJson(400, ['error' => 'payload_required']);
            return;
        }
        $payloadKinds = 0;
        $payloadKinds += $payloadHexList !== [] ? 1 : 0;
        $payloadKinds += $payloadBase64List !== [] ? 1 : 0;
        $payloadKinds += $payloadAsciiList !== [] ? 1 : 0;
        if ($payloadKinds > 1) {
            $this->respondJson(400, ['error' => 'payload_conflict']);
            return;
        }

        if ($payloadHexList !== []) {
            $payloadBase64List = $this->hexListToBase64List($payloadHexList);
            if ($payloadBase64List === null) {
                $this->respondJson(400, ['error' => 'invalid_payload_hex']);
                return;
            }
        } elseif ($payloadBase64List !== []) {
            foreach ($payloadBase64List as $b64) {
                if ($this->decodeBase64($b64) === null) {
                    $this->respondJson(400, ['error' => 'invalid_payload_base64']);
                    return;
                }
            }
        } else {
            $payloadBase64List = $this->asciiListToBase64List($payloadAsciiList);
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
        $instructionsPayload['payloadBase64'] = count($payloadBase64List) === 1
            ? $payloadBase64List[0]
            : $payloadBase64List;
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
                'agent_url' => $agentUrl,
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
        echo '<label>payloadType ';
        echo '<select name="payloadType" id="payloadTypeSelect">';
        echo '<option value="ascii" selected>ascii</option>';
        echo '<option value="hex">hex</option>';
        echo '</select>';
        echo '</label><br>';
        echo '<div id="payloadAsciiFields">';
        echo '<div id="payloadAsciiRows">';
        echo '<div><label>payloadAscii[0] <input name="payloadAscii[]" size="40" value="Hello"></label></div>';
        echo '<div><label>payloadAscii[1] <input name="payloadAscii[]" size="40" value="World"></label></div>';
        echo '<div><label>payloadAscii[2] <input name="payloadAscii[]" size="40" value=":)"></label></div>';
        echo '</div>';
        echo '<button type="button" id="addAsciiRow">+ add ascii</button> ';
        echo '<button type="button" id="removeAsciiRow">- remove ascii</button><br>';
        echo '</div>';
        echo '<div id="payloadHexFields">';
        echo '<div id="payloadHexRows">';
        echo '<div><label>payloadHex[0] <input name="payloadHex[]" size="40" value="48656c6c6f207072696e746572"></label></div>';
        echo '<div><label>payloadHex[1] <input name="payloadHex[]" size="40" value="414243"></label></div>';
        echo '<div><label>payloadHex[2] <input name="payloadHex[]" size="40" value="313233"></label></div>';
        echo '</div>';
        echo '<button type="button" id="addHexRow">+ add hex</button> ';
        echo '<button type="button" id="removeHexRow">- remove hex</button><br>';
        echo '</div>';
        echo '<label>deviceIp <input name="deviceIp" value="192.168.1.50"></label><br>';
        echo '<label>devicePort <input name="devicePort" value="9100"></label><br>';
        echo '<label>deviceId <input name="deviceId" value=""></label><br>';
        echo '<label><input type="checkbox" name="debug" value="1" checked id="debugToggle"> debug</label><br>';
        echo '<div id="agentUrlRow">';
        echo '<label>agentUrl <input name="agentUrl" size="40" value="http://localhost:34279/api/send"></label><br>';
        echo '</div>';
        echo '<script>';
        echo 'const debugToggle = document.getElementById("debugToggle");';
        echo 'const agentUrlRow = document.getElementById("agentUrlRow");';
        echo 'const payloadTypeSelect = document.getElementById("payloadTypeSelect");';
        echo 'const payloadAsciiFields = document.getElementById("payloadAsciiFields");';
        echo 'const payloadHexFields = document.getElementById("payloadHexFields");';
        echo 'const setDisabled = (root, disabled) => {';
        echo '  root.querySelectorAll("input").forEach((el) => { el.disabled = disabled; });';
        echo '};';
        echo 'const syncPayloadFields = () => {';
        echo '  const isAscii = payloadTypeSelect.value === "ascii";';
        echo '  payloadAsciiFields.style.display = isAscii ? "block" : "none";';
        echo '  payloadHexFields.style.display = isAscii ? "none" : "block";';
        echo '  setDisabled(payloadAsciiFields, !isAscii);';
        echo '  setDisabled(payloadHexFields, isAscii);';
        echo '};';
        echo 'const updateRowLabels = (root, labelPrefix) => {';
        echo '  const rows = root.querySelectorAll("div");';
        echo '  rows.forEach((row, idx) => {';
        echo '    const label = row.querySelector("label");';
        echo '    if (label) { label.firstChild.nodeValue = labelPrefix + "[" + idx + "] "; }';
        echo '  });';
        echo '};';
        echo 'const addRow = (root, labelPrefix, defaultValue) => {';
        echo '  const row = document.createElement("div");';
        echo '  row.innerHTML = `<label>${labelPrefix}[X] <input name="${labelPrefix}[]" size="40" value="${defaultValue}"></label>`;';
        echo '  root.appendChild(row);';
        echo '  updateRowLabels(root, labelPrefix);';
        echo '};';
        echo 'const removeRow = (root, labelPrefix) => {';
        echo '  const rows = root.querySelectorAll("div");';
        echo '  if (rows.length <= 1) { return; }';
        echo '  rows[rows.length - 1].remove();';
        echo '  updateRowLabels(root, labelPrefix);';
        echo '};';
        echo 'const syncAgentRow = () => { agentUrlRow.style.display = debugToggle.checked ? "block" : "none"; };';
        echo 'debugToggle.addEventListener("change", syncAgentRow);';
        echo 'payloadTypeSelect.addEventListener("change", syncPayloadFields);';
        echo 'document.getElementById("addAsciiRow").addEventListener("click", () => addRow(document.getElementById("payloadAsciiRows"), "payloadAscii", ""));';
        echo 'document.getElementById("removeAsciiRow").addEventListener("click", () => removeRow(document.getElementById("payloadAsciiRows"), "payloadAscii"));';
        echo 'document.getElementById("addHexRow").addEventListener("click", () => addRow(document.getElementById("payloadHexRows"), "payloadHex", ""));';
        echo 'document.getElementById("removeHexRow").addEventListener("click", () => removeRow(document.getElementById("payloadHexRows"), "payloadHex"));';
        echo 'syncAgentRow();';
        echo 'syncPayloadFields();';
        echo '</script>';
        echo '<button type="submit">Sign</button>';
        echo '</form>';
        echo '<h2>cURL</h2>';
        echo '<pre>curl -s -X POST "http://localhost:8080/api/sign" \\' . "\n";
        echo '  -H "Content-Type: application/json" \\' . "\n";
        echo '  -d \'{"payloadHex":["48656c6c6f207072696e746572","414243","313233"],"deviceIp":"192.168.1.50","devicePort":9100}\'</pre>';
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

        $agentUrl = trim((string)($details['agent_url'] ?? ''));
        if ($agentUrl !== '') {
            $safeAgentUrl = htmlspecialchars($agentUrl, ENT_QUOTES, 'UTF-8');
            $safeParams = htmlspecialchars($response, ENT_QUOTES, 'UTF-8');
            echo '<hr>';
            echo '<h2>Agent Request (browser)</h2>';
            echo '<p>URL: <code>' . $safeAgentUrl . '</code></p>';
            echo '<h3>Request</h3>';
            echo '<pre id="agentRequest">POST ' . $safeAgentUrl . "\n" . 'Content-Type: application/x-www-form-urlencoded' . "\n\n" . $safeParams . '</pre>';
            echo '<h3>Response</h3>';
            echo '<pre id="agentResponse">Loading...</pre>';
            echo '<pre id="agentResponseHeaders"></pre>';
            echo '<script>';
            echo 'const agentUrl = ' . json_encode($agentUrl) . ';';
            echo 'const agentBody = ' . json_encode($response) . ';';
            echo 'fetch(agentUrl, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: agentBody, credentials: "include" })';
            echo '.then(async (r) => {';
            echo '  const text = await r.text();';
            echo '  const headers = Array.from(r.headers.entries()).map(([k, v]) => k + ": " + v).join("\\n");';
            echo '  const statusLine = "HTTP " + r.status + " " + r.statusText;';
            echo '  document.getElementById("agentResponse").textContent = statusLine + "\\n\\n" + text;';
            echo '  document.getElementById("agentResponseHeaders").textContent = headers;';
            echo '})';
            echo '.catch((err) => { document.getElementById("agentResponse").textContent = String(err); });';
            echo '</script>';
        }

        echo '</body></html>';
    }

    private function respondJson(int $status, array $payload): void
    {
        http_response_code($status);
        header('Content-Type: application/json');
        echo json_encode($payload);
    }

    /** @return list<string> */
    private function normalizeStringList(mixed $value): array
    {
        if (is_array($value)) {
            $out = [];
            foreach ($value as $item) {
                $item = trim((string)$item);
                if ($item !== '') {
                    $out[] = $item;
                }
            }
            return $out;
        }

        $value = trim((string)$value);
        return $value === '' ? [] : [$value];
    }

    /** @return list<string>|null */
    private function hexListToBase64List(array $hexList): ?array
    {
        $out = [];
        foreach ($hexList as $hex) {
            $hex = trim($hex);
            if ($hex === '' || strlen($hex) % 2 !== 0 || !ctype_xdigit($hex)) {
                return null;
            }
            $bytes = hex2bin($hex);
            if ($bytes === false) {
                return null;
            }
            $out[] = base64_encode($bytes);
        }
        return $out;
    }

    /** @return list<string> */
    private function asciiListToBase64List(array $asciiList): array
    {
        $out = [];
        foreach ($asciiList as $ascii) {
            $out[] = base64_encode($ascii);
        }
        return $out;
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
