# HTTP2TCP Server

Lightweight HTTP signing server that lets a web or cloud app, via the user's browser, securely communicate with LAN devices over TCP without opening ports, setting up a VPN, or exposing the LAN to the internet.

```
Cloud/Web App -> Signing Server -> Browser (user) -> Local Agent -> TCP Device (user LAN)
```

## Core Idea
- The server receives an app-level instruction (e.g., TCP payload in hex).
- It wraps it with metadata (nonce, key id), signs it with Ed25519, and emits URL parameters.
- The browser embeds those parameters into a URL and calls the local agent. The agent verifies the signature and performs the TCP request. Trust mode is TOFU: the first valid key is paired, and the agent rejects all others.

## Language-Agnostic Interface (curl examples)
- Works purely over HTTP API; client language is irrelevant.
- **Input to server:** device IP, device port, TCP payload in hex. The server resolves the signing key internally (default or device-specific by id).
- **Output from server:** serialized parameters `instructions`, `sig`, `kid`, `exp`, `nonce`.
- **Flow:**
  1) call the server (`http://http2tcp-server/api/sign`) to get signed params,
  2) forward those params to the agent (`http://localhost:34279/api/send`) via GET or POST,
  3) read JSON response.

## Minimal API snippets (multi-language)
Each snippet only obtains the signed `params` string; the actual call to the local agent happens in the Browser Embedding step.

<details>
<summary><strong>cURL</strong></summary>

```bash
# Get signed params from the server; pass this string to the browser
params=$(curl -s -X POST "http://http2tcp-server/api/sign" \
  -H "Content-Type: application/json" \
  -d '{"payloadHex":"STRING_V_HEXA_PRE_TCP","deviceIp":"192.168.1.50","devicePort":9100}')
# echo "$params"
```

</details>

<details>
<summary><strong>PHP</strong></summary>

```php
// Raw HTTP request; no client class required.
$payload = json_encode([
    'payloadHex' => 'STRING_V_HEXA_PRE_TCP',
    'deviceIp' => '192.168.1.50',
    'devicePort' => 9100,
], JSON_THROW_ON_ERROR);

$ch = curl_init('http://http2tcp-server/api/sign');
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    CURLOPT_POSTFIELDS => $payload,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 5,
]);
$params = curl_exec($ch);
if ($params === false) {
    throw new RuntimeException(curl_error($ch));
}
curl_close($ch);
// $params is the serialized string: instructions=...&sig=...&kid=...&exp=...&nonce=...
```

</details>

<details>
<summary><strong>Python</strong></summary>

```python
import requests

resp = requests.post(
    "http://http2tcp-server/api/sign",
    json={
        "payloadHex": "STRING_V_HEXA_PRE_TCP",
        "deviceIp": "192.168.1.50",
        "devicePort": 9100,
    },
    timeout=5,
)
resp.raise_for_status()
params = resp.text  # serialized params; hand off to the browser/embed step
```

</details>

<details>
<summary><strong>JavaScript (Node/Browser)</strong></summary>

```js
const params = await fetch("http://http2tcp-server/api/sign", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    payloadHex: "STRING_V_HEXA_PRE_TCP",
    deviceIp: "192.168.1.50",
    devicePort: 9100,
  }),
}).then((r) => r.text());
```

</details>

### Returned value
- A serialized parameter string ready to append or POST, e.g. `instructions=...&sig=...&kid=...&exp=...&nonce=...`.
- Includes: encoded instructions (payload hex + device IP/port), signature, key id (resolved server-side, default if no device-specific key applies), expiration/nonce to prevent replay.

## Browser Embedding (generic JS)
```html
<script>
  // `params` is the signed response returned by your server (/api/sign); inject it into the page
  // (e.g., templated server-side, fetched via XHR, or passed via postMessage from your app shell).
  // Use the `params` produced by any snippet above.
  const agentBase = 'http://localhost:34279/api/send';
  const params = window.signedParams; // e.g., "instructions=...&sig=...&kid=...&exp=...&nonce=..."

  // POST to local agent
  fetch(agentBase, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params,
    credentials: 'include'
  })
    .then(r => r.json())
    .then(console.log)
    .catch(console.error);
</script>
```

## Expected Endpoints
- `GET /api/send` with query params `instructions`, `sig`, `kid`, `exp`, `nonce`.
- `POST /api/send` with the same fields as `application/x-www-form-urlencoded`.

## Implementation Notes
- Crypto is fixed to Ed25519; no extra setup needed.
