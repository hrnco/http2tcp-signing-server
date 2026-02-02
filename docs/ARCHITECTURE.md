# Architecture Overview

## Components
- **Signing Server**: Issues signed request parameters over HTTP (`/api/sign`). Holds private keys.
- **Application Server**: Requests signed parameters from the signing server and passes them to the browser.
- **Browser**: Receives signed parameters and forwards them to the local agent.
- **Local Agent**: Verifies signatures and performs TCP calls to the LAN device (e.g., receipt printer).
- **LAN Device**: Physical target (printer, terminal) reachable only from the local network.

## Data Flow
1) The app calls the signing server (`/api/sign`) with device IP/port and payload.
2) The server wraps `instructions`, adds `exp` + `nonce`, signs, and returns serialized params.
3) The browser forwards params to the local agent (`/api/send`).
4) The agent verifies the signature via `kid`, checks TTL/nonce, and sends the TCP payload to the LAN device.

## Trust Model
- **Server is the root of trust** (private keys stored on the server).
- **Agent uses TOFU/pinning**: the first valid public key is pinned; later signatures must match.
- **Key ID (`kid`)** identifies which public key to use for verification.

## Key Storage
- Default key: `/keys/default/{private.pem,public.pem}`
- Device key: `/keys/devices/{deviceId}/{private.pem,public.pem}`
- Key ID mapping: `/keys/**/kid`

## Protocol Notes
- `instructions` is base64url JSON with payload and device info.
- `sig` is base64url signature of the serialized params (without `sig`).
- `exp` + `nonce` protect against replay.
