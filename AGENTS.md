# Repository Guidelines

## Project Structure & Module Organization
- `index.php` is the entrypoint; it boots `SignerApp` and handles all routing.
- `src/SignerApp.php` contains request validation, key management, and signing logic.
- `docs/` holds architectural and onboarding notes (`docs/ARCHITECTURE.md`, `docs/ONBOARDING.md`).
- `.docker/` contains the container build and entrypoint (`.docker/Dockerfile`, `.docker/docker-entrypoint.sh`).
- `compose.yml` defines the dev container, port mapping, and the persistent `/keys` volume.

## Build, Test, and Development Commands
- `docker compose up --build` builds the PHP 8.4 + Apache image and runs the signing server on `http://localhost:8080`.
- `docker compose build` rebuilds the container image after Dockerfile or system dependency changes.
- `docker compose down` stops the container; the `keys` volume remains unless manually removed.
- Quick manual check: `curl -s -X POST "http://localhost:8080/api/sign" -H "Content-Type: application/json" -d '{"payloadHex":"48656c6c6f","deviceIp":"192.168.1.50","devicePort":9100}'`.

## Coding Style & Naming Conventions
- PHP with `declare(strict_types=1);` at the top of files.
- Indentation: 4 spaces; keep line lengths reasonable for readability.
- Naming: classes `StudlyCaps` (e.g., `SignerApp`), methods/variables `camelCase`.
- No configured formatter or linter; keep changes consistent with existing style.

## Testing Guidelines
- There is no automated test suite in this repository.
- Validate behavior manually via `GET /api/sign` or the root page form at `http://localhost:8080/`.
- If adding tests, document the runner and naming pattern in this file.

## Commit & Pull Request Guidelines
- Current history uses short, file-focused commit messages (e.g., `README.md`) with no formal convention.
- Keep commits small and descriptive; prefer imperative summaries when possible.
- PRs should explain the behavior change, note any config changes (e.g., `.env`, key paths), and include a verification note or curl snippet.

## Security & Configuration Tips
- Keys are generated and stored under `/keys` (volume-backed in Docker). Do not commit generated keys.
- Config lives in `.env` (`APP_ENV`, `KEYS_DIR`, `TTL_SECONDS`). Use `APP_ENV=dev` to enable debug output.
- Default key path is `/keys/default`; device-specific keys live under `/keys/devices/{deviceId}`.
