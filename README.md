# DVC — SD-JWT Share & Verify API

Node.js service that builds and verifies **SD-JWT verifiable-credential presentations** (selective disclosure with holder key binding, ES256).

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET  /health` | none | Liveness check |
| `POST /api/v1/sdjwt/share` | none | Build a presentation SD-JWT containing only the selected claims |
| `POST /api/v1/sdjwt/verify` | none | Verify an SD-JWT + KB-JWT presentation |

Base URL (default): `http://localhost:3006`

---

## Table of contents

1. [Prerequisites](#1-prerequisites)
2. [Setup — step by step](#2-setup--step-by-step)
3. [Start the server](#3-start-the-server)
4. [Share → KB-JWT → Verify — step by step](#4-share--kb-jwt--verify--step-by-step)
5. [API reference](#5-api-reference)
6. [Configuration (.env)](#6-configuration-env)
7. [Helper scripts & `npm test`](#7-helper-scripts--npm-test)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Prerequisites

- **Node.js 20 or newer** — check with `node -v`
- **npm** (bundled with Node)
- `curl` or Postman for calling the API

---

## 2. Setup — step by step

Run all commands from the project root (the folder containing `package.json`).

### Step 1 — Install dependencies

```bash
npm install
```

### Step 2 — Generate the issuer signing key pair

```bash
npm run keys:generate
```

This writes three files into `src/keys/`:

```
src/keys/issuer-private.pem       ES256 (P-256) private key — signs the SD-JWT
src/keys/issuer-public.pem        matching public key
src/keys/issuer-public.jwks.json  public key as a JWKS document
```

These files are git-ignored. **Never commit or share the private key.**

### Step 3 — Create the `.env` file

```bash
cp .env.example .env
```

The template works as-is for local development — the key paths already point at `src/keys/`. See [Configuration](#6-configuration-env) for what each setting does.

### Step 4 — Generate the holder key pair

The *holder* is the entity that owns the credential (e.g. a farmer's wallet). It needs its own key pair so it can prove possession when presenting the credential (the KB-JWT in Step 4.2 below).

```bash
node tests/holder-keys.test.js
```

This writes:

```
keys/holder-private.pem   holder private key — signs the KB-JWT
keys/holder-public.pem    holder public key
```

and prints the **public JWK** to the console. Copy it — you will paste it into the `holderJwk` field of the `/share` request:

```json
{
  "kty": "EC",
  "x": "2E9_1-owSEaiWhcYutAtOOjh-L2ZW4byeVFle1_TNg8",
  "y": "mO9WKszAZ59DYipOhU8iEWc6ngjPX7fb2Vs26_8cnko",
  "crv": "P-256",
  "alg": "ES256"
}
```

> `keys/` (project root) holds the **holder** keys; `src/keys/` holds the **issuer** keys. Both are git-ignored.

---

## 3. Start the server

```bash
npm start          # production-style start
# or
npm run dev        # auto-restarts on file changes
```

Expected log output:

```
INFO: JWT issuer key loaded   kid: "jwt-signing-key-01"  alg: "ES256"  keySource: "file"
INFO: JWT API listening       port: 3006  env: "development"
```

Confirm it is up:

```bash
curl http://localhost:3006/health
```

```json
{"status":"success","data":{"service":"jwt-api","uptime":1.23}}
```

---

## 4. Share → KB-JWT → Verify — step by step

```
 Holder (wallet)  ──/share──▶  presentation SD-JWT
        │
        └── signs KB-JWT with keys/holder-private.pem
                    │
                    ▼
 Verifier (bank, etc.)  ──/verify (sdJwt + kbJwt + audience + nonce)──▶  { valid, disclosedClaims }
```

1. **Holder** picks only the claims it wants to reveal and builds a presentation (`/share`).
2. **Holder** signs a **Key Binding JWT (KB-JWT)** with its private key, bound to the verifier's `audience` and one-time `nonce`.
3. **Verifier** checks the presentation + KB-JWT (`/verify`).

Neither endpoint requires an `Authorization` header.

### Step 4.1 — Build a presentation with selected claims: `POST /api/v1/sdjwt/share`

Replace `holderJwk` with the JWK printed in [Setup Step 4](#step-4--generate-the-holder-key-pair). Put only the claims you want to disclose in `claims`.

```bash
curl -X POST http://localhost:3006/api/v1/sdjwt/share \
  -H "Content-Type: application/json" \
  -d '{
    "credentialId": "farmer-001",
    "holderJwk": {
      "kty": "EC", "crv": "P-256", "alg": "ES256",
      "x": "2E9_1-owSEaiWhcYutAtOOjh-L2ZW4byeVFle1_TNg8",
      "y": "mO9WKszAZ59DYipOhU8iEWc6ngjPX7fb2Vs26_8cnko"
    },
    "claims": {
      "name": "Ram Kumar",
      "state": "UP"
    }
  }'
```

Response `200 OK`:

```json
{
  "sdJwt": "eyJhbGciOiJFUzI1NiIs...~WyIxMmZkOGUyMy...~WyI1OWFiZDg1Yi...",
  "signedJwt": "eyJhbGciOiJFUzI1NiIs..."
}
```

- `signedJwt` — the issuer-signed JWT. Its payload contains **only SHA-256 hashes** (`_sd`) of the claims, not the values.
- `sdJwt` — `signedJwt` followed by one `~`-separated *disclosure* per claim. Each disclosure is base64url of `[salt, claimName, value]`.

Decoded `signedJwt` payload (for reference):

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v1"],
  "iss": "https://agristack.example.gov.in",
  "cnf": { "jwk": { "kty": "EC", "crv": "P-256", "alg": "ES256", "x": "...", "y": "..." } },
  "id": "farmer-001",
  "iat": 1789639529,
  "exp": 1789725929,
  "status": "https://agristack.example.gov.in/credentials/status/farmer-001",
  "_sd_alg": "sha-256",
  "_sd": ["hz-F9rIDj59GGzlcqQU_9mV3lucYPqdyu_neyg3oyzk", "iFuz-aSExO7gqY6w9H9SeommPtGH9Zp-l6XzoLI_iWg"]
}
```

**Save the `sdJwt` value** — you need it for the next two steps.

### Step 4.2 — Create the Key Binding JWT (KB-JWT)

The KB-JWT is signed with the **holder private key** (`keys/holder-private.pem`). It contains the verifier's `audience`, the verifier's one-time `nonce`, and `sd_hash` = SHA-256 of the exact `sdJwt` string, so it cannot be replayed against a different presentation or verifier.

Use the helper script, passing the `sdJwt` from Step 4.1:

```bash
node tests/key-binding.test.js "<paste sdJwt here>"
```

Output:

```
KB-JWT:

eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE3ODk2Mzk4Mzc...

KB-JWT parts:

Header:  { alg: 'ES256', typ: 'kb+jwt' }
Payload: { iat: 1789639837, aud: 'https://bank.example.in', nonce: 'demo-bank-challenge-001', sd_hash: '7zKa4kv...' }
```

The script hard-codes `audience = https://bank.example.in` and `nonce = demo-bank-challenge-001`. In a real integration the verifier supplies both values. To do that in code:

```js
import { createKeyBindingJwt } from './src/services/key-binding.js';

const kbJwt = await createKeyBindingJwt({
  sdJwt,                               // exact string from /share
  audience: 'https://bank.example.in', // supplied by the verifier
  nonce: 'demo-bank-challenge-001',    // supplied by the verifier
});
```

**Save the KB-JWT value.**

### Step 4.3 — Verify the presentation: `POST /api/v1/sdjwt/verify`

Send the `sdJwt` (Step 4.1) and `kbJwt` (Step 4.2) together with the **same** `audience` and `nonce` used to create the KB-JWT.

```bash
curl -X POST http://localhost:3006/api/v1/sdjwt/verify \
  -H "Content-Type: application/json" \
  -d '{
    "sdJwt": "<sdJwt from step 4.1>",
    "kbJwt": "<kbJwt from step 4.2>",
    "audience": "https://bank.example.in",
    "nonce": "demo-bank-challenge-001"
  }'
```

Response `200 OK`:

```json
{
  "valid": true,
  "protectedHeader": { "alg": "ES256", "typ": "vc+sd-jwt", "kid": "jwt-signing-key-01" },
  "payload": { "iss": "https://agristack.example.gov.in", "id": "farmer-001", "cnf": { "jwk": { "...": "..." } }, "_sd": ["..."], "...": "..." },
  "disclosedClaims": {
    "name": "Ram Kumar",
    "state": "UP"
  },
  "disclosureCount": 2,
  "keyBinding": {
    "valid": true,
    "protectedHeader": { "alg": "ES256", "typ": "kb+jwt" },
    "payload": {
      "iat": 1789639846,
      "aud": "https://bank.example.in",
      "nonce": "demo-bank-challenge-001",
      "sd_hash": "7zKa4kvGQUlsj_mFnHQKCe3zsz6JPsqa7GPBZaKRD14"
    }
  }
}
```

`disclosedClaims` contains only what the holder chose to reveal. The verifier checks:

- issuer signature (against the issuer public key / `kid`)
- every disclosure hashes to an entry in `_sd`
- KB-JWT signature against `cnf.jwk` (the holder's public key)
- KB-JWT `aud` and `nonce` match the expected values
- KB-JWT `sd_hash` matches the SHA-256 of the presented `sdJwt`

If any check fails (wrong nonce, tampered disclosure, wrong holder key, etc.) the response is currently `500` with `{"status":"error","error":{"code":"INTERNAL_ERROR"}}`. The reason is written to the server log.

### Quick one-shot script (all three steps)

For a fast local check, run this from the project root with the server already running (bash / Git Bash):

```bash
JWK='{"kty":"EC","crv":"P-256","alg":"ES256","x":"<x>","y":"<y>"}'   # from Setup Step 4

SD=$(curl -s -X POST http://localhost:3006/api/v1/sdjwt/share \
  -H "Content-Type: application/json" \
  -d "{\"credentialId\":\"farmer-001\",\"holderJwk\":$JWK,\"claims\":{\"name\":\"Ram Kumar\",\"state\":\"UP\"}}" \
  | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>process.stdout.write(JSON.parse(s).sdJwt))")

KB=$(node tests/key-binding.test.js "$SD" | grep -E '^eyJ')

curl -s -X POST http://localhost:3006/api/v1/sdjwt/verify \
  -H "Content-Type: application/json" \
  -d "{\"sdJwt\":\"$SD\",\"kbJwt\":\"$KB\",\"audience\":\"https://bank.example.in\",\"nonce\":\"demo-bank-challenge-001\"}"
```

---

## 5. API reference

Both request bodies must be `Content-Type: application/json`. Both schemas are **strict** — unknown fields return `400 Validation failed`.

### `POST /api/v1/sdjwt/share`

| Field | Type | Required | Rules |
|---|---|---|---|
| `credentialId` | string | yes | 1–256 chars |
| `holderJwk` | object | yes | EC: `kty`,`crv`,`x`,`y` · RSA: `kty`,`n`,`e` · optional `alg`,`kid`. Public members only |
| `claims` | object | yes | the claims to disclose; 1–100 keys; key matches `^[A-Za-z][A-Za-z0-9_.-]*$`; ≤ 64 KB serialized |

Returns `200 { sdJwt, signedJwt }`. Expiry is fixed at 24 h from issue time.

### `POST /api/v1/sdjwt/verify`

| Field | Type | Required | Rules |
|---|---|---|---|
| `sdJwt` | string | yes | ≤ 256 KB |
| `kbJwt` | string | yes | ≤ 16 KB |
| `audience` | string | yes | ≤ 256 chars; must equal KB-JWT `aud` |
| `nonce` | string | yes | ≤ 256 chars; must equal KB-JWT `nonce` |

Returns `200 { valid, protectedHeader, payload, disclosedClaims, disclosureCount, keyBinding }`.

### Error format

Validation failures (`400`):

```json
{ "error": "Validation failed", "details": { "formErrors": [], "fieldErrors": { "kbJwt": ["kbJwt is required"] } } }
```

Other errors:

```json
{ "status": "error", "error": { "code": "INTERNAL_ERROR", "message": "..." }, "correlationId": "..." }
```

Codes: `MALFORMED_JSON` (400), `PAYLOAD_TOO_LARGE` (413), `RATE_LIMITED` (429), `ROUTE_NOT_FOUND` (404), `INTERNAL_ERROR` (500).

Every response carries an `X-Correlation-Id` header (you may send your own; `^[A-Za-z0-9_.:-]{1,64}$`).

---

## 6. Configuration (.env)

| Variable | Default | Description |
|---|---|---|
| `NODE_ENV` | `development` | `development` / `test` / `production` |
| `PORT` | `3006` | Listen port |
| `LOG_LEVEL` | `info` | pino log level |
| `JWT_ISSUER` | `https://agristack.example.gov.in` | Goes into `iss` and the `status` URL; must be an absolute URL |
| `JWT_KEY_ID` | `jwt-signing-key-01` | `kid` in the SD-JWT header |
| `JWT_PRIVATE_KEY_PATH` | `./src/keys/issuer-private.pem` | ES256 private key (relative to cwd) |
| `JWT_PUBLIC_KEY_PATH` | `./src/keys/issuer-public.pem` | Must match the private key |
| `JWT_PRIVATE_KEY` | — | Inline PEM; overrides the path if set |
| `JSON_BODY_LIMIT` | `50mb` | Max request body |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Rate-limit window |
| `RATE_LIMIT_MAX` | `60` | Requests per window per IP on `/api/*` |
| `TRUST_PROXY` | `0` | Proxy hops to trust for client IP |
| `REQUEST_TIMEOUT_MS` | `20000` | Max time for a request to fully arrive |

---

## 7. Helper scripts & `npm test`

The files in `tests/` are **manual helper scripts**, not an automated test suite. Run each one directly with `node`:

| Script | What it does | Run |
|---|---|---|
| `tests/holder-keys.test.js` | Generates the holder key pair into `keys/` and prints the public JWK | `node tests/holder-keys.test.js` |
| `tests/key-binding.test.js` | Signs a KB-JWT for a given `sdJwt` using `keys/holder-private.pem` | `node tests/key-binding.test.js "<sdJwt>"` |
| `tests/sdjwt-integrity.test.js` | Decodes a hard-coded SD-JWT and checks each disclosure hashes into `_sd` (edit the `sdJwt` constant inside the file first) | `node tests/sdjwt-integrity.test.js` |
| `tests/sdjwt-verifier.test.js` | Runs the verifier service against a hard-coded SD-JWT / KB-JWT (edit the constants inside the file first) | `node tests/sdjwt-verifier.test.js` |

> **`npm test` does not work on Windows.** The script is `node --test "tests/*.test.js"`, and on Windows the quoted glob is not expanded, so Node reports `Could not find '...\tests\*.test.js'`. Even on macOS/Linux it only runs the scripts above as if they were tests — there are no `node:test` assertions in this repo. Use the direct `node` commands in the table instead.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `provide JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH (run npm run keys:generate)` | No `.env` or keys missing → do Setup Steps 2 & 3 |
| `ENOENT ... issuer-private.pem` | `JWT_PRIVATE_KEY_PATH` in `.env` points to the wrong folder; it must be `./src/keys/issuer-private.pem` |
| `listen EADDRINUSE :::3006` | Another instance is already running on that port; stop it or change `PORT` |
| `ENOENT ... keys/holder-private.pem` when running `key-binding.test.js` | Holder keys not generated → Setup Step 4 |
| `400 Validation failed` with `"Unrecognized key(s)"` | Schemas are strict — remove the extra field |
| `400 Holder JWK must be a valid EC or RSA public key` | `holderJwk` needs `kty`,`crv`,`x`,`y` (EC) or `kty`,`n`,`e` (RSA) — no private-key members (`d`) |
| `400 kbJwt is required` | The KB-JWT string was empty — make sure you copied the full `eyJ...` line from the script output |
| `/verify` returns `500 INTERNAL_ERROR` | Verification failed (bad signature, `audience`/`nonce` mismatch, `sd_hash` mismatch, tampered disclosure, expired). Check the server log for the exact reason |
| `429 RATE_LIMITED` | 60 requests/min per IP by default; raise `RATE_LIMIT_MAX` |
| `npm test` → `Could not find '...\tests\*.test.js'` | Expected on Windows — see [Helper scripts & `npm test`](#7-helper-scripts--npm-test); run the scripts directly with `node` |
