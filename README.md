# JWT API — create & verify (ES256)

A small Node.js service exposing exactly two endpoints:

```
POST /api/v1/jwt/create    mint an ES256-signed JWT
POST /api/v1/jwt/verify    verify one and return its claims
```

Both are authenticated. `/create` signs with the issuer key, so leaving it open
would let anyone mint tokens this deployment trusts; `/verify` is authenticated
because an open endpoint that decodes any token handed to it is a decoding
oracle.

---

## Table of contents

1. [Quick start](#1-quick-start)
2. [Project structure](#2-project-structure)
3. [API reference](#3-api-reference)
4. [Configuration](#4-configuration)
5. [Security considerations](#5-security-considerations)
6. [Testing](#6-testing)

---

## 1. Quick start

```bash
npm install
npm run keys:generate        # writes src/keys/issuer-private.pem (mode 0600)
cp .env.example .env         # then edit JWT_ISSUER and API_ACCESS_TOKENS
npm start                    # or: npm run dev
```

Smoke test:

```bash
curl http://localhost:3000/health

curl -X POST http://localhost:3000/api/v1/jwt/create \
  -H "Authorization: Bearer dev-token-aiu-1" \
  -H "Content-Type: application/json" \
  -d '{"subject":"AIU_ID","audience":"svc-a","claims":{"role":"AIU"}}'

curl -X POST http://localhost:3000/api/v1/jwt/verify \
  -H "Authorization: Bearer dev-token-aiu-1" \
  -H "Content-Type: application/json" \
  -d '{"token":"<paste the token>","expectedAudience":"svc-a"}'
```

A Postman collection covering the same flow is in
`postman/JWT-API.postman_collection.json`.

---

## 2. Project structure

Four source files, one per layer:

```
src/
  config.js       schema-validated env (read once) + logger + ES256 key loading
  jwt.js          typed errors + token issuance and verification rules
  app.js          request schemas, auth, handlers, routes, error handling
  server.js       bootstrap: load key -> listen -> graceful shutdown
  keys/           issuer key pair (never committed)
scripts/generate-keys.js   ES256 key pair generator
tests/api.test.js          the whole suite (node:test, no external runner)
postman/                   importable request collection
```

The dependency direction is one-way — `server.js` -> `app.js` -> `jwt.js` ->
`config.js` — so nothing below the HTTP layer knows Express exists.

---

## 3. API reference

### `GET /health`

Unauthenticated liveness probe.

### `POST /api/v1/jwt/create`

Header: `Authorization: Bearer <API_ACCESS_TOKENS entry>`

```jsonc
{
  "subject":   "AIU_ID",            // optional -> sub
  "audience":  "svc-a",             // optional -> aud
  "claims":    { "role": "AIU" },   // optional, bounded custom claims
  "data":      { "any": "json" },   // optional, unrestricted payload
  "expiresIn": 3600,                // optional seconds, capped by JWT_MAX_EXPIRY
  "notBefore": 0                    // optional seconds -> nbf
}
```

`expectedSubject` / `expectedAudience` are accepted as aliases for
`subject` / `audience`, so one body can be carried across both endpoints.

**201 Created**

```json
{
  "status": "success",
  "data": {
    "token": "eyJhbGciOiJFUzI1NiIs...",
    "token_id": "9a338636-c2a3-4fa5-923c-f410c7c69621",
    "issued_at": "2026-09-03T06:02:58.000Z",
    "expires_at": "2026-09-03T07:02:58.000Z",
    "token_type": "Bearer",
    "expires_in": 3600
  },
  "correlationId": "..."
}
```

**`claims` vs `data`**

| | `claims` | `data` |
|---|---|---|
| Placement | merged at the payload top level | nested under one claim (`JWT_DATA_CLAIM`) |
| Validation | bounded: 32 keys, depth 5, 8 KB serialized | none at all |
| Reserved names | `iss sub aud exp nbf iat jti typ alg` rejected | impossible to collide — it is nested |
| Ceiling | 8 KB | `JSON_BODY_LIMIT` only |

Reserved claims are **rejected, not silently stripped** — silent stripping hides
an attempted attack.

### `POST /api/v1/jwt/verify`

```jsonc
{
  "token": "eyJhbGciOiJFUzI1NiIs...",
  "expectedAudience": "svc-a",   // optional
  "expectedSubject":  "AIU_ID"   // optional
}
```

**200 OK** returns `valid`, the protected `header`, the registered claims
(`issuer`, `subject`, `audience`, `token_id`, `issued_at`, `expires_at`,
`not_before`), the caller's custom `claims`, and `data`.

A failure is a **400** whose `error.code` is a stable reason code:

| Code | Meaning |
|---|---|
| `MALFORMED_JWS` | not three dot-separated segments, or an undecodable header |
| `UNSUPPORTED_ALGORITHM` | header `alg` is not ES256 |
| `UNSUPPORTED_TYP` | header `typ` is not `JWT_TYP` |
| `UNKNOWN_KEY_ID` | `kid` is not this issuer's active key |
| `INVALID_SIGNATURE` | signature check failed |
| `UNTRUSTED_ISSUER` | `iss` is not in `JWT_TRUSTED_ISSUERS` |
| `UNSAFE_HEADER` | header carries key material (`jwk`/`jku`/`x5u`/`x5c`) or `crit` |
| `MISSING_CLAIM` | no `iss`, or no numeric `exp` |
| `INVALID_IAT` | `iat` missing or in the future |
| `CREDENTIAL_EXPIRED` | past `exp` |
| `CREDENTIAL_NOT_YET_VALID` | before `nbf` |
| `HOLDER_BINDING_FAILED` | `aud` or `sub` mismatch |

Other codes: `VALIDATION_ERROR` (400), `MALFORMED_JSON` (400), `UNAUTHORIZED`
(401), `ROUTE_NOT_FOUND` (404), `UNSUPPORTED_MEDIA_TYPE` (415),
`PAYLOAD_TOO_LARGE` (413), `RATE_LIMITED` (429), `TOO_MANY_FAILED_AUTH` (429),
`INTERNAL_ERROR` (500).

Every response carries `x-correlation-id`, echoed from the request when
supplied.

---

## 4. Configuration

All configuration is read once, at import, through a zod schema in
`src/config.js`; the process refuses to start on misconfiguration rather than
failing open at request time. The signing algorithm is deliberately *not*
configurable — `ES256` is a constant, so it cannot be downgraded by an env var.
See `.env.example` for the full list.

| Variable | Default | Notes |
|---|---|---|
| `JWT_ISSUER` | — | **required**, absolute URL; becomes `iss` |
| `JWT_KEY_ID` | `jwt-signing-key-01` | `kid` in the protected header |
| `JWT_PRIVATE_KEY_PATH` | — | PKCS#8 PEM; or supply `JWT_PRIVATE_KEY` inline |
| `JWT_PUBLIC_KEY_PATH` | — | optional; asserted to match the private key at boot |
| `JWT_TYP` | `JWT` | pinned on issue and on verify |
| `JWT_DEFAULT_EXPIRY` / `JWT_MAX_EXPIRY` | `3600` / `86400` | seconds |
| `JWT_CLOCK_SKEW` | `60` | seconds tolerated on `exp`/`iat`/`nbf` |
| `JWT_TRUSTED_ISSUERS` | `[JWT_ISSUER]` | CSV; never empty, so it cannot fail open |
| `JWT_DATA_CLAIM` | `data` | claim the unrestricted payload nests under |
| `JSON_BODY_LIMIT` | `1mb` | the only ceiling on `data` |
| `API_ACCESS_TOKENS` | — | CSV of bearer tokens; required in production |
| `AUTH_ENABLED` | `true` | must be true in production (enforced) |
| `RATE_LIMIT_WINDOW_MS` / `RATE_LIMIT_MAX` | `60000` / `60` | applied to `/api/` only |
| `AUTH_RATE_LIMIT_MAX` | `10` | failed-auth budget per IP per window; only 401s count |
| `TRUST_PROXY` | `0` | proxy hops to trust for the client IP — see below |
| `REQUEST_TIMEOUT_MS` | `20000` | slowloris ceiling on a single request |

Boot-time invariants a per-field schema cannot express are checked explicitly:
`JWT_MAX_EXPIRY >= JWT_DEFAULT_EXPIRY`, a key source is present, `JWT_DATA_CLAIM`
is neither a registered claim nor a prototype-polluting key, and production may
not run with auth disabled, with an empty token list, with duplicate tokens, or
with any token shorter than 32 characters.

**`TRUST_PROXY` defaults to 0 on purpose.** The rate limiters key on the client
IP, and `X-Forwarded-For` is caller-supplied. Trusting it when nothing strips it
lets an attacker rotate a fake IP per request and walk straight past both
limiters. Set it to the number of proxy hops you actually control (usually `1`).

---

## 5. Security considerations

The code carries no comments, so this section is where the reasoning lives. Each
control below has a test in `tests/api.test.js`.

### Token forgery

| Attack | Control |
|---|---|
| `alg: none` | `alg` must be `ES256`, checked **before any key is touched** |
| HMAC / public-key confusion (signing with the public key as an HMAC secret) | same allow-list; `HS256` never reaches a key |
| Embedded key in the header (`jwk`) | header carrying `jwk`/`jku`/`x5u`/`x5c`/`x5t` is rejected outright — the key comes from local config, never from the token |
| SSRF via `jku`/`x5u` | same rejection; the verifier never fetches a URL |
| Unknown `crit` extensions | rejected rather than ignored |
| Retired-key replay | unknown `kid` is rejected, never falls back to the active key |
| Payload tampering | signature checked over the exact compact serialization |
| Expiry stretching via `claims` | `iss sub aud exp nbf iat jti typ alg` are rejected, not stripped, at both the schema and the service |
| Cross-format replay | `typ` is pinned inside the signed header on both issue and verify |
| Non-object payload / no `exp` / future `iat` | each is an explicit rejection |

### Injection and pollution

- **Prototype pollution** — `__proto__`, `constructor` and `prototype` are
  rejected as claim keys at any depth, by the schema *and* again in the service.
  `JWT_DATA_CLAIM` is validated the same way at boot, so the unrestricted `data`
  payload can never be written to a polluting key. A verified token carrying such
  a claim has it dropped and logged.
- **Strict schemas** — unknown body properties are rejected, so a caller cannot
  smuggle a field a future refactor might start honouring.
- **Query-string pollution** — the simple query parser is used, so `?a[b]=c`
  cannot build nested objects or deep structures.
- **Log/header injection** — an inbound `x-correlation-id` is echoed only if it
  matches `[A-Za-z0-9_.:-]{1,64}`; anything else is replaced with a fresh UUID.

### Credential attacks

- **Constant-time bearer comparison over SHA-256 digests**, always against every
  configured token — neither the timing nor the length of a guess leaks.
- **Brute force** — failed authentication has its own budget
  (`AUTH_RATE_LIMIT_MAX`) on top of the general limiter, and only 401 responses
  consume it, so a client making schema mistakes is never locked out.
- **Weak secrets** — production refuses to boot with duplicate access tokens or
  any token under 32 characters.

### Denial of service

- Rate limiting runs **before** body parsing, and body parsing runs **after**
  authentication, so an unauthenticated flood is rejected before a byte of JSON
  is parsed.
- `JSON_BODY_LIMIT` caps the body (the only ceiling on `data`); an oversize body
  is a clean 413.
- `claims` is bounded on serialized size, depth, array length, key count and
  string length.
- Slowloris is bounded by `REQUEST_TIMEOUT_MS`, `headersTimeout`,
  `keepAliveTimeout` and `maxHeadersCount` on the HTTP server.
- `TRUST_PROXY` defaults to 0 so a spoofed `X-Forwarded-For` cannot rotate a
  fake IP past the limiters.

### Disclosure

- **Errors disclose nothing by default.** Only `AppError` subclasses marked
  `expose` return their message; anything else is a generic 500 with a
  correlation id. Validation failures report field paths, never submitted values.
  Signature failures are deliberately generic — distinguishing failure modes
  helps an attacker probe.
- **No caching of tokens** — both token routes send `Cache-Control: no-store`.
- **Headers** — CSP `default-src 'none'`, no framing, no referrer, `nosniff`,
  HSTS in production, no `X-Powered-By`, no ETag, and no CORS headers at all, so
  a browser on another origin cannot call this API.
- **Logs** — `authorization`, `token`, `privateKey` and `password` paths are
  redacted by the logger; the service logs a token's `jti` and shape, never the
  token or its claim values.

### Key handling

- The signing key is imported **non-extractable**: it signs but cannot be
  exported back to PEM. The public JWK is derived from the private key, so the
  key that verifies always matches the key that signs.
- The key is loaded once at boot, before the port is bound, from a path or an
  inline secret that is never committed. A group/world-readable key file warns.
- **Rotation:** generate a new key, distribute the new public key to verifiers
  first, then switch `JWT_KEY_ID`. `scripts/generate-keys.js` refuses to
  overwrite an existing key without `--force`.
- **Signed, not encrypted.** Every claim in a JWT is readable by anyone holding
  it — never put a secret in `claims` or `data`.

### Known gaps

- There is no revocation list: a valid token stays valid until `exp`. Keep
  lifetimes short (`JWT_MAX_EXPIRY`) or add a `jti` denylist backed by a store.
- Access tokens are static strings. Replace `tokenMatches` in `src/app.js` with
  OAuth2 introspection for anything beyond a trusted internal caller.
- Rate-limit state is in-process; behind multiple instances, use a shared store.

---

## 6. Testing

```bash
npm test
npm run test:watch
```

Uses the built-in `node:test` runner — no external test framework. The HTTP
suite mounts the app with supertest, so no port is bound.

Coverage includes: header shape and `kid`, reserved-claim rejection, expiry
clamping, `alg: none`, HMAC key confusion, unknown-key rejection, expired /
not-yet-valid / no-`exp` tokens, issuer and audience mismatches, the `claims`
bounds, `data` round-tripping verbatim, auth failures, and the error and
correlation-id contract.
