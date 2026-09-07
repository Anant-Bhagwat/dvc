import test, { describe, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import request from 'supertest';
import { SignJWT, decodeProtectedHeader, decodeJwt } from 'jose';

const TEST_TOKEN = 'test-token-aiu-1';
const TEST_ISSUER = 'https://agristack.test.gov.in';

Object.assign(process.env, {
  NODE_ENV: 'test',
  LOG_LEVEL: 'fatal',
  JWT_ISSUER: TEST_ISSUER,
  JWT_KEY_ID: 'test-signing-key-01',
  JWT_PRIVATE_KEY_PATH: './src/keys/issuer-private.pem',
  JWT_PUBLIC_KEY_PATH: './src/keys/issuer-public.pem',
  JWT_DEFAULT_EXPIRY: '3600',
  JWT_MAX_EXPIRY: '86400',
  JWT_TRUSTED_ISSUERS: TEST_ISSUER,
  JSON_BODY_LIMIT: '64kb',
  AUTH_ENABLED: 'true',
  API_ACCESS_TOKENS: TEST_TOKEN,
  RATE_LIMIT_MAX: '100000',
  AUTH_RATE_LIMIT_MAX: '5',
});

const { initKeys, getSigningKey, getKeyId } = await import('../src/config.js');
const { createJwt, verifyJwt, PROTECTED_CLAIMS, VERIFY_REASONS } = await import('../src/jwt.js');
const { createApp, jwtCreateSchema, CLAIM_LIMITS } = await import('../src/app.js');

let app;

before(async () => {
  await initKeys();
  app = createApp();
});

const signRaw = (payload, header = {}) =>
  new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: getKeyId(), ...header })
    .sign(getSigningKey());

const nowSeconds = () => Math.floor(Date.now() / 1000);

const b64url = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

const handCraft = (header, payload, signature = 'A'.repeat(86)) =>
  [b64url(header), b64url(payload), signature].join('.');

describe('JWT issuance', () => {
  test('produces a compact JWS with the expected header', async () => {
    const { token } = await createJwt({ subject: 'AIU_ID' });

    assert.equal(token.split('.').length, 3);

    const header = decodeProtectedHeader(token);
    assert.equal(header.alg, 'ES256');
    assert.equal(header.typ, 'JWT');
    assert.equal(header.kid, getKeyId());
  });

  test('sets iss, iat, exp and a unique jti', async () => {
    const { token, jwtId } = await createJwt({ subject: 'AIU_ID', expiresIn: 600 });
    const payload = decodeJwt(token);

    assert.equal(payload.iss, TEST_ISSUER);
    assert.equal(payload.sub, 'AIU_ID');
    assert.equal(payload.jti, jwtId);
    assert.equal(typeof payload.iat, 'number');
    assert.equal(payload.exp - payload.iat, 600);
  });

  test('jti is unique across tokens', async () => {
    const ids = new Set();
    for (let i = 0; i < 50; i += 1) ids.add((await createJwt({})).jwtId);
    assert.equal(ids.size, 50);
  });

  test('carries custom claims through', async () => {
    const { token } = await createJwt({
      subject: 'AIU_ID',
      audience: 'agristack-api',
      claims: { role: 'AIU', level: 3, active: true },
    });
    const payload = decodeJwt(token);

    assert.equal(payload.role, 'AIU');
    assert.equal(payload.level, 3);
    assert.equal(payload.active, true);
    assert.equal(payload.aud, 'agristack-api');
  });

  test('honours notBefore', async () => {
    const { token } = await createJwt({ notBefore: 300 });
    const payload = decodeJwt(token);
    assert.equal(payload.nbf - payload.iat, 300);
  });

  test('clamps expiresIn to the configured maximum', async () => {
    const { issuedAt, expiresAt } = await createJwt({ expiresIn: 999_999_999 });
    assert.ok(expiresAt - issuedAt <= 86_400);
  });

  test('rejects a notBefore that outlives the token', async () => {
    await assert.rejects(() => createJwt({ expiresIn: 600, notBefore: 600 }), {
      code: 'VALIDATION_ERROR',
    });
  });
});

describe('JWT issuance - reserved claim protection', () => {
  for (const claim of PROTECTED_CLAIMS) {
    test(`rejects an attempt to set \`${claim}\` via custom claims`, async () => {
      await assert.rejects(() => createJwt({ claims: { [claim]: 'attacker-value' } }), {
        code: 'VALIDATION_ERROR',
      });
    });
  }

  test('rejects rather than silently strips, so the attempt is visible', async () => {
    await assert.rejects(
      () => createJwt({ claims: { exp: 99_999_999_999, role: 'admin' } }),
      (err) => {
        assert.equal(err.code, 'VALIDATION_ERROR');
        assert.deepEqual(err.details.reserved, ['exp']);
        return true;
      },
    );
  });
});

describe('JWT verification - happy path', () => {
  test('verifies a freshly issued token', async () => {
    const { token, jwtId } = await createJwt({
      subject: 'AIU_ID',
      audience: 'agristack-api',
      claims: { role: 'AIU' },
    });

    const result = await verifyJwt(token);

    assert.equal(result.valid, true);
    assert.equal(result.payload.sub, 'AIU_ID');
    assert.equal(result.payload.jti, jwtId);
    assert.equal(result.payload.role, 'AIU');
  });

  test('accepts a matching expected audience and subject', async () => {
    const { token } = await createJwt({ subject: 'AIU_ID', audience: 'agristack-api' });

    const result = await verifyJwt(token, {
      expectedAudience: 'agristack-api',
      expectedSubject: 'AIU_ID',
    });
    assert.equal(result.valid, true);
  });

  test('handles an array-valued aud', async () => {
    const now = nowSeconds();
    const token = await signRaw({ iss: TEST_ISSUER, iat: now, exp: now + 600, aud: ['svc-a', 'svc-b'] });

    const result = await verifyJwt(token, { expectedAudience: 'svc-b' });
    assert.equal(result.valid, true);
  });
});

describe('JWT verification - rejections', () => {
  test('rejects a tampered payload', async () => {
    const { token } = await createJwt({ subject: 'AIU_ID', claims: { role: 'AIU' } });
    const [h, p, s] = token.split('.');

    const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    payload.role = 'ADMIN';
    const forged = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');

    await assert.rejects(() => verifyJwt([h, forged, s].join('.')), {
      code: VERIFY_REASONS.INVALID_SIGNATURE,
    });
  });

  test('rejects an expired token', async () => {
    const now = nowSeconds();
    const token = await signRaw({ iss: TEST_ISSUER, iat: now - 7200, exp: now - 3600 });

    await assert.rejects(() => verifyJwt(token), { code: VERIFY_REASONS.CREDENTIAL_EXPIRED });
  });

  test('rejects a token with no exp - it would be valid forever', async () => {
    const token = await signRaw({ iss: TEST_ISSUER, iat: nowSeconds() });

    await assert.rejects(() => verifyJwt(token), { code: VERIFY_REASONS.MISSING_CLAIM });
  });

  test('rejects a not-yet-valid token', async () => {
    const now = nowSeconds();
    const token = await signRaw({ iss: TEST_ISSUER, iat: now, exp: now + 600, nbf: now + 300 });

    await assert.rejects(() => verifyJwt(token), { code: VERIFY_REASONS.CREDENTIAL_NOT_YET_VALID });
  });

  test('rejects an iat in the future', async () => {
    const now = nowSeconds();
    const token = await signRaw({ iss: TEST_ISSUER, iat: now + 3600, exp: now + 7200 });

    await assert.rejects(() => verifyJwt(token), { code: VERIFY_REASONS.INVALID_IAT });
  });

  test('rejects an untrusted issuer', async () => {
    const { token } = await createJwt({});
    await assert.rejects(() => verifyJwt(token, { trustedIssuers: ['https://other.example'] }), {
      code: VERIFY_REASONS.UNTRUSTED_ISSUER,
    });
  });

  test('rejects an audience mismatch', async () => {
    const { token } = await createJwt({ audience: 'svc-a' });
    await assert.rejects(() => verifyJwt(token, { expectedAudience: 'svc-b' }), {
      code: VERIFY_REASONS.HOLDER_BINDING_FAILED,
    });
  });

  test('rejects a subject mismatch', async () => {
    const { token } = await createJwt({ subject: 'AIU_A' });
    await assert.rejects(() => verifyJwt(token, { expectedSubject: 'AIU_B' }), {
      code: VERIFY_REASONS.HOLDER_BINDING_FAILED,
    });
  });

  test('rejects a structurally malformed token', async () => {
    await assert.rejects(() => verifyJwt('not-a-token'), { code: VERIFY_REASONS.MALFORMED_JWS });
  });
});

describe('Attack surface - token forgery', () => {
  test('rejects alg=none', async () => {
    const token = handCraft({ alg: 'none', typ: 'JWT' }, { iss: TEST_ISSUER }, '');

    await assert.rejects(() => verifyJwt(token), { code: VERIFY_REASONS.UNSUPPORTED_ALGORITHM });
  });

  test('rejects an HMAC-signed token (key confusion)', async () => {
    const token = await new SignJWT({ iss: TEST_ISSUER })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .sign(crypto.randomBytes(32));

    await assert.rejects(() => verifyJwt(token), { code: VERIFY_REASONS.UNSUPPORTED_ALGORITHM });
  });

  test('rejects a token signed by an unknown key', async () => {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const token = await new SignJWT({ iss: TEST_ISSUER })
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: 'attacker-key' })
      .sign(privateKey);

    await assert.rejects(() => verifyJwt(token), { code: VERIFY_REASONS.UNKNOWN_KEY_ID });
  });

  test('rejects a token minted under another `typ`', async () => {
    const now = nowSeconds();
    const token = await signRaw({ iss: TEST_ISSUER, iat: now, exp: now + 600 }, { typ: 'vc+sd-jwt' });

    await assert.rejects(() => verifyJwt(token), { code: VERIFY_REASONS.UNSUPPORTED_TYP });
  });

  test('rejects a header carrying an embedded jwk', async () => {
    const now = nowSeconds();
    const attacker = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = attacker.publicKey.export({ format: 'jwk' });
    const token = await signRaw({ iss: TEST_ISSUER, iat: now, exp: now + 600 }, { jwk });

    await assert.rejects(() => verifyJwt(token), { code: VERIFY_REASONS.UNSAFE_HEADER });
  });

  test('rejects a header pointing at a remote key set (jku)', async () => {
    const now = nowSeconds();
    const token = await signRaw(
      { iss: TEST_ISSUER, iat: now, exp: now + 600 },
      { jku: 'https://attacker.example/jwks.json' },
    );

    await assert.rejects(() => verifyJwt(token), { code: VERIFY_REASONS.UNSAFE_HEADER });
  });

  test('rejects a header declaring critical extensions', async () => {
    const now = nowSeconds();
    const token = handCraft(
      { alg: 'ES256', typ: 'JWT', kid: getKeyId(), crit: ['exp'] },
      { iss: TEST_ISSUER, iat: now, exp: now + 600 },
    );

    await assert.rejects(() => verifyJwt(token), { code: VERIFY_REASONS.UNSAFE_HEADER });
  });

  test('rejects a payload that is not a JSON object', async () => {
    const token = handCraft({ alg: 'ES256', typ: 'JWT', kid: getKeyId() }, [1, 2, 3]);

    await assert.rejects(() => verifyJwt(token), { code: VERIFY_REASONS.INVALID_SIGNATURE });
  });
});

describe('Attack surface - prototype pollution', () => {
  test('the service refuses a __proto__ claim', async () => {
    const claims = JSON.parse('{"__proto__":{"admin":true}}');
    await assert.rejects(() => createJwt({ claims }), { code: 'VALIDATION_ERROR' });
  });

  test('the service refuses a nested constructor key', async () => {
    const claims = JSON.parse('{"ctx":{"constructor":{"admin":true}}}');
    await assert.rejects(() => createJwt({ claims }), { code: 'VALIDATION_ERROR' });
  });

  test('the schema refuses polluting keys before the service is reached', () => {
    assert.equal(jwtCreateSchema.safeParse(JSON.parse('{"claims":{"__proto__":{"a":1}}}')).success, false);
    assert.equal(jwtCreateSchema.safeParse(JSON.parse('{"claims":{"prototype":1}}')).success, false);
  });

  test('a signed token carrying __proto__ has it stripped on verification', async () => {
    const now = nowSeconds();
    const payload = JSON.parse(
      `{"iss":"${TEST_ISSUER}","iat":${now},"exp":${now + 600},"__proto__":{"admin":true}}`,
    );
    const result = await verifyJwt(await signRaw(payload));

    assert.equal(Object.hasOwn(result.payload, '__proto__'), false);
    assert.equal({}.admin, undefined);
  });
});

const parse = (body) => jwtCreateSchema.safeParse(body);

describe('Create schema - accepted `claims` shapes', () => {
  test('accepts flat primitives', () => {
    assert.equal(parse({ claims: { role: 'AIU', level: 3, active: true, note: null } }).success, true);
  });

  test('accepts arrays', () => {
    const r = parse({ claims: { roles: ['AIU', 'VIEWER'], codes: [1, 2, 3] } });
    assert.equal(r.success, true);
    assert.deepEqual(r.data.claims.roles, ['AIU', 'VIEWER']);
  });

  test('accepts nested objects', () => {
    const r = parse({ claims: { ctx: { id: '96318220004', state: { code: 27, name: 'MH' } } } });
    assert.equal(r.success, true);
    assert.equal(r.data.claims.ctx.state.code, 27);
  });

  test('accepts mixed arrays of objects', () => {
    const r = parse({ claims: { grants: [{ scope: 'read', ttl: 60 }, { scope: 'write', ttl: 30 }] } });
    assert.equal(r.success, true);
  });

  test('accepts an empty claims object, and a body with no claims at all', () => {
    assert.equal(parse({ claims: {} }).success, true);
    assert.equal(parse({}).success, true);
  });
});

describe('Create schema - claim limits are enforced', () => {
  test('rejects nesting beyond the depth limit', () => {
    let deep = 'leaf';
    for (let i = 0; i < CLAIM_LIMITS.MAX_DEPTH + 1; i += 1) deep = { n: deep };

    const r = parse({ claims: { deep } });
    assert.equal(r.success, false);
    assert.match(JSON.stringify(r.error.issues), /nest at most/);
  });

  test('rejects claims larger than the serialized byte cap', () => {
    const claims = {};
    for (let i = 0; i < 10; i += 1) claims[`k${i}`] = 'x'.repeat(CLAIM_LIMITS.MAX_STRING_LENGTH);

    const r = parse({ claims });
    assert.equal(r.success, false);
    assert.match(JSON.stringify(r.error.issues), /must not exceed/);
  });

  test('rejects too many top-level claims', () => {
    const claims = {};
    for (let i = 0; i <= CLAIM_LIMITS.MAX_TOP_LEVEL_KEYS; i += 1) claims[`k${i}`] = 1;
    assert.equal(parse({ claims }).success, false);
  });

  test('rejects an over-long array', () => {
    const xs = Array.from({ length: CLAIM_LIMITS.MAX_ARRAY_LENGTH + 1 }, () => 1);
    assert.equal(parse({ claims: { xs } }).success, false);
  });

  test('rejects an over-long string value', () => {
    assert.equal(parse({ claims: { s: 'x'.repeat(CLAIM_LIMITS.MAX_STRING_LENGTH + 1) } }).success, false);
  });

  test('rejects non-finite numbers that JSON cannot represent', () => {
    assert.equal(parse({ claims: { n: Number.POSITIVE_INFINITY } }).success, false);
    assert.equal(parse({ claims: { n: Number.NaN } }).success, false);
  });

  test('rejects reserved claims at the top level, but allows them nested', () => {
    const r = parse({ claims: { exp: 9_999_999_999 } });
    assert.equal(r.success, false);
    assert.match(JSON.stringify(r.error.issues), /set by the issuer/);
    assert.equal(parse({ claims: { meta: { exp: 123 } } }).success, true);
  });

  test('rejects unknown top-level body properties', () => {
    assert.equal(parse({ claims: {}, injected: 'x' }).success, false);
  });
});

describe('Create schema - the unrestricted `data` field', () => {
  test('accepts an arbitrary nested object', () => {
    assert.equal(parse({ data: { a: { b: { c: { d: { e: { f: 'deep' } } } } } } }).success, true);
  });

  test('accepts a bare array, string, number, boolean and null', () => {
    for (const value of [[1, 2, 3], 'plain string', 42, true, null]) {
      assert.equal(parse({ data: value }).success, true, `rejected ${JSON.stringify(value)}`);
    }
  });

  test('accepts payloads far beyond the `claims` limits', () => {
    let deep = 'leaf';
    for (let i = 0; i < 40; i += 1) deep = { n: deep };

    const r = parse({
      data: { deep, big: 'x'.repeat(200_000), wide: Array.from({ length: 5000 }, (_, i) => i) },
    });
    assert.equal(r.success, true);
  });

  test('accepts keys that would be rejected inside `claims`', () => {
    assert.equal(parse({ data: { exp: 1, iss: 'anything', '': 'empty key', 'ключ': 'unicode' } }).success, true);
  });

  test('can be combined with `claims`', () => {
    assert.equal(parse({ claims: { role: 'AIU' }, data: { anything: [1, { two: 3 }] } }).success, true);
  });
});

const auth = (req) => req.set('Authorization', `Bearer ${TEST_TOKEN}`);
const post = (path, body) => auth(request(app).post(path)).send(body);
const create = (body) => post('/api/v1/jwt/create', body);
const verify = (body) => post('/api/v1/jwt/verify', body);

async function mint(body = { subject: 'AIU_ID', audience: 'svc-a' }) {
  const res = await create(body).expect(201);
  return res.body.data.token;
}

describe('GET /health', () => {
  test('responds without authentication', async () => {
    const res = await request(app).get('/health').expect(200);
    assert.equal(res.body.status, 'success');
  });
});

describe('Authentication', () => {
  test('rejects a missing token', async () => {
    const res = await request(app).post('/api/v1/jwt/create').send({}).expect(401);
    assert.equal(res.body.error.code, 'UNAUTHORIZED');
  });

  test('rejects an invalid token', async () => {
    const res = await request(app)
      .post('/api/v1/jwt/verify')
      .set('Authorization', 'Bearer wrong-token')
      .send({ token: 'x'.repeat(40) })
      .expect(401);
    assert.equal(res.body.error.code, 'UNAUTHORIZED');
  });

  test('rejects a non-Bearer scheme', async () => {
    await request(app)
      .post('/api/v1/jwt/create')
      .set('Authorization', `Basic ${TEST_TOKEN}`)
      .send({})
      .expect(401);
  });

  test('rate-limits repeated authentication failures', async () => {
    const isolated = createApp();
    const attempt = () => request(isolated).post('/api/v1/jwt/create').send({});

    for (let i = 0; i < 5; i += 1) await attempt().expect(401);

    const res = await attempt().expect(429);
    assert.equal(res.body.error.code, 'TOO_MANY_FAILED_AUTH');
  });

  test('successful requests do not consume the failure budget', async () => {
    const isolated = createApp();
    for (let i = 0; i < 8; i += 1) {
      await auth(request(isolated).post('/api/v1/jwt/create')).send({ subject: 'AIU_ID' }).expect(201);
    }
  });
});

describe('POST /api/v1/jwt/create', () => {
  test('issues a token with the expected envelope', async () => {
    const res = await create({ subject: 'AIU_ID', audience: 'svc-a', expiresIn: 600 }).expect(201);

    assert.equal(res.body.status, 'success');
    assert.equal(res.body.data.token_type, 'Bearer');
    assert.equal(res.body.data.expires_in, 600);
    assert.equal(res.body.data.token.split('.').length, 3);
    assert.ok(res.body.data.token_id);
  });

  test('carries the unrestricted `data` payload verbatim', async () => {
    const data = { any: ['shape', { at: 'all' }], n: 1 };
    const res = await verify({ token: await mint({ subject: 'AIU_ID', data }) }).expect(200);
    assert.deepEqual(res.body.data.data, data);
  });

  test('accepts the /verify field names as aliases', async () => {
    const res = await create({ expectedSubject: 'AIU_ID', expectedAudience: 'svc-a' }).expect(201);
    const verified = await verify({ token: res.body.data.token, expectedAudience: 'svc-a' }).expect(200);
    assert.equal(verified.body.data.subject, 'AIU_ID');
  });

  test('never lets a token response be cached', async () => {
    const res = await create({ subject: 'AIU_ID' }).expect(201);
    assert.match(res.headers['cache-control'], /no-store/);
  });

  test('rejects a reserved claim smuggled through `claims`', async () => {
    const res = await create({ claims: { exp: 9_999_999_999 } }).expect(400);
    assert.equal(res.body.error.code, 'VALIDATION_ERROR');
  });

  test('rejects unknown properties in the body', async () => {
    await create({ subject: 'AIU_ID', injected: 'value' }).expect(400);
  });

  test('rejects an expiresIn above the configured maximum', async () => {
    await create({ expiresIn: 999_999_999 }).expect(400);
  });

  test('rejects malformed JSON', async () => {
    const res = await auth(request(app).post('/api/v1/jwt/create'))
      .set('Content-Type', 'application/json')
      .send('{ not json')
      .expect(400);
    assert.equal(res.body.error.code, 'MALFORMED_JSON');
  });

  test('rejects a non-JSON content type', async () => {
    const res = await auth(request(app).post('/api/v1/jwt/create'))
      .set('Content-Type', 'text/plain')
      .send('subject=AIU_ID')
      .expect(415);
    assert.equal(res.body.error.code, 'UNSUPPORTED_MEDIA_TYPE');
  });

  test('rejects a body beyond the configured size limit', async () => {
    const res = await create({ data: 'x'.repeat(80 * 1024) }).expect(413);
    assert.equal(res.body.error.code, 'PAYLOAD_TOO_LARGE');
  });
});

describe('POST /api/v1/jwt/verify', () => {
  test('verifies a freshly minted token', async () => {
    const res = await verify({ token: await mint() }).expect(200);

    assert.equal(res.body.data.valid, true);
    assert.equal(res.body.data.issuer, TEST_ISSUER);
    assert.equal(res.body.data.subject, 'AIU_ID');
    assert.equal(res.body.data.audience, 'svc-a');
    assert.equal(res.body.data.header.alg, 'ES256');
    assert.equal(res.body.data.header.typ, 'JWT');
    assert.equal(res.body.data.header.kid, getKeyId());
  });

  test('returns custom claims separately from the registered ones', async () => {
    const token = await mint({ subject: 'AIU_ID', claims: { role: 'AIU', level: 3 } });
    const res = await verify({ token }).expect(200);

    assert.deepEqual(res.body.data.claims, { role: 'AIU', level: 3 });
    assert.ok(!('iss' in res.body.data.claims));
  });

  test('rejects an audience mismatch', async () => {
    const res = await verify({ token: await mint({ audience: 'svc-a' }), expectedAudience: 'svc-b' });
    assert.equal(res.status, 400);
    assert.equal(res.body.error.code, 'HOLDER_BINDING_FAILED');
  });

  test('rejects a tampered signature', async () => {
    const [h, p] = (await mint()).split('.');
    const res = await verify({ token: [h, p, 'A'.repeat(86)].join('.') }).expect(400);
    assert.equal(res.body.error.code, 'INVALID_SIGNATURE');
  });

  test('rejects a structurally malformed token', async () => {
    const res = await verify({ token: 'x'.repeat(40) }).expect(400);
    assert.equal(res.body.error.code, 'MALFORMED_JWS');
  });

  test('rejects a missing token field', async () => {
    const res = await verify({}).expect(400);
    assert.equal(res.body.error.code, 'VALIDATION_ERROR');
  });
});

describe('Error handling and headers', () => {
  test('unknown routes return a structured 404', async () => {
    const res = await request(app).get('/api/v1/does-not-exist').expect(404);
    assert.equal(res.body.error.code, 'ROUTE_NOT_FOUND');
  });

  test('every response carries a correlation id', async () => {
    const res = await request(app).get('/api/v1/nope').expect(404);
    assert.ok(res.headers['x-correlation-id']);
    assert.equal(res.body.correlationId, res.headers['x-correlation-id']);
  });

  test('a well-formed inbound correlation id is echoed back', async () => {
    const res = await request(app)
      .get('/api/v1/nope')
      .set('x-correlation-id', 'trace-abc-123')
      .expect(404);
    assert.equal(res.headers['x-correlation-id'], 'trace-abc-123');
  });

  test('a hostile correlation id is replaced, not reflected', async () => {
    const res = await request(app)
      .get('/api/v1/nope')
      .set('x-correlation-id', '<script>alert(1)</script>')
      .expect(404);
    assert.ok(!res.headers['x-correlation-id'].includes('<'));
    assert.match(res.headers['x-correlation-id'], /^[0-9a-f-]{36}$/);
  });

  test('the framework is not advertised and responses are not sniffable', async () => {
    const res = await request(app).get('/health');
    assert.equal(res.headers['x-powered-by'], undefined);
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN');
  });

  test('a validation failure does not echo the submitted values', async () => {
    const res = await create({ subject: 'AIU_ID', secretField: 'super-secret-value' }).expect(400);
    assert.ok(!JSON.stringify(res.body).includes('super-secret-value'));
  });

  test('an internal error never leaks a stack trace', async () => {
    const res = await verify({ token: `${'a'.repeat(20)}.b.c` }).expect(400);
    assert.ok(!JSON.stringify(res.body).includes('at '));
    assert.equal(res.body.error.details, undefined);
  });
});
