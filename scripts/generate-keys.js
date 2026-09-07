#!/usr/bin/env node
import 'dotenv/config';

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const keysDir = path.resolve(__dirname, '..', 'src', 'keys');

const privatePath = path.join(keysDir, 'issuer-private.pem');
const publicPath = path.join(keysDir, 'issuer-public.pem');
const jwksPath = path.join(keysDir, 'issuer-public.jwks.json');

const force = process.argv.includes('--force');

function main() {
  fs.mkdirSync(keysDir, { recursive: true });

  if (fs.existsSync(privatePath) && !force) {
    console.error(
      `Refusing to overwrite an existing issuer key at:\n  ${privatePath}\n\n` +
        `Replacing the issuer key invalidates every token already issued.\n` +
        `If that is genuinely what you want, re-run with --force, and plan a\n` +
        `key rotation: distribute the new public key first, then retire the old kid.`,
    );
    process.exit(1);
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

  fs.writeFileSync(privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(publicPath, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });

  const jwk = publicKey.export({ format: 'jwk' });
  const kid = process.env.JWT_KEY_ID || 'jwt-signing-key-01';
  const publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, alg: 'ES256', use: 'sig', kid };

  fs.writeFileSync(jwksPath, `${JSON.stringify({ keys: [publicJwk] }, null, 2)}\n`, { mode: 0o644 });

  console.log('ES256 issuer key pair generated:\n');
  console.log(`  private key : ${privatePath}   (mode 0600 - NEVER commit)`);
  console.log(`  public key  : ${publicPath}`);
  console.log(`  public JWKS : ${jwksPath}`);
  console.log(`\n  kid : ${kid}`);
  console.log(`  crv : ${publicJwk.crv}`);
  console.log('\nNext steps:');
  console.log('  1. Copy .env.example to .env');
  console.log(`  2. Ensure JWT_KEY_ID=${kid}`);
  console.log('  3. Confirm .gitignore excludes src/keys/*.pem  (it does by default)');
}

main();
