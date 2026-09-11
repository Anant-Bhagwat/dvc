
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    generateHolderKeyPair,
    exportHolderPublicJwk,
} from '../src/services/holder-keys.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const keysDir = path.join(__dirname, '..', 'keys');

fs.mkdirSync(keysDir, {
    recursive: true,
});

const {
    publicKey,
    privateKey,
} = generateHolderKeyPair();

const privatePem = privateKey.export({
    type: 'pkcs8',
    format: 'pem',
});

const publicPem = publicKey.export({
    type: 'spki',
    format: 'pem',
});

const publicJwk = exportHolderPublicJwk(publicKey);

fs.writeFileSync(
    path.join(keysDir, 'holder-private.pem'),
    privatePem,
    'utf8',
);

fs.writeFileSync(
    path.join(keysDir, 'holder-public.pem'),
    publicPem,
    'utf8',
);

console.log('Holder key pair generated successfully.');

console.log('\nPublic JWK:');
console.log(JSON.stringify(publicJwk, null, 2));

console.log('\nSaved files:');
console.log('keys/holder-private.pem');
console.log('keys/holder-public.pem');

