import {
    createKeyBindingJwt,
} from '../src/services/key-binding.js';

const sdJwt = process.argv[2];

if (!sdJwt) {
    console.error(
        'Usage: node tests/key-binding.test.js "<sdJwt>"',
    );

    process.exit(1);
}

const kbJwt = await createKeyBindingJwt({
    sdJwt,
    audience: 'https://bank.example.in',
    nonce: 'demo-bank-challenge-001',
});

console.log('\nKB-JWT:\n');
console.log(kbJwt);

console.log('\nKB-JWT parts:\n');

const parts = kbJwt.split('.');

console.log(
    'Header:',
    JSON.parse(
        Buffer.from(parts[0], 'base64url').toString('utf8'),
    ),
);

console.log(
    'Payload:',
    JSON.parse(
        Buffer.from(parts[1], 'base64url').toString('utf8'),
    ),
);