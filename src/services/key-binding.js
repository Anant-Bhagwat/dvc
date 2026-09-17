import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import {
    importPKCS8,
    SignJWT,
} from 'jose';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const HOLDER_PRIVATE_KEY_PATH = path.join(
    __dirname,
    '../../keys/holder-private.pem',
);

async function getHolderPrivateKey() {
    const privatePem = fs.readFileSync(
        HOLDER_PRIVATE_KEY_PATH,
        'utf8',
    );

    return importPKCS8(
        privatePem,
        'ES256',
    );
}


export async function createKeyBindingJwt({
    sdJwt,
    audience,
    nonce,
}) {
    if (
        typeof sdJwt !== 'string' ||
        sdJwt.length === 0
    ) {
        throw new TypeError(
            'sdJwt is required',
        );
    }

    if (
        typeof audience !== 'string' ||
        audience.length === 0
    ) {
        throw new TypeError(
            'audience is required',
        );
    }

    if (
        typeof nonce !== 'string' ||
        nonce.length === 0
    ) {
        throw new TypeError(
            'nonce is required',
        );
    }

    const privateKey = await getHolderPrivateKey();

    const issuedAt = Math.floor(
        Date.now() / 1000,
    );


    const sdHash = crypto
        .createHash('sha256')
        .update(
            Buffer.from(sdJwt, 'utf8'),
        )
        .digest('base64url');

    const kbJwt = await new SignJWT({
        iat: issuedAt,
        aud: audience,
        nonce,
        sd_hash: sdHash,
    })
        .setProtectedHeader({
            alg: 'ES256',
            typ: 'kb+jwt',
        })
        .sign(privateKey);

    return kbJwt;
}