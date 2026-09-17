
import crypto from 'node:crypto';

import {
    SDJWT,
    SDJWT_LIMITS,
} from '../constants/sdjwt.constants.js';


function base64url(value) {
    const buffer = Buffer.isBuffer(value)
        ? value
        : Buffer.from(value, 'utf8');

    return buffer.toString('base64url');
}


function createSalt() {
    return crypto.randomUUID();
}


export function createDisclosure(name, value) {
    if (typeof name !== 'string' || name.length === 0) {
        throw new TypeError(
            'Disclosure claim name must be a non-empty string',
        );
    }

    const disclosure = [
        createSalt(),
        name,
        value,
    ];

    // Step 1: JSON
    const json = JSON.stringify(disclosure);

    const jsonBytes = Buffer.byteLength(json, 'utf8');

    if (jsonBytes > SDJWT_LIMITS.MAX_DISCLOSURE_BYTES) {
        throw new Error(
            `Disclosure for "${name}" exceeds the maximum size of ` +
            `${SDJWT_LIMITS.MAX_DISCLOSURE_BYTES} bytes`,
        );
    }

    // Step 2: Base64URL
    const disclosureB64 = base64url(json);

    // Step 3: SHA-256
    const hash = crypto
        .createHash('sha256')
        .update(disclosureB64)
        .digest();

    // Step 4: Base64URL digest
    const sdDigest = hash.toString('base64url');

    return Object.freeze({
        name,
        value,
        salt: disclosure[0],
        json,
        encoded: disclosureB64,
        digest: sdDigest,
    });
}


export function createDisclosures(claims = {}) {
    const entries = Object.entries(claims);

    if (entries.length > SDJWT_LIMITS.MAX_DISCLOSURES) {
        throw new Error(
            `Maximum of ${SDJWT_LIMITS.MAX_DISCLOSURES} disclosures allowed`,
        );
    }

    return entries.map(([name, value]) =>
        createDisclosure(name, value),
    );
}


export function getDisclosureDigests(disclosures) {
    return disclosures.map(
        (disclosure) => disclosure.digest,
    );
}


export function serializeSdJwt(jwt, disclosures = []) {
    if (typeof jwt !== 'string' || jwt.length === 0) {
        throw new TypeError(
            'Signed JWT must be a non-empty string',
        );
    }

    const parts = [
        jwt,
        ...disclosures.map(
            (disclosure) => disclosure.encoded,
        ),
    ];

    const serialized = parts.join(
        SDJWT.SERIALIZATION_SEPARATOR,
    );

    const serializedBytes = Buffer.byteLength(
        serialized,
        'utf8',
    );

    if (serializedBytes > SDJWT_LIMITS.MAX_SERIALIZED_BYTES) {
        throw new Error(
            `Serialized SD-JWT exceeds the maximum size of ` +
            `${SDJWT_LIMITS.MAX_SERIALIZED_BYTES} bytes`,
        );
    }

    return serialized;
}

