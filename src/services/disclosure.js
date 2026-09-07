
import crypto from 'node:crypto';

import {
    SDJWT,
    SDJWT_LIMITS,
} from '../constants/sdjwt.constants.js';

/**
 * Encode a value using Base64URL encoding.
 *
 * Node.js provides the "base64url" encoding directly.
 */
function base64url(value) {
    const buffer = Buffer.isBuffer(value)
        ? value
        : Buffer.from(value, 'utf8');

    return buffer.toString('base64url');
}

/**
 * Generate a random salt for a disclosure.
 *
 * The salt is the first element of the disclosure array.
 */
function createSalt() {
    return crypto.randomUUID();
}

/**
 * Create one SD-JWT disclosure.
 *
 * Disclosure format:
 *
 * [
 *     "salt",
 *     "claim-name",
 *     claim-value
 * ]
 *
 * Example:
 *
 * [
 *     "31dbda4b-4f31-4c09-aad5-896259ae23cc",
 *     "ResidentName",
 *     "Shahid Anwer Shaikh"
 * ]
 *
 * Processing:
 *
 * 1. JSON.stringify(disclosure)
 * 2. Base64URL encode the JSON
 * 3. SHA-256 the Base64URL disclosure
 * 4. Base64URL encode the SHA-256 result
 */
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

/**
 * Create disclosures for all selectively disclosable claims.
 */
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

/**
 * Extract the disclosure digests.
 *
 * These values will later become the "_sd" array
 * inside the SD-JWT payload.
 */
export function getDisclosureDigests(disclosures) {
    return disclosures.map(
        (disclosure) => disclosure.digest,
    );
}

/**
 * Serialize the issuer-signed JWT and disclosures.
 *
 * Format:
 *
 * JWT~disclosure1~disclosure2~disclosure3
 */
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

