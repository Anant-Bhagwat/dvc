
// import {
//     jwtVerify,
// } from 'jose';

import {
    importJWK,
    jwtVerify,
} from 'jose';
import crypto from 'node:crypto';

import {
    env,
    getKeyId,
    resolveVerificationKey,
} from '../config/jwtkeys.config.js';

import {
    SDJWT,
    SDJWT_CLAIMS,
    SDJWT_LIMITS,
} from '../constants/sdjwt.constants.js';



function decodeBase64UrlJson(value) {
    try {
        const json = Buffer
            .from(value, 'base64url')
            .toString('utf8');

        return JSON.parse(json);
    } catch {
        throw new Error(
            'Invalid Base64URL JSON value',
        );
    }
}

function calculateDisclosureDigest(disclosureEncoded,) { return crypto.createHash('sha256').update(disclosureEncoded).digest('base64url'); }
function parseSdJwt(sdJwt) {
    if (
        typeof sdJwt !== 'string' ||
        sdJwt.length === 0
    ) {
        throw new TypeError(
            'SD-JWT must be a non-empty string',
        );
    }

    const size = Buffer.byteLength(
        sdJwt,
        'utf8',
    );

    if (
        size >
        SDJWT_LIMITS.MAX_SERIALIZED_BYTES
    ) {
        throw new Error(
            `SD-JWT exceeds the maximum size of ` +
            `${SDJWT_LIMITS.MAX_SERIALIZED_BYTES} bytes`,
        );
    }

    const parts = sdJwt.split(
        SDJWT.SERIALIZATION_SEPARATOR,
    );

    if (parts.length < 2) {
        throw new Error(
            'Invalid SD-JWT: disclosures are missing',
        );
    }

    const signedJwt = parts[0];
    const disclosures = parts.slice(1);

    if (
        disclosures.length >
        SDJWT_LIMITS.MAX_DISCLOSURES
    ) {
        throw new Error(
            `SD-JWT contains more than ` +
            `${SDJWT_LIMITS.MAX_DISCLOSURES} disclosures`,
        );
    }

    return {
        signedJwt,
        disclosures,
    };
}

function decodeDisclosure(
    disclosureEncoded,
) {
    const disclosure = decodeBase64UrlJson(
        disclosureEncoded,
    );

    if (
        !Array.isArray(disclosure) ||
        disclosure.length !== 3
    ) {
        throw new Error(
            'Invalid disclosure: expected [salt, claimName, value]',
        );
    }

    const [
        salt,
        name,
        value,
    ] = disclosure;

    if (
        typeof salt !== 'string' ||
        salt.length === 0
    ) {
        throw new Error(
            'Invalid disclosure salt',
        );
    }

    if (
        typeof name !== 'string' ||
        name.length === 0
    ) {
        throw new Error(
            'Invalid disclosure claim name',
        );
    }

    return {
        salt,
        name,
        value,
        encoded: disclosureEncoded,
    };
}

function verifyDisclosureDigests(
    disclosures,
    expectedDigests,
) {
    if (!Array.isArray(expectedDigests)) {
        throw new Error(
            '_sd must be an array',
        );
    }

    if (
        expectedDigests.length !==
        disclosures.length
    ) {
        throw new Error(
            `_sd contains ${expectedDigests.length} digests, ` +
            `but SD-JWT contains ${disclosures.length} disclosures`,
        );
    }

    const verifiedDisclosures = disclosures.map(
        (encoded, index) => {
            const calculatedDigest =
                calculateDisclosureDigest(
                    encoded,
                );

            const expectedDigest =
                expectedDigests[index];

            if (
                calculatedDigest !==
                expectedDigest
            ) {
                throw new Error(
                    `Disclosure ${index + 1} digest mismatch`,
                );
            }

            return decodeDisclosure(encoded);
        },
    );

    return verifiedDisclosures;
}

function buildDisclosedClaims(
    disclosures,
) {
    const claims = {};

    for (const disclosure of disclosures) {
        if (
            Object.prototype.hasOwnProperty.call(
                claims,
                disclosure.name,
            )
        ) {
            throw new Error(
                `Duplicate disclosed claim: ${disclosure.name}`,
            );
        }

        claims[disclosure.name] =
            disclosure.value;
    }

    return claims;
}

function validateProtectedHeader(
    protectedHeader,
) {
    if (
        protectedHeader.alg !==
        SDJWT.ALGORITHM
    ) {
        throw new Error(
            `Unexpected JWT algorithm: ${protectedHeader.alg}`,
        );
    }

    if (
        protectedHeader.typ !==
        SDJWT.TYPE
    ) {
        throw new Error(
            `Unexpected JWT type: ${protectedHeader.typ}`,
        );
    }

    if (
        protectedHeader.kid !==
        getKeyId()
    ) {
        throw new Error(
            `Unexpected JWT key ID: ${protectedHeader.kid}`,
        );
    }
}

function validatePayload(payload) {
    if (
        payload[SDJWT_CLAIMS.ISSUER] !==
        env.JWT_ISSUER
    ) {
        throw new Error(
            `Unexpected issuer: ${payload[SDJWT_CLAIMS.ISSUER]}`,
        );
    }

    if (
        payload[SDJWT_CLAIMS.SD_ALGORITHM] !==
        SDJWT.HASH_ALGORITHM
    ) {
        throw new Error(
            `Unexpected SD algorithm: ` +
            `${payload[SDJWT_CLAIMS.SD_ALGORITHM]}`,
        );
    }

    if (
        typeof payload[SDJWT_CLAIMS.CREDENTIAL_ID] !==
        'string' ||
        payload[SDJWT_CLAIMS.CREDENTIAL_ID].length === 0
    ) {
        throw new Error(
            'Credential ID is missing',
        );
    }

    if (
        !Number.isInteger(
            payload[SDJWT_CLAIMS.ISSUED_AT],
        )
    ) {
        throw new Error(
            'iat must be an integer Unix timestamp',
        );
    }

    if (
        !Number.isInteger(
            payload[SDJWT_CLAIMS.EXPIRATION],
        )
    ) {
        throw new Error(
            'exp must be an integer Unix timestamp',
        );
    }

    if (
        payload[SDJWT_CLAIMS.EXPIRATION] <=
        payload[SDJWT_CLAIMS.ISSUED_AT]
    ) {
        throw new Error(
            'exp must be greater than iat',
        );
    }
}

async function verifyKeyBindingJwt({
    kbJwt,
    sdJwt,
    holderJwk,
    expectedAudience,
    expectedNonce,
}) {
    if (
        typeof kbJwt !== 'string' ||
        kbJwt.length === 0
    ) {
        throw new Error(
            'KB-JWT is required',
        );
    }

    if (
        !holderJwk ||
        typeof holderJwk !== 'object'
    ) {
        throw new Error(
            'Holder public JWK is missing',
        );
    }

    if (
        typeof expectedAudience !== 'string' ||
        expectedAudience.length === 0
    ) {
        throw new Error(
            'Expected audience is required',
        );
    }

    if (
        typeof expectedNonce !== 'string' ||
        expectedNonce.length === 0
    ) {
        throw new Error(
            'Expected nonce is required',
        );
    }

    const holderPublicKey =
        await importJWK(
            holderJwk,
            'ES256',
        );

    const verification =
        await jwtVerify(
            kbJwt,
            holderPublicKey,
            {
                algorithms: [
                    'ES256',
                ],
                audience:
                    expectedAudience,
            },
        );

    if (
        verification.protectedHeader.typ !==
        'kb+jwt'
    ) {
        throw new Error(
            `Unexpected KB-JWT type: ` +
            `${verification.protectedHeader.typ}`,
        );
    }

    if (
        verification.protectedHeader.alg !==
        'ES256'
    ) {
        throw new Error(
            `Unexpected KB-JWT algorithm: ` +
            `${verification.protectedHeader.alg}`,
        );
    }

    if (
        verification.payload.nonce !==
        expectedNonce
    ) {
        throw new Error(
            'KB-JWT nonce mismatch',
        );
    }

    const calculatedSdHash =
        crypto
            .createHash('sha256')
            .update(
                Buffer.from(sdJwt, 'utf8'),
            )
            .digest('base64url');

    if (
        verification.payload.sd_hash !==
        calculatedSdHash
    ) {
        throw new Error(
            'KB-JWT sd_hash does not match the presented SD-JWT',
        );
    }

    return Object.freeze({
        protectedHeader:
            verification.protectedHeader,

        payload:
            verification.payload,
    });
}

export async function verifySdJwt({
    sdJwt,
    kbJwt,
    expectedAudience,
    expectedNonce,
}) {
    const {
        signedJwt,
        disclosures,
    } = parseSdJwt(sdJwt);

    const verificationKey =
        resolveVerificationKey(
            getKeyId(),
        );

    const verification =
        await jwtVerify(
            signedJwt,
            verificationKey,
            {
                issuer: env.JWT_ISSUER,
                algorithms: [
                    SDJWT.ALGORITHM,
                ],
            },
        );

    validateProtectedHeader(
        verification.protectedHeader,
    );

    validatePayload(
        verification.payload,
    );
    const holderJwk =
        verification.payload[
            SDJWT_CLAIMS.HOLDER_BINDING
        ]?.jwk;

    const keyBinding =
        await verifyKeyBindingJwt({
            kbJwt,
            sdJwt,
            holderJwk,
            expectedAudience,
            expectedNonce,
        });

    const verifiedDisclosures =
        verifyDisclosureDigests(
            disclosures,
            verification.payload[
            SDJWT_CLAIMS.SD_DIGESTS
            ],
        );

    const disclosedClaims =
        buildDisclosedClaims(
            verifiedDisclosures,
        );

    return Object.freeze({
        valid: true,

        signedJwt,

        sdJwt,

        protectedHeader:
            verification.protectedHeader,

        payload:
            verification.payload,

        disclosedClaims,

        disclosures:
            verifiedDisclosures,
        keyBinding: {
            valid: true,
            protectedHeader:
                keyBinding.protectedHeader,
            payload:
                keyBinding.payload,
        },
    });
}

