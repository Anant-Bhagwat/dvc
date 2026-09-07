
export const SDJWT = Object.freeze({
    TYPE: 'vc+sd-jwt',
    ALGORITHM: 'ES256',
    HASH_ALGORITHM: 'sha-256',
    VC_CONTEXT: 'https://www.w3.org/ns/credentials/v1',
    SERIALIZATION_SEPARATOR: '~',
    JWT_SEPARATOR: '.',
});

export const SDJWT_CLAIMS = Object.freeze({
    ISSUER: 'iss',
    CREDENTIAL_ID: 'id',
    ISSUED_AT: 'iat',
    EXPIRATION: 'exp',
    STATUS: 'status',
    HOLDER_BINDING: 'cnf',

    SD_ALGORITHM: '_sd_alg',
    SD_DIGESTS: '_sd',
});

export const SDJWT_LIMITS = Object.freeze({
    MAX_DISCLOSURES: 100,
    MAX_DISCLOSURE_BYTES: 16 * 1024,
    MAX_SERIALIZED_BYTES: 256 * 1024,
});

