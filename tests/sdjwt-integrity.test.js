
import crypto from 'node:crypto';

import {
    initKeys,
} from '../src/config/jwtkeys.config.js';

import {
    SDJWT,
    SDJWT_CLAIMS,
} from '../src/constants/sdjwt.constants.js';

function decodeBase64UrlJson(value) {
    const json = Buffer
        .from(value, 'base64url')
        .toString('utf8');

    return JSON.parse(json);
}

function calculateDisclosureDigest(disclosureEncoded) {
    return crypto
        .createHash('sha256')
        .update(disclosureEncoded)
        .digest('base64url');
}

async function main() {
    await initKeys();

    /*
     * Paste the complete FINAL SD-JWT here.
     *
     * It must contain:
     *
     * signed-JWT~disclosure1~disclosure2~disclosure3
     */
  const sdJwt = `eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCIsImtpZCI6Imp3dC1zaWduaW5nLWtleS0wMSJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjEiXSwiaXNzIjoiaHR0cHM6Ly9hZ3Jpc3RhY2suZXhhbXBsZS5nb3YuaW4iLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwieCI6ImQtclFEX3E4bHJRSXVvTGMwOWt5LTh3SUZTR1NzcFg3R1ptRDNJY0JqSDAiLCJ5IjoiMVlRV1I1dGVwVUpHSE92RFYzQjY3SjctcGVCN2R2dThDU3dlenlTM1hqRSIsImNydiI6IlAtMjU2IiwiYWxnIjoiRVMyNTYifX0sImlkIjoiRlJNLUNSRUQtMDAwMSIsImlhdCI6MTc4ODc2OTA1MSwiZXhwIjoxNzg4ODU1NDUxLCJzdGF0dXMiOiJodHRwczovL2FncmlzdGFjay5leGFtcGxlLmdvdi5pbi9jcmVkZW50aWFscy9zdGF0dXMvRlJNLUNSRUQtMDAwMSIsIl9zZF9hbGciOiJzaGEtMjU2IiwiX3NkIjpbIkZod0d6NnRTSDg0ZV84emNnV0NLVkZoa05JN1VUaFI0S1VycXE0czJwRFEiLCJ2bDRyc05mVkYzU291aFNIZ2dyQUQzcnpjck1aRmdYNXZNb0NFSnhuenlrIiwia2ViTktQTEpzd0Y1UHdFM3gtTC10b3NwZ0ZzanBtZ05FTWlMZkpQVnl4MCJdfQ.ycoNa-ymXYSjstXKNlpkS9hM2l8DRPxZs1BYhpJSyFEbqtziaVR51dkkMG3K8Pq7aYa3AALxy8eLNZru3f60AA~WyI3MDM5MmQwOC05Mjk5LTQ0NzktOGE3Yi1lZmM0NzFhOTZkOWUiLCJmYXJtZXJJZCIsIkZSTTAwMDEiXQ~WyI4YzI3NTE2MS03MmU3LTRjNTktYmZhZi1kY2E1NDQxNGJjNzUiLCJmYXJtZXJOYW1lIiwiUmFqZXNoIEt1bWFyIl0~WyJkMWI3NDI5ZS03YWZlLTRiZDAtYjFlNy1mOTM1Mzg0NGMyMTUiLCJmYXRoZXJOYW1lIiwiTWFoZXNoIEt1bWFyIl0`;

    console.log('\n========================================');
    console.log('SD-JWT INTEGRITY CHECK');
    console.log('========================================');

    if (!sdJwt || sdJwt === 'PLACEHOLDER') {
        throw new Error(
            'Please paste the complete FINAL SD-JWT into the sdJwt variable',
        );
    }

    /*
     * SD-JWT structure:
     *
     * signed-JWT~disclosure1~disclosure2~...
     */
    const parts = sdJwt.split(
        SDJWT.SERIALIZATION_SEPARATOR,
    );

    const signedJwt = parts[0];
    const disclosures = parts.slice(1);

    console.log('\nTotal parts:', parts.length);
    console.log('Disclosure count:', disclosures.length);

    /*
     * Signed JWT must contain:
     *
     * header.payload.signature
     */
    const jwtParts = signedJwt.split(
        SDJWT.JWT_SEPARATOR,
    );

    if (jwtParts.length !== 3) {
        throw new Error(
            'Invalid signed JWT: expected header.payload.signature',
        );
    }

    const [encodedHeader, encodedPayload, signature] =
        jwtParts;

    if (!signature) {
        throw new Error(
            'Signed JWT signature is missing',
        );
    }

    const header = decodeBase64UrlJson(
        encodedHeader,
    );

    const payload = decodeBase64UrlJson(
        encodedPayload,
    );

    console.log('\n========================================');
    console.log('JWT HEADER');
    console.log('========================================');

    console.log(JSON.stringify(
        header,
        null,
        2,
    ));

    console.log('\n========================================');
    console.log('JWT PAYLOAD');
    console.log('========================================');

    console.log(JSON.stringify(
        payload,
        null,
        2,
    ));

    /*
     * Check SD-JWT algorithm.
     */
    if (
        payload[SDJWT_CLAIMS.SD_ALGORITHM] !==
        SDJWT.HASH_ALGORITHM
    ) {
        throw new Error(
            `Unexpected SD algorithm: ${payload[SDJWT_CLAIMS.SD_ALGORITHM]
            }`,
        );
    }

    /*
     * Get the digest list from _sd.
     */
    const expectedDigests =
        payload[SDJWT_CLAIMS.SD_DIGESTS];

    if (!Array.isArray(expectedDigests)) {
        throw new Error(
            '_sd must be an array',
        );
    }

    if (expectedDigests.length !== disclosures.length) {
        throw new Error(
            `_sd contains ${expectedDigests.length} digests, ` +
            `but SD-JWT contains ${disclosures.length} disclosures`,
        );
    }

    console.log('\n========================================');
    console.log('DISCLOSURE VERIFICATION');
    console.log('========================================');

    let allPassed = true;

    disclosures.forEach(
        (disclosureEncoded, index) => {
            const calculatedDigest =
                calculateDisclosureDigest(
                    disclosureEncoded,
                );

            const expectedDigest =
                expectedDigests[index];

            const passed =
                calculatedDigest === expectedDigest;

            console.log(
                `\nDisclosure ${index + 1}`,
            );

            console.log(
                'Encoded disclosure:',
            );

            console.log(
                disclosureEncoded,
            );

            console.log(
                '\nExpected digest:',
            );

            console.log(
                expectedDigest,
            );

            console.log(
                '\nCalculated digest:',
            );

            console.log(
                calculatedDigest,
            );

            console.log(
                '\nResult:',
                passed ? 'PASS' : 'FAIL',
            );

            if (!passed) {
                allPassed = false;
            }
        },
    );

    console.log('\n========================================');
    console.log('FINAL RESULT');
    console.log('========================================');

    if (!allPassed) {
        throw new Error(
            'SD-JWT integrity check FAILED',
        );
    }

    console.log(
        'PASS - All disclosure digests match _sd',
    );

    console.log(
        'PASS - SD-JWT disclosure integrity verified',
    );
}

main().catch((error) => {
    console.error('\nSD-JWT integrity check failed:');
    console.error(error);
    process.exit(1);
});

