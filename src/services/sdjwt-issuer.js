
import {
    SignJWT,
} from 'jose';

import {
    env,
    getKeyId,
    getSigningKey,
} from '../config/jwtkeys.config.js';

import {
    SDJWT,
    SDJWT_CLAIMS,
} from '../constants/sdjwt.constants.js';

import {
    createDisclosures,
    getDisclosureDigests,
    serializeSdJwt,
} from './disclosure.js';

/**
 * Create an SD-JWT VC.
 *
 * The resulting format is:
 *
 *   signed-JWT~disclosure1~disclosure2~...
 *
 * The signed JWT contains:
 *
 *   header:
 *     alg
 *     typ
 *     kid
 *
 *   payload:
 *     @context
 *     iss
 *     cnf
 *     id
 *     iat
 *     exp
 *     status
 *     _sd_alg
 *     _sd
 */
export async function createSdJwt({
    credentialId,
    holderJwk,
    claims = {},
    expiresIn = 24 * 60 * 60,
}) {
    const issuedAt = Math.floor(Date.now() / 1000);
    const expiresAt = issuedAt + expiresIn;

    /*
     * Step 1:
     * Convert selectively disclosable claims into disclosures.
     */
    const disclosures = createDisclosures(claims);

    /*
     * Step 2:
     * Extract the disclosure digests.
     *
     * These are the values that go into "_sd".
     */
    const sdDigests = getDisclosureDigests(disclosures);

    /*
     * Step 3:
     * Build the SD-JWT VC payload.
     */
    const payload = {
        '@context': [
            SDJWT.VC_CONTEXT,
        ],

        [SDJWT_CLAIMS.ISSUER]:
            env.JWT_ISSUER,

        [SDJWT_CLAIMS.HOLDER_BINDING]: {
            jwk: holderJwk,
        },

        [SDJWT_CLAIMS.CREDENTIAL_ID]:
            credentialId,

        [SDJWT_CLAIMS.ISSUED_AT]:
            issuedAt,

        [SDJWT_CLAIMS.EXPIRATION]:
            expiresAt,

        [SDJWT_CLAIMS.STATUS]:
            `${env.JWT_ISSUER}/credentials/status/${encodeURIComponent(
                credentialId,
            )}`,

        [SDJWT_CLAIMS.SD_ALGORITHM]:
            SDJWT.HASH_ALGORITHM,

        [SDJWT_CLAIMS.SD_DIGESTS]:
            sdDigests,
    };

    /*
     * Step 4:
     * Create the issuer-signed JWT.
     *
     * This is still a normal JOSE/JWT signing operation.
     */
    const signedJwt = await new SignJWT(payload)
        .setProtectedHeader({
            alg: SDJWT.ALGORITHM,
            typ: SDJWT.TYPE,
            kid: getKeyId(),
        })
        .sign(getSigningKey());

    /*
     * Step 5:
     * Add the disclosures using "~".
     */
    const sdJwt = serializeSdJwt(
        signedJwt,
        disclosures,
    );

    return Object.freeze({
        sdJwt,
        signedJwt,
        disclosures,
        payload,
        issuedAt,
        expiresAt,
    });
}

