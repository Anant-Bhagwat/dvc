
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


export async function createShareSdJwt({
    credentialId,
    holderJwk,
    claims = {},
}) {
    const issuedAt = Math.floor(Date.now() / 1000);
    const expiresAt = issuedAt + 24 * 60 * 60;

    const disclosures = createDisclosures(claims);

    const sdDigests = getDisclosureDigests(disclosures);

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


    const signedJwt = await new SignJWT(payload)
        .setProtectedHeader({
            alg: SDJWT.ALGORITHM,
            typ: SDJWT.TYPE,
            kid: getKeyId(),
        })
        .sign(getSigningKey());


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
        expiresAt
    });
}
