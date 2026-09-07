
import crypto from 'node:crypto';

import {
    initKeys,
    getKeyId,
} from '../src/config/jwtkeys.config.js';

import {
    createSdJwt,
} from '../src/services/sdjwt-issuer.js';

async function main() {
    console.log('Initializing issuer keys...');

    await initKeys();

    /*
     * Create a test holder key.
     *
     * This is NOT your issuer key.
     * It represents the holder's public key that will go
     * inside cnf.jwk.
     */
    const { publicKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
    });

    const holderJwk = publicKey.export({
        format: 'jwk',
    });

    holderJwk.alg = 'ES256';

    console.log('\nIssuer key ID:');
    console.log(getKeyId());

    /*
     * Sample selectively-disclosable farmer claims.
     */
    const claims = {
        farmerId: 'FRM0001',
        farmerName: 'Rajesh Kumar',
        fatherName: 'Mahesh Kumar',
    };

    /*
     * Create the SD-JWT.
     */
    const result = await createSdJwt({
        credentialId: 'FRM-CRED-0001',
        holderJwk,
        claims,
        expiresIn: 24 * 60 * 60,
    });

    console.log('\n========================================');
    console.log('SIGNED JWT');
    console.log('========================================');

    console.log(result.signedJwt);

    console.log('\n========================================');
    console.log('DISCLOSURES');
    console.log('========================================');

    result.disclosures.forEach((disclosure, index) => {
        console.log(`\nDisclosure ${index + 1}`);
        console.log('Claim name :', disclosure.name);
        console.log('Value      :', disclosure.value);
        console.log('Salt       :', disclosure.salt);
        console.log('JSON       :', disclosure.json);
        console.log('Base64URL   :', disclosure.encoded);
        console.log('SHA-256    :', disclosure.digest);
    });

    console.log('\n========================================');
    console.log('_SD DIGESTS');
    console.log('========================================');

    console.log(JSON.stringify(
        result.payload._sd,
        null,
        2,
    ));

    console.log('\n========================================');
    console.log('SD-JWT PAYLOAD');
    console.log('========================================');

    console.log(JSON.stringify(
        result.payload,
        null,
        2,
    ));

    console.log('\n========================================');
    console.log('FINAL SD-JWT');
    console.log('========================================');

    console.log(result.sdJwt);

    console.log('\n========================================');
    console.log('STRUCTURE CHECK');
    console.log('========================================');

    const parts = result.sdJwt.split('~');

    console.log('Total ~ separated parts:', parts.length);
    console.log('Signed JWT:', parts[0]);
    console.log('Disclosure count:', parts.length - 1);

    console.log('\nIssuer test completed successfully.');
}

main().catch((error) => {
    console.error('\nIssuer test failed:');
    console.error(error);
    process.exit(1);
});

