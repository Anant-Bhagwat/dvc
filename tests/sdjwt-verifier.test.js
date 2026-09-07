
import { verifySdJwt } from '../src/services/sdjwt-verifier.js';
import {
    initKeys,
} from '../src/config/jwtkeys.config.js';

const sdJwt = `eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCIsImtpZCI6Imp3dC1zaWduaW5nLWtleS0wMSJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjEiXSwiaXNzIjoiaHR0cHM6Ly9hZ3Jpc3RhY2suZXhhbXBsZS5nb3YuaW4iLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwieCI6ImQtclFEX3E4bHJRSXVvTGMwOWt5LTh3SUZTR1NzcFg3R1ptRDNJY0JqSDAiLCJ5IjoiMVlRV1I1dGVwVUpHSE92RFYzQjY3SjctcGVCN2R2dThDU3dlenlTM1hqRSIsImNydiI6IlAtMjU2IiwiYWxnIjoiRVMyNTYifX0sImlkIjoiRlJNLUNSRUQtMDAwMSIsImlhdCI6MTc4ODc2OTA1MSwiZXhwIjoxNzg4ODU1NDUxLCJzdGF0dXMiOiJodHRwczovL2FncmlzdGFjay5leGFtcGxlLmdvdi5pbi9jcmVkZW50aWFscy9zdGF0dXMvRlJNLUNSRUQtMDAwMSIsIl9zZF9hbGciOiJzaGEtMjU2IiwiX3NkIjpbIkZod0d6NnRTSDg0ZV84emNnV0NLVkZoa05JN1VUaFI0S1VycXE0czJwRFEiLCJ2bDRyc05mVkYzU291aFNIZ2dyQUQzcnpjck1aRmdYNXZNb0NFSnhuenlrIiwia2ViTktQTEpzd0Y1UHdFM3gtTC10b3NwZ0ZzanBtZ05FTWlMZkpQVnl4MCJdfQ.ycoNa-ymXYSjstXKNlpkS9hM2l8DRPxZs1BYhpJSyFEbqtziaVR51dkkMG3K8Pq7aYa3AALxy8eLNZru3f60AA~WyI3MDM5MmQwOC05Mjk5LTQ0NzktOGE3Yi1lZmM0NzFhOTZkOWUiLCJmYXJtZXJJZCIsIkZSTTAwMDEiXQ~WyI4YzI3NTE2MS03MmU3LTRjNTktYmZhZi1kY2E1NDQxNGJjNzUiLCJmYXJtZXJOYW1lIiwiUmFqZXNoIEt1bWFyIl0~WyJkMWI3NDI5ZS03YWZlLTRiZDAtYjFlNy1mOTM1Mzg0NGMyMTUiLCJmYXRoZXJOYW1lIiwiTWFoZXNoIEt1bWFyIl0`;

console.log('\n========================================');
console.log('SD-JWT VERIFIER TEST');
console.log('========================================');

async function main() {
    try {
         await initKeys();
        const result = await verifySdJwt(sdJwt);

        console.log('');
        console.log('VERIFICATION RESULT');
        console.log('----------------------------------------');

        console.log(
            'Valid:',
            result.valid,
        );

        console.log('');
        console.log('Protected Header:');
        console.log(
            JSON.stringify(
                result.protectedHeader,
                null,
                2,
            ),
        );

        console.log('');
        console.log('Disclosed Claims:');
        console.log(
            JSON.stringify(
                result.disclosedClaims,
                null,
                2,
            ),
        );

        console.log('');
        console.log('Disclosure Count:');
        console.log(
            result.disclosures.length,
        );

        console.log('');
        console.log('========================================');
        console.log('FINAL RESULT');
        console.log('========================================');

        if (result.valid) {
            console.log(
                'PASS - SD-JWT signature verified',
            );

            console.log(
                'PASS - Issuer verified',
            );

            console.log(
                'PASS - Disclosure digests verified',
            );

            console.log(
                'PASS - SD-JWT verification successful',
            );
        }
    } catch (error) {
        console.log('');
        console.log('========================================');
        console.log('VERIFICATION FAILED');
        console.log('========================================');

        console.error(
            error.message,
        );

        process.exitCode = 1;
    }
}

main();

