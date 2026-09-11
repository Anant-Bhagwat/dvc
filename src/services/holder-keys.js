import crypto from "node:crypto";

/**
 * Generate an EC P-256 key pair for the credential holder.
 *
 * Private key:
 * - Stays with the holder
 * - Will later be used to sign the KB-JWT
 * - Must NOT be sent to the issuer API
 *
 * Public key:
 * - Can be shared with the issuer
 * - Will later be converted to JWK
 * - Will be stored in the credential as cnf.jwk
 */
export function generateHolderKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });

  return Object.freeze({
    publicKey,
    privateKey,
  });
}

export function exportHolderPublicJwk(publicKey) {
  if (!publicKey) {
    throw new TypeError("Holder public key is required");
  }
  const jwk = publicKey.export({ format: "jwk" });
  return Object.freeze({ ...jwk, alg: "ES256" });
}
