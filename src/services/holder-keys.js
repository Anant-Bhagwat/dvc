import crypto from "node:crypto";


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
