import { z } from "zod";

const claimKey = z
  .string()
  .min(1)
  .max(128)
  .regex(
    /^[A-Za-z][A-Za-z0-9_.-]*$/,
    "Claim name must contain only letters, numbers, dots, hyphens, or underscores",
  );

const jsonValue = z.union([
  z.string(),
  z.number().finite(),
  z.boolean(),
  z.null(),
  z.lazy(() => z.array(jsonValue)),
  z.lazy(() => z.record(z.string(), jsonValue)),
]);

const holderJwkSchema = z
  .object({
    kty: z.string().min(1),
    alg: z.string().optional(),
    kid: z.string().optional(),

    crv: z.string().optional(),
    x: z.string().optional(),
    y: z.string().optional(),

    e: z.string().optional(),
    n: z.string().optional(),
  })
  .strict()
  .refine(
    (jwk) => {
      if (jwk.kty === "EC") {
        return Boolean(jwk.crv && jwk.x && jwk.y);
      }

      if (jwk.kty === "RSA") {
        return Boolean(jwk.n && jwk.e);
      }

      return false;
    },
    {
      message: "Holder JWK must be a valid EC or RSA public key representation",
    },
  );

export const sdJwtCreateSchema = z
  .object({
    credentialId: z.string().min(1).max(256),

    expiresIn: z.coerce
      .number()
      .int()
      .min(60, "expiresIn must be at least 60 seconds")
      .max(365 * 24 * 60 * 60, "expiresIn must not exceed one year")
      .optional(),

    holderJwk: holderJwkSchema,

    claims: z
      .record(claimKey, jsonValue)
      .refine((claims) => Object.keys(claims).length > 0, {
        message: "At least one selectively disclosable claim is required",
      })
      .refine((claims) => Object.keys(claims).length <= 100, {
        message: "At most 100 selectively disclosable claims are allowed",
      })
      .refine(
        (claims) =>
          Buffer.byteLength(JSON.stringify(claims), "utf8") <= 64 * 1024,
        {
          message: "Serialized claims must not exceed 64 KB",
        },
      ),
  })
  .strict();

export const sdJwtVerifySchema = z
  .object({
    sdJwt: z
      .string()
      .min(1, "sdJwt is required")
      .max(256 * 1024, "sdJwt must not exceed 256 KB"),
  })
  .strict();
