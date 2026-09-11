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

// export const sdJwtVerifySchema = z
//   .object({
//     sdJwt: z
//       .string()
//       .min(1, "sdJwt is required")
//       .max(256 * 1024, "sdJwt must not exceed 256 KB"),
//   })
//   .strict();

export const sdJwtVerifySchema = z
  .object({
    sdJwt: z
      .string()
      .min(1, 'sdJwt is required')
      .max(
        256 * 1024,
        'sdJwt must not exceed 256 KB',
      ),

    kbJwt: z
      .string()
      .min(1, 'kbJwt is required')
      .max(
        16 * 1024,
        'kbJwt must not exceed 16 KB',
      ),

    audience: z
      .string()
      .min(1, 'audience is required')
      .max(
        256,
        'audience must not exceed 256 characters',
      ),

    nonce: z
      .string()
      .min(1, 'nonce is required')
      .max(
        256,
        'nonce must not exceed 256 characters',
      ),
  })
  .strict();


export const sdJwtShareSchema = z
  .object({
    credentialId: z
      .string()
      .min(1, 'credentialId is required')
      .max(256, 'credentialId must not exceed 256 characters'),

    holderJwk: holderJwkSchema,

    claims: z
      .record(claimKey, jsonValue)
      .refine(
        (claims) => Object.keys(claims).length > 0,
        {
          message:
            'At least one claim must be selected for sharing',
        },
      )
      .refine(
        (claims) => Object.keys(claims).length <= 100,
        {
          message:
            'At most 100 claims can be selected for sharing',
        },
      )
      .refine(
        (claims) =>
          Buffer.byteLength(
            JSON.stringify(claims),
            'utf8',
          ) <= 64 * 1024,
        {
          message:
            'Selected claims must not exceed 64 KB',
        },
      ),
  })
  .strict();