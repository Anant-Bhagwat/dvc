import express, { Router } from "express";

import { env } from "../config/jwtkeys.config.js";

import {
  sdJwtCreateSchema,
  sdJwtVerifySchema,
} from "../validations/sdjwt.validation.js";

import { createSdJwt } from "../services/sdjwt-issuer.js";
import { verifySdJwt } from "../services/sdjwt-verifier.js";

const router = Router();

router.use(
  express.json({
    limit: env.JSON_BODY_LIMIT,
    strict: true,
    type: "application/json",
  }),
);

router.post("/issue", async (req, res, next) => {
  try {
    const parsed = sdJwtCreateSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Validation failed",
        details: parsed.error.flatten(),
      });
    }

    const result = await createSdJwt(parsed.data);

    return res.status(201).json({
      sdJwt: result.sdJwt,
      signedJwt: result.signedJwt,
    //   disclosures: result.disclosures.map((disclosure) => ({
    //     name: disclosure.name,
    //     value: disclosure.value,
    //     encoded: disclosure.encoded,
    //     digest: disclosure.digest,
    //   })),
    });
  } catch (error) {
    next(error);
  }
});

router.post("/verify", async (req, res, next) => {
  try {
    const parsed = sdJwtVerifySchema.safeParse(req.body);
    if (!parsed.success) {
      return res
        .status(400)
        .json({ error: "Validation failed", details: parsed.error.flatten() });
    }
    const result = await verifySdJwt(parsed.data.sdJwt);
    return res
      .status(200)
      .json({
        valid: result.valid,
        protectedHeader: result.protectedHeader,
        payload: result.payload,
        // disclosedClaims: result.disclosedClaims,
        // disclosureCount: result.disclosures.length,
      });
  } catch (error) {
    next(error);
  }
});

export default router;
