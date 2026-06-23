import { encryptJson, decryptJson, getPiiKey } from "./piiEncryption";
import { config } from "../config/env";
import { logger } from "../config/logger";

function getKey(): Buffer | null {
  const hex = config.piiEncryptionKey;
  if (!hex) return null;
  try {
    return getPiiKey(hex);
  } catch {
    return null;
  }
}

export function encryptKycPayload(payload: unknown): string | null {
  if (payload == null) return null;
  const key = getKey();
  if (!key) {
    logger.warn("PII_ENCRYPTION_KEY not configured — skipping KYC payload encryption");
    return JSON.stringify(payload);
  }
  return encryptJson(payload, key);
}

export function decryptKycPayload(encrypted: string | null): unknown {
  if (encrypted == null) return null;
  if (!encrypted.startsWith("v1:")) {
    try {
      return JSON.parse(encrypted);
    } catch {
      return encrypted;
    }
  }
  const key = getKey();
  if (!key) {
    logger.warn("PII_ENCRYPTION_KEY not configured — cannot decrypt KYC payload");
    return null;
  }
  return decryptJson(encrypted, key);
}
