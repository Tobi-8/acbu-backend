-- AlterTable: change machine_redacted_payload and machine_extracted_payload from jsonb to text
-- to support AES-256-GCM encrypted payloads instead of plaintext JSON.

ALTER TABLE "kyc_applications" ALTER COLUMN "machine_redacted_payload" TYPE TEXT USING "machine_redacted_payload"::text;
ALTER TABLE "kyc_applications" ALTER COLUMN "machine_extracted_payload" TYPE TEXT USING "machine_extracted_payload"::text;
