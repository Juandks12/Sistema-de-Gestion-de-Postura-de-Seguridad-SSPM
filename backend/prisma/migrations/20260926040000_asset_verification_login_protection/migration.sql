-- CreateEnum
CREATE TYPE "VerificationMethod" AS ENUM ('DNS_TXT', 'HTTP_FILE', 'INHERITED', 'PRE_AUTHORIZED');

-- AlterTable: prueba de propiedad por activo. Los activos existentes quedan
-- sin verificar: no se podrán escanear hasta que la organización lo demuestre.
ALTER TABLE "assets" ADD COLUMN     "verification_checked_at" TIMESTAMPTZ(6),
ADD COLUMN     "verification_error" VARCHAR(500),
ADD COLUMN     "verification_method" "VerificationMethod",
ADD COLUMN     "verification_scope" VARCHAR(253),
ADD COLUMN     "verified_at" TIMESTAMPTZ(6);

-- AlterTable: token de verificación por organización. Se rellena para las
-- organizaciones existentes con 128 bits aleatorios (gen_random_uuid, PostgreSQL 13+).
ALTER TABLE "organizations" ADD COLUMN     "verification_token" VARCHAR(64);
UPDATE "organizations" SET "verification_token" = replace(gen_random_uuid()::text, '-', '') WHERE "verification_token" IS NULL;
ALTER TABLE "organizations" ALTER COLUMN "verification_token" SET NOT NULL;

-- CreateTable
CREATE TABLE "login_attempts" (
    "key" VARCHAR(64) NOT NULL,
    "failures" INTEGER NOT NULL DEFAULT 0,
    "locked_until" TIMESTAMPTZ(6),
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "login_attempts_pkey" PRIMARY KEY ("key")
);

-- CreateIndex
CREATE UNIQUE INDEX "organizations_verification_token_key" ON "organizations"("verification_token");
