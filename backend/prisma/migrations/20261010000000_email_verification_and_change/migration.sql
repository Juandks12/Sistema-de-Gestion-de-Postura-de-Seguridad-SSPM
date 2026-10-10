-- AlterEnum
ALTER TYPE "AccountTokenType" ADD VALUE 'EMAIL_VERIFICATION';
ALTER TYPE "AccountTokenType" ADD VALUE 'EMAIL_CHANGE';

-- AlterTable
ALTER TABLE "users" ADD COLUMN "email_verified_at" TIMESTAMPTZ(6);
ALTER TABLE "users" ADD COLUMN "pending_email" VARCHAR(254);
