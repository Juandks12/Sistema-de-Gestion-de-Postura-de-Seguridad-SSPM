-- CreateEnum
CREATE TYPE "AccountTokenType" AS ENUM ('PASSWORD_RESET', 'INVITATION');

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "mfa_enabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "mfa_enabled_at" TIMESTAMP(3),
ADD COLUMN     "mfa_pending_secret" VARCHAR(64),
ADD COLUMN     "mfa_recovery_codes" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "mfa_secret" VARCHAR(64);

-- CreateTable
CREATE TABLE "account_tokens" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "type" "AccountTokenType" NOT NULL,
    "token_hash" VARCHAR(64) NOT NULL,
    "email" VARCHAR(254) NOT NULL,
    "user_id" UUID,
    "role" "UserRole",
    "created_by_id" UUID,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "used_at" TIMESTAMPTZ(6),
    "delivery_status" VARCHAR(10),
    "delivery_error" VARCHAR(500),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "account_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_log" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "action" VARCHAR(60) NOT NULL,
    "actor_id" UUID,
    "actor_email" VARCHAR(254),
    "actor_name" VARCHAR(150),
    "target_type" VARCHAR(30),
    "target_id" VARCHAR(64),
    "target_label" VARCHAR(253),
    "detail" JSONB,
    "ip" VARCHAR(45),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_log_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "account_tokens_token_hash_key" ON "account_tokens"("token_hash");

-- CreateIndex
CREATE INDEX "account_tokens_organization_id_type_created_at_idx" ON "account_tokens"("organization_id", "type", "created_at");

-- CreateIndex
CREATE INDEX "account_tokens_email_type_idx" ON "account_tokens"("email", "type");

-- CreateIndex
CREATE INDEX "audit_log_organization_id_created_at_idx" ON "audit_log"("organization_id", "created_at");

-- CreateIndex
CREATE INDEX "audit_log_organization_id_action_created_at_idx" ON "audit_log"("organization_id", "action", "created_at");

-- AddForeignKey
ALTER TABLE "account_tokens" ADD CONSTRAINT "account_tokens_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account_tokens" ADD CONSTRAINT "account_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account_tokens" ADD CONSTRAINT "account_tokens_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

