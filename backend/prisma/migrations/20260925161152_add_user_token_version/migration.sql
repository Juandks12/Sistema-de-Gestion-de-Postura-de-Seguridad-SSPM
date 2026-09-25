-- AlterTable
ALTER TABLE "users" ADD COLUMN     "password_changed_at" TIMESTAMPTZ(6),
ADD COLUMN     "token_version" INTEGER NOT NULL DEFAULT 0;
