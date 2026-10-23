-- CreateEnum
CREATE TYPE "DiagnosticBatchStatus" AS ENUM ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "DiagnosticProfile" AS ENUM ('COMMERCE_360', 'PERIMETER_FAST', 'FULL_AUDIT');

-- AlterTable
ALTER TABLE "scans" ADD COLUMN     "batch_id" UUID,
ADD COLUMN     "stage" INTEGER;

-- CreateTable
CREATE TABLE "diagnostic_batches" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "asset_id" UUID NOT NULL,
    "requested_by_id" UUID,
    "profile" "DiagnosticProfile" NOT NULL DEFAULT 'COMMERCE_360',
    "status" "DiagnosticBatchStatus" NOT NULL DEFAULT 'PENDING',
    "current_stage" INTEGER NOT NULL DEFAULT 1,
    "total_stages" INTEGER NOT NULL DEFAULT 3,
    "summary" JSONB,
    "started_at" TIMESTAMPTZ(6),
    "finished_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "diagnostic_batches_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "diagnostic_batches_organization_id_asset_id_idx" ON "diagnostic_batches"("organization_id", "asset_id");

-- CreateIndex
CREATE INDEX "diagnostic_batches_status_created_at_idx" ON "diagnostic_batches"("status", "created_at");

-- CreateIndex
CREATE INDEX "scans_batch_id_idx" ON "scans"("batch_id");

-- AddForeignKey
ALTER TABLE "scans" ADD CONSTRAINT "scans_batch_id_fkey" FOREIGN KEY ("batch_id") REFERENCES "diagnostic_batches"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "diagnostic_batches" ADD CONSTRAINT "diagnostic_batches_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "diagnostic_batches" ADD CONSTRAINT "diagnostic_batches_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "diagnostic_batches" ADD CONSTRAINT "diagnostic_batches_requested_by_id_fkey" FOREIGN KEY ("requested_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
