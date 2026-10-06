-- AlterEnum
ALTER TYPE "FindingStatus" ADD VALUE 'IN_PROGRESS';
ALTER TYPE "FindingStatus" ADD VALUE 'VERIFYING';

-- AlterTable
ALTER TABLE "findings" ADD COLUMN "assigned_to_id" UUID,
ADD COLUMN "due_date" TIMESTAMPTZ(6),
ADD COLUMN "remediation_note" TEXT;

-- CreateIndex
CREATE INDEX "findings_organization_id_assigned_to_id_idx" ON "findings"("organization_id", "assigned_to_id");

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_assigned_to_id_fkey" FOREIGN KEY ("assigned_to_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
