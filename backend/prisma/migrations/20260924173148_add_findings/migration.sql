-- CreateEnum
CREATE TYPE "FindingSeverity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');

-- CreateEnum
CREATE TYPE "FindingCategory" AS ENUM ('EXPOSED_SERVICE', 'HTTP_HEADERS', 'TLS_CERTIFICATE', 'SENSITIVE_PATH');

-- CreateEnum
CREATE TYPE "FindingStatus" AS ENUM ('OPEN', 'RESOLVED', 'ACCEPTED', 'FALSE_POSITIVE');

-- CreateTable
CREATE TABLE "findings" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "asset_id" UUID NOT NULL,
    "last_scan_id" UUID,
    "category" "FindingCategory" NOT NULL,
    "rule_id" VARCHAR(60) NOT NULL,
    "severity" "FindingSeverity" NOT NULL,
    "cvss_score" DECIMAL(3,1),
    "status" "FindingStatus" NOT NULL DEFAULT 'OPEN',
    "title" VARCHAR(200) NOT NULL,
    "description" TEXT NOT NULL,
    "recommendation" TEXT NOT NULL,
    "location" VARCHAR(500) NOT NULL,
    "evidence" JSONB,
    "fingerprint" VARCHAR(64) NOT NULL,
    "first_seen_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolved_at" TIMESTAMPTZ(6),
    "reviewed_by_id" UUID,
    "review_note" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "findings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "findings_organization_id_status_severity_idx" ON "findings"("organization_id", "status", "severity");

-- CreateIndex
CREATE INDEX "findings_organization_id_asset_id_category_idx" ON "findings"("organization_id", "asset_id", "category");

-- CreateIndex
CREATE UNIQUE INDEX "findings_asset_id_fingerprint_key" ON "findings"("asset_id", "fingerprint");

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_last_scan_id_fkey" FOREIGN KEY ("last_scan_id") REFERENCES "scans"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_reviewed_by_id_fkey" FOREIGN KEY ("reviewed_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
