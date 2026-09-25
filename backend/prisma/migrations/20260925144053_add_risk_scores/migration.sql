-- CreateEnum
CREATE TYPE "RiskScoreScope" AS ENUM ('ORGANIZATION', 'ASSET');

-- CreateEnum
CREATE TYPE "RiskScoreTrigger" AS ENUM ('SCAN_COMPLETED', 'FINDING_REVIEWED', 'ASSET_CHANGED', 'MANUAL');

-- CreateTable
CREATE TABLE "risk_scores" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "scope" "RiskScoreScope" NOT NULL,
    "asset_id" UUID,
    "score" INTEGER,
    "grade" VARCHAR(1),
    "critical_count" INTEGER NOT NULL DEFAULT 0,
    "high_count" INTEGER NOT NULL DEFAULT 0,
    "medium_count" INTEGER NOT NULL DEFAULT 0,
    "low_count" INTEGER NOT NULL DEFAULT 0,
    "info_count" INTEGER NOT NULL DEFAULT 0,
    "scored_assets" INTEGER NOT NULL DEFAULT 0,
    "breakdown" JSONB,
    "trigger" "RiskScoreTrigger" NOT NULL,
    "scan_id" UUID,
    "computed_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "risk_scores_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "risk_scores_organization_id_scope_computed_at_idx" ON "risk_scores"("organization_id", "scope", "computed_at");

-- CreateIndex
CREATE INDEX "risk_scores_asset_id_computed_at_idx" ON "risk_scores"("asset_id", "computed_at");

-- AddForeignKey
ALTER TABLE "risk_scores" ADD CONSTRAINT "risk_scores_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_scores" ADD CONSTRAINT "risk_scores_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;
