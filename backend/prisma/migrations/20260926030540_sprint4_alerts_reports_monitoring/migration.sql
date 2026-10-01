-- CreateEnum
CREATE TYPE "ScanSource" AS ENUM ('MANUAL', 'SCHEDULED');

-- CreateEnum
CREATE TYPE "MonitoringFrequency" AS ENUM ('OFF', 'DAILY', 'WEEKLY');

-- CreateEnum
CREATE TYPE "AlertType" AS ENUM ('NEW_OPEN_PORT', 'CERT_EXPIRING', 'CRITICAL_FINDING');

-- CreateEnum
CREATE TYPE "AlertChannelType" AS ENUM ('EMAIL', 'WEBHOOK');

-- CreateEnum
CREATE TYPE "ReportType" AS ENUM ('EXECUTIVE', 'TECHNICAL');

-- AlterTable
ALTER TABLE "assets" ADD COLUMN     "last_scheduled_scan_at" TIMESTAMPTZ(6);

-- AlterTable
ALTER TABLE "organizations" ADD COLUMN     "monitoring_frequency" "MonitoringFrequency" NOT NULL DEFAULT 'OFF';

-- AlterTable
ALTER TABLE "scans" ADD COLUMN     "source" "ScanSource" NOT NULL DEFAULT 'MANUAL';

-- CreateTable
CREATE TABLE "alerts" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "asset_id" UUID,
    "scan_id" UUID,
    "type" "AlertType" NOT NULL,
    "severity" "FindingSeverity" NOT NULL,
    "title" VARCHAR(200) NOT NULL,
    "message" TEXT NOT NULL,
    "data" JSONB,
    "deliveries" JSONB,
    "acknowledged_at" TIMESTAMPTZ(6),
    "acknowledged_by_id" UUID,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "alerts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "alert_channels" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "type" "AlertChannelType" NOT NULL,
    "name" VARCHAR(100) NOT NULL,
    "target" VARCHAR(1000) NOT NULL,
    "min_severity" "FindingSeverity" NOT NULL DEFAULT 'HIGH',
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_by_id" UUID,
    "last_delivery_at" TIMESTAMPTZ(6),
    "last_delivery_status" VARCHAR(10),
    "last_delivery_error" VARCHAR(500),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "alert_channels_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "reports" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "asset_id" UUID,
    "type" "ReportType" NOT NULL,
    "generated_by_id" UUID,
    "score" INTEGER,
    "grade" VARCHAR(1),
    "open_findings" INTEGER NOT NULL DEFAULT 0,
    "pages" INTEGER NOT NULL DEFAULT 0,
    "size_bytes" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "reports_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "alerts_organization_id_created_at_idx" ON "alerts"("organization_id", "created_at");

-- CreateIndex
CREATE INDEX "alerts_organization_id_acknowledged_at_idx" ON "alerts"("organization_id", "acknowledged_at");

-- CreateIndex
CREATE INDEX "alert_channels_organization_id_idx" ON "alert_channels"("organization_id");

-- CreateIndex
CREATE INDEX "reports_organization_id_created_at_idx" ON "reports"("organization_id", "created_at");

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_scan_id_fkey" FOREIGN KEY ("scan_id") REFERENCES "scans"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_acknowledged_by_id_fkey" FOREIGN KEY ("acknowledged_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alert_channels" ADD CONSTRAINT "alert_channels_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alert_channels" ADD CONSTRAINT "alert_channels_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reports" ADD CONSTRAINT "reports_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reports" ADD CONSTRAINT "reports_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reports" ADD CONSTRAINT "reports_generated_by_id_fkey" FOREIGN KEY ("generated_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
