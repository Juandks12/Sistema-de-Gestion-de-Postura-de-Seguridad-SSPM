-- DropIndex
DROP INDEX "scans_status_idx";

-- AlterTable
ALTER TABLE "scans" ADD COLUMN     "parameters" JSONB,
ADD COLUMN     "target_address" VARCHAR(45);

-- CreateTable
CREATE TABLE "scan_ports" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "scan_id" UUID NOT NULL,
    "asset_id" UUID NOT NULL,
    "port" INTEGER NOT NULL,
    "protocol" VARCHAR(8) NOT NULL,
    "state" VARCHAR(20) NOT NULL,
    "reason" VARCHAR(40),
    "service_name" VARCHAR(100),
    "product" VARCHAR(200),
    "version" VARCHAR(100),
    "extra_info" VARCHAR(255),
    "tunnel" VARCHAR(20),
    "cpe" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "confidence" INTEGER,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_ports_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "scan_ports_organization_id_asset_id_state_idx" ON "scan_ports"("organization_id", "asset_id", "state");

-- CreateIndex
CREATE UNIQUE INDEX "scan_ports_scan_id_protocol_port_key" ON "scan_ports"("scan_id", "protocol", "port");

-- CreateIndex
CREATE INDEX "scans_status_created_at_idx" ON "scans"("status", "created_at");

-- AddForeignKey
ALTER TABLE "scan_ports" ADD CONSTRAINT "scan_ports_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_ports" ADD CONSTRAINT "scan_ports_scan_id_fkey" FOREIGN KEY ("scan_id") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_ports" ADD CONSTRAINT "scan_ports_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;
