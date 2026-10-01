-- AlterEnum
ALTER TYPE "AlertType" ADD VALUE 'NEW_SUBDOMAIN';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "FindingCategory" ADD VALUE 'VULNERABLE_SOFTWARE';
ALTER TYPE "FindingCategory" ADD VALUE 'EMAIL_SECURITY';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ScanType" ADD VALUE 'EMAIL_SECURITY';
ALTER TYPE "ScanType" ADD VALUE 'SUBDOMAIN_DISCOVERY';

-- CreateTable
CREATE TABLE "discovered_hosts" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "asset_id" UUID NOT NULL,
    "hostname" VARCHAR(253) NOT NULL,
    "source" VARCHAR(20) NOT NULL DEFAULT 'ct',
    "resolves" BOOLEAN NOT NULL DEFAULT false,
    "addresses" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "wildcard" BOOLEAN NOT NULL DEFAULT false,
    "last_certificate_at" TIMESTAMPTZ(6),
    "ignored_at" TIMESTAMPTZ(6),
    "last_scan_id" UUID,
    "first_seen_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "discovered_hosts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cve_product_cache" (
    "product" VARCHAR(200) NOT NULL,
    "total_results" INTEGER NOT NULL DEFAULT 0,
    "entries" JSONB NOT NULL,
    "fetched_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "cve_product_cache_pkey" PRIMARY KEY ("product")
);

-- CreateIndex
CREATE INDEX "discovered_hosts_asset_id_idx" ON "discovered_hosts"("asset_id");

-- CreateIndex
CREATE UNIQUE INDEX "discovered_hosts_organization_id_hostname_key" ON "discovered_hosts"("organization_id", "hostname");

-- AddForeignKey
ALTER TABLE "discovered_hosts" ADD CONSTRAINT "discovered_hosts_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "discovered_hosts" ADD CONSTRAINT "discovered_hosts_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "discovered_hosts" ADD CONSTRAINT "discovered_hosts_last_scan_id_fkey" FOREIGN KEY ("last_scan_id") REFERENCES "scans"("id") ON DELETE SET NULL ON UPDATE CASCADE;

