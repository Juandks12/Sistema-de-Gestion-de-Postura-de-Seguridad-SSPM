-- CreateEnum
CREATE TYPE "CloudProvider" AS ENUM ('AWS', 'AZURE');

-- CreateEnum
CREATE TYPE "CloudAuthType" AS ENUM ('ROLE_ARN', 'ACCESS_KEYS', 'SERVICE_PRINCIPAL');

-- CreateEnum
CREATE TYPE "CloudAccountStatus" AS ENUM ('PENDING', 'CONNECTED', 'ERROR', 'DISCONNECTED');

-- CreateEnum
CREATE TYPE "CloudResourceType" AS ENUM ('AWS_S3_BUCKET', 'AWS_IAM_USER', 'AWS_IAM_ROLE', 'AWS_SECURITY_GROUP', 'AWS_EC2_INSTANCE', 'AWS_RDS_INSTANCE', 'AWS_CLOUDTRAIL', 'AWS_VPC', 'AZURE_STORAGE_ACCOUNT', 'AZURE_BLOB_CONTAINER', 'AZURE_NSG', 'AZURE_VM', 'AZURE_SQL_DATABASE', 'AZURE_ACTIVITY_LOG', 'AZURE_VNET', 'OTHER');

-- AlterEnum
ALTER TYPE "AssetType" ADD VALUE 'CLOUD_ACCOUNT';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "FindingCategory" ADD VALUE 'CLOUD_IAM';
ALTER TYPE "FindingCategory" ADD VALUE 'CLOUD_STORAGE';
ALTER TYPE "FindingCategory" ADD VALUE 'CLOUD_NETWORK';
ALTER TYPE "FindingCategory" ADD VALUE 'CLOUD_COMPUTE';
ALTER TYPE "FindingCategory" ADD VALUE 'CLOUD_DATABASE';
ALTER TYPE "FindingCategory" ADD VALUE 'CLOUD_LOGGING';

-- AlterTable
ALTER TABLE "findings" ADD COLUMN     "cloud_account_id" UUID,
ADD COLUMN     "cloud_resource_id" UUID;

-- CreateTable
CREATE TABLE "cloud_accounts" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "provider" "CloudProvider" NOT NULL,
    "name" VARCHAR(150) NOT NULL,
    "auth_type" "CloudAuthType" NOT NULL,
    "status" "CloudAccountStatus" NOT NULL DEFAULT 'PENDING',
    "account_or_subscription_id" VARCHAR(100) NOT NULL,
    "azure_tenant_id" VARCHAR(100),
    "aws_role_arn" VARCHAR(255),
    "aws_external_id" VARCHAR(100),
    "encrypted_credentials" TEXT,
    "monitored_regions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "asset_id" UUID,
    "last_audited_at" TIMESTAMPTZ(6),
    "last_audit_error" VARCHAR(500),
    "resource_count" INTEGER NOT NULL DEFAULT 0,
    "failing_finding_count" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "cloud_accounts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cloud_resources" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "cloud_account_id" UUID NOT NULL,
    "provider" "CloudProvider" NOT NULL,
    "resource_type" "CloudResourceType" NOT NULL,
    "native_id" VARCHAR(500) NOT NULL,
    "name" VARCHAR(255) NOT NULL,
    "region" VARCHAR(50),
    "configuration" JSONB,
    "tags" JSONB,
    "has_active_findings" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "cloud_resources_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "cloud_accounts_asset_id_key" ON "cloud_accounts"("asset_id");

-- CreateIndex
CREATE INDEX "cloud_accounts_organization_id_status_idx" ON "cloud_accounts"("organization_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "cloud_accounts_organization_id_provider_account_or_subscrip_key" ON "cloud_accounts"("organization_id", "provider", "account_or_subscription_id");

-- CreateIndex
CREATE INDEX "cloud_resources_organization_id_provider_resource_type_idx" ON "cloud_resources"("organization_id", "provider", "resource_type");

-- CreateIndex
CREATE UNIQUE INDEX "cloud_resources_cloud_account_id_native_id_key" ON "cloud_resources"("cloud_account_id", "native_id");

-- CreateIndex
CREATE INDEX "findings_organization_id_cloud_account_id_idx" ON "findings"("organization_id", "cloud_account_id");

-- CreateIndex
CREATE INDEX "findings_organization_id_cloud_resource_id_idx" ON "findings"("organization_id", "cloud_resource_id");

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_cloud_account_id_fkey" FOREIGN KEY ("cloud_account_id") REFERENCES "cloud_accounts"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_cloud_resource_id_fkey" FOREIGN KEY ("cloud_resource_id") REFERENCES "cloud_resources"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cloud_accounts" ADD CONSTRAINT "cloud_accounts_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cloud_accounts" ADD CONSTRAINT "cloud_accounts_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cloud_resources" ADD CONSTRAINT "cloud_resources_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cloud_resources" ADD CONSTRAINT "cloud_resources_cloud_account_id_fkey" FOREIGN KEY ("cloud_account_id") REFERENCES "cloud_accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
