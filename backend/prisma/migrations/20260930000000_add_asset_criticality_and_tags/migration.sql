-- CreateEnum
CREATE TYPE "AssetCriticality" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW');

-- AlterTable
ALTER TABLE "assets" ADD COLUMN "criticality" "AssetCriticality" NOT NULL DEFAULT 'MEDIUM',
ADD COLUMN "tags" TEXT[] DEFAULT ARRAY[]::TEXT[];
