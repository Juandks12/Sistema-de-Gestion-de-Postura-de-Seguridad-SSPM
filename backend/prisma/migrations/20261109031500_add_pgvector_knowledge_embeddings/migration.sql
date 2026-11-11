-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Create enum KnowledgeCategory if not exists
DO $$ BEGIN
  CREATE TYPE "KnowledgeCategory" AS ENUM ('CVE', 'GRC_CONTROL', 'HARDENING_GUIDE', 'REMEDIATION_IAC');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

-- Create Table knowledge_embeddings
CREATE TABLE IF NOT EXISTS "knowledge_embeddings" (
  "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "category" "KnowledgeCategory" NOT NULL,
  "source_id" VARCHAR(120),
  "title" VARCHAR(500) NOT NULL,
  "content" TEXT NOT NULL,
  "metadata" JSONB,
  "embedding" vector(1536),
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT NOW(),
  "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT NOW()
);

-- BTree Indexes
CREATE INDEX IF NOT EXISTS "knowledge_embeddings_category_idx" ON "knowledge_embeddings"("category");
CREATE INDEX IF NOT EXISTS "knowledge_embeddings_source_id_idx" ON "knowledge_embeddings"("source_id");

-- HNSW Vector Cosine Distance Index
CREATE INDEX IF NOT EXISTS "idx_knowledge_embeddings_hnsw" ON "knowledge_embeddings" USING hnsw ("embedding" vector_cosine_ops);
