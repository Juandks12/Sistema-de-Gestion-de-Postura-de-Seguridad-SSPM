-- CreateTable llm_execution_logs
CREATE TABLE IF NOT EXISTS "llm_execution_logs" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "agent_or_service" VARCHAR(100) NOT NULL,
    "model" VARCHAR(100) NOT NULL,
    "prompt_tokens" INTEGER NOT NULL DEFAULT 0,
    "completion_tokens" INTEGER NOT NULL DEFAULT 0,
    "total_tokens" INTEGER NOT NULL DEFAULT 0,
    "estimated_cost_usd" DECIMAL(10,6) NOT NULL DEFAULT 0,
    "latency_ms" INTEGER NOT NULL DEFAULT 0,
    "ttft_ms" INTEGER,
    "status" VARCHAR(30) NOT NULL DEFAULT 'SUCCESS',
    "prompt_injection_detected" BOOLEAN NOT NULL DEFAULT false,
    "prompt_injection_score" INTEGER,
    "detected_patterns" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "fallback_reason" VARCHAR(500),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "llm_execution_logs_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "llm_execution_logs_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateIndex
CREATE INDEX IF NOT EXISTS "llm_execution_logs_organization_id_created_at_idx" ON "llm_execution_logs"("organization_id", "created_at");
CREATE INDEX IF NOT EXISTS "llm_execution_logs_organization_id_agent_or_service_idx" ON "llm_execution_logs"("organization_id", "agent_or_service");
CREATE INDEX IF NOT EXISTS "llm_execution_logs_prompt_injection_detected_idx" ON "llm_execution_logs"("prompt_injection_detected");
