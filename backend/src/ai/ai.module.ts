import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { EmbeddingService } from './embeddings/embedding.service';
import { KnowledgeIngestionService } from './rag/knowledge-ingestion.service';
import { RagRetrievalService } from './rag/rag-retrieval.service';
import { RagController } from './rag/rag.controller';
import { PromptInjectionShieldService } from './guardrails/prompt-injection-shield.service';
import { OutputGuardrailService } from './guardrails/output-guardrail.service';
import { LlmObservabilityService } from './observability/llm-observability.service';
import { LlmObservabilityController } from './observability/llm-observability.controller';

@Module({
  imports: [PrismaModule],
  controllers: [RagController, LlmObservabilityController],
  providers: [
    EmbeddingService,
    KnowledgeIngestionService,
    RagRetrievalService,
    PromptInjectionShieldService,
    OutputGuardrailService,
    LlmObservabilityService,
  ],
  exports: [
    EmbeddingService,
    KnowledgeIngestionService,
    RagRetrievalService,
    PromptInjectionShieldService,
    OutputGuardrailService,
    LlmObservabilityService,
  ],
})
export class AiModule {}
