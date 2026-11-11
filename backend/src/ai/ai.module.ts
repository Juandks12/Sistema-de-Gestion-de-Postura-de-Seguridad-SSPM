import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { EmbeddingService } from './embeddings/embedding.service';
import { KnowledgeIngestionService } from './rag/knowledge-ingestion.service';
import { RagRetrievalService } from './rag/rag-retrieval.service';
import { RagController } from './rag/rag.controller';

@Module({
  imports: [PrismaModule],
  controllers: [RagController],
  providers: [EmbeddingService, KnowledgeIngestionService, RagRetrievalService],
  exports: [EmbeddingService, KnowledgeIngestionService, RagRetrievalService],
})
export class AiModule {}
