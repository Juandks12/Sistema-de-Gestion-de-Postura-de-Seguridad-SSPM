import { ConfigService } from '@nestjs/config';
import { EmbeddingService, EMBEDDING_DIMENSION } from './embedding.service';

describe('EmbeddingService', () => {
  let service: EmbeddingService;
  let configService: jest.Mocked<ConfigService>;

  beforeEach(() => {
    configService = {
      get: jest.fn((key: string) => {
        if (key === 'OPENAI_API_KEY') return null;
        if (key === 'OPENAI_EMBEDDING_MODEL') return 'text-embedding-3-small';
        return null;
      }),
    } as unknown as jest.Mocked<ConfigService>;

    service = new EmbeddingService(configService);
  });

  it('debe inicializarse correctamente', () => {
    expect(service).toBeDefined();
  });

  it('debe generar un vector determinista de 1536 dimensiones normalizado a L2=1.0', async () => {
    const text = 'HSTS Strict-Transport-Security Nginx SSL bastionado';
    const embedding = await service.generateEmbedding(text);

    expect(embedding).toHaveLength(EMBEDDING_DIMENSION);

    // Comprobar norma L2 = 1.0 (dentro de tolerancia numérica)
    const normSq = embedding.reduce((sum, v) => sum + v * v, 0);
    const norm = Math.sqrt(normSq);
    expect(norm).toBeCloseTo(1.0, 3);
  });

  it('debe retornar vectores con alta similitud coseno para textos semánticamente relacionados', () => {
    const v1 = service.generateDeterministicSemanticVector('Strict-Transport-Security HSTS header');
    const v2 = service.generateDeterministicSemanticVector('Strict-Transport-Security HSTS preloading max-age');
    const v3 = service.generateDeterministicSemanticVector('PostgreSQL database query optimization index');

    // Dot product de vectores unitarios es la similitud coseno
    const dotProduct = (a: number[], b: number[]) => a.reduce((sum, val, i) => sum + val * b[i], 0);

    const simRelated = dotProduct(v1, v2);
    const simUnrelated = dotProduct(v1, v3);

    expect(simRelated).toBeGreaterThan(simUnrelated);
  });

  it('debe manejar cadenas vacías devolviendo un vector de ceros', async () => {
    const emptyVec = await service.generateEmbedding('');
    expect(emptyVec).toHaveLength(EMBEDDING_DIMENSION);
    expect(emptyVec.every((v) => v === 0)).toBe(true);
  });
});
