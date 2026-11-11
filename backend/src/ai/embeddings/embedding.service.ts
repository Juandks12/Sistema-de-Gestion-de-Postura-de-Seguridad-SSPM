import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export const EMBEDDING_DIMENSION = 1536;

@Injectable()
export class EmbeddingService {
  private readonly logger = new Logger(EmbeddingService.name);
  private readonly openAiApiKey: string | null;
  private readonly openAiModel: string;

  constructor(private readonly config: ConfigService) {
    this.openAiApiKey = this.config.get<string>('OPENAI_API_KEY')?.trim() || null;
    this.openAiModel = this.config.get<string>('OPENAI_EMBEDDING_MODEL') || 'text-embedding-3-small';
  }

  /**
   * Genera un embedding vectorial de 1536 dimensiones para un texto dado.
   * Si hay clave de OpenAI disponible la usa; si no o ante fallo, usa el motor
   * semántico determinista normalizado a norma L2 = 1.0.
   */
  async generateEmbedding(text: string): Promise<number[]> {
    const cleanedText = (text || '').trim();
    if (!cleanedText) {
      return new Array(EMBEDDING_DIMENSION).fill(0);
    }

    if (this.openAiApiKey) {
      try {
        const response = await fetch('https://api.openai.com/v1/embeddings', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${this.openAiApiKey}`,
          },
          body: JSON.stringify({
            input: cleanedText.slice(0, 8000),
            model: this.openAiModel,
            dimensions: EMBEDDING_DIMENSION,
          }),
        });

        if (response.ok) {
          const data = (await response.json()) as { data?: Array<{ embedding: number[] }> };
          if (data.data?.[0]?.embedding) {
            return this.normalizeL2(data.data[0].embedding);
          }
        } else {
          this.logger.warn(`OpenAI Embeddings API retornó status ${response.status}. Usando fallback semántico.`);
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.warn(`Fallo al contactar OpenAI Embeddings API (${msg}). Usando fallback determinista.`);
      }
    }

    return this.generateDeterministicSemanticVector(cleanedText);
  }

  /**
   * Genera embeddings en lote para un conjunto de textos.
   */
  async generateBatchEmbeddings(texts: string[]): Promise<number[][]> {
    const results: number[][] = [];
    for (const text of texts) {
      results.push(await this.generateEmbedding(text));
    }
    return results;
  }

  /**
   * Normaliza un vector a norma Euclidiana (L2) unitaria (magnitud = 1.0).
   * Necesario para que la distancia coseno <=> en pgvector sea exactamente 1 - similitud coseno.
   */
  normalizeL2(vec: number[]): number[] {
    let sumSq = 0;
    for (let i = 0; i < vec.length; i++) {
      sumSq += vec[i] * vec[i];
    }
    const mag = Math.sqrt(sumSq);
    if (mag < 1e-12) {
      return vec.map(() => 0);
    }
    return vec.map((v) => Number((v / mag).toFixed(6)));
  }

  /**
   * Generador semántico determinista de 1536 dimensiones.
   * Utiliza hashing de características fonético-lexicales y n-gramas con ponderación TF
   * y proyección hash ortogonal dispersa, normalizado a longitud unitaria L2 = 1.0.
   */
  generateDeterministicSemanticVector(text: string): number[] {
    const vector = new Array<number>(EMBEDDING_DIMENSION).fill(0);
    const tokens = this.tokenize(text.toLowerCase());

    if (tokens.length === 0) {
      return vector;
    }

    // Ponderación de frecuencias de términos y bigramas
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      this.accumulateTokenHash(vector, token, 1.0);

      // Bigramas contiguos para preservar relación sintáctica/semántica
      if (i + 1 < tokens.length) {
        const bigram = `${token}_${tokens[i + 1]}`;
        this.accumulateTokenHash(vector, bigram, 0.7);
      }
    }

    return this.normalizeL2(vector);
  }

  private tokenize(text: string): string[] {
    // Separa palabras, identificadores de vulnerabilidad (CVE-202X-XXXX) y directivas técnicas
    return text
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .split(/[^a-z0-9_.-]+/)
      .filter((t) => t.length > 1);
  }

  private accumulateTokenHash(vector: number[], token: string, weight: number): void {
    let h1 = 0x811c9dc5;
    let h2 = 0x27d4eb2f;

    for (let i = 0; i < token.length; i++) {
      const code = token.charCodeAt(i);
      h1 ^= code;
      h1 = Math.imul(h1, 0x01000193);

      h2 ^= code;
      h2 = Math.imul(h2, 0x5bd1e995);
    }

    const idx1 = Math.abs(h1) % EMBEDDING_DIMENSION;
    const idx2 = Math.abs(h2) % EMBEDDING_DIMENSION;
    const sign1 = (h1 & 1) === 0 ? 1 : -1;
    const sign2 = (h2 & 1) === 0 ? 1 : -1;

    vector[idx1] += sign1 * weight;
    vector[idx2] += sign2 * (weight * 0.5);
  }
}
