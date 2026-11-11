import { Injectable, Logger } from '@nestjs/common';
import { MalwareVerdict } from '@prisma/client';

export interface ForensicIndicator {
  type: string;
  value: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
}

export interface OutputEnforcementResult {
  finalVerdict: MalwareVerdict;
  wasOverriddenByGuardrail: boolean;
  guardrailReason?: string;
  violations: string[];
}

@Injectable()
export class OutputGuardrailService {
  private readonly logger = new Logger(OutputGuardrailService.name);

  /**
   * Asegura la inviolabilidad del veredicto forense.
   * Si existen indicadores estáticos o de Threat Intel maliciosos,
   * un LLM probabilístico jamás podrá rebajar el veredicto a CLEAN.
   */
  enforceForensicVerdict(
    staticVerdict: MalwareVerdict,
    llmSuggestedVerdict: MalwareVerdict | string,
    indicators: ForensicIndicator[] = [],
  ): OutputEnforcementResult {
    const violations: string[] = [];
    const normalizedLlmVerdict = (String(llmSuggestedVerdict || '')).toUpperCase() as MalwareVerdict;

    const hasCriticalIndicators = indicators.some(
      (ind) => ind.severity === 'CRITICAL' || ind.severity === 'HIGH',
    );

    // Regla de Oro 1: Si el motor estático determinó MALICIOUS o hay indicadores críticos,
    // el veredicto final es irrevocablemente MALICIOUS.
    if ((staticVerdict === MalwareVerdict.MALICIOUS || hasCriticalIndicators) && normalizedLlmVerdict === MalwareVerdict.CLEAN) {
      const reason = `Guardrail violado: El LLM sugirió veredicto CLEAN pero existen indicadores críticos forenses o firma estática MALICIOUS. Se fuerza veredicto MALICIOUS.`;
      this.logger.warn(`[Output Guardrail] ${reason}`);
      violations.push(reason);

      return {
        finalVerdict: MalwareVerdict.MALICIOUS,
        wasOverriddenByGuardrail: true,
        guardrailReason: reason,
        violations,
      };
    }

    // Regla de Oro 2: Si el motor estático es SUSPICIOUS y el LLM sugiere CLEAN,
    // se mantiene como mínimo SUSPICIOUS.
    if (staticVerdict === MalwareVerdict.SUSPICIOUS && normalizedLlmVerdict === MalwareVerdict.CLEAN) {
      const reason = `Guardrail violado: Evidencia sospechosa presente. Se preserva veredicto SUSPICIOUS frente a la sugerencia CLEAN del LLM.`;
      this.logger.warn(`[Output Guardrail] ${reason}`);
      violations.push(reason);

      return {
        finalVerdict: MalwareVerdict.SUSPICIOUS,
        wasOverriddenByGuardrail: true,
        guardrailReason: reason,
        violations,
      };
    }

    // Si el LLM detectó severidad mayor que la estática (ej. detectó un truco de ingeniería social sutil),
    // se adopta la más restrictiva.
    let finalVerdict = staticVerdict;
    if (normalizedLlmVerdict === MalwareVerdict.MALICIOUS) {
      finalVerdict = MalwareVerdict.MALICIOUS;
    } else if (normalizedLlmVerdict === MalwareVerdict.SUSPICIOUS && staticVerdict === MalwareVerdict.CLEAN) {
      finalVerdict = MalwareVerdict.SUSPICIOUS;
    }

    return {
      finalVerdict,
      wasOverriddenByGuardrail: false,
      violations,
    };
  }

  /**
   * Valida comandos técnicos de remediación para evitar recomendaciones destructivas o inseguras
   * (e.g. chmod 777, deshabilitar SSL, rm -rf).
   */
  sanitizeRemediationCommands(commands: string[]): { safeCommands: string[]; blockedCommands: string[] } {
    const dangerousPatterns = [
      /chmod\s+(-R\s+)?777/i,
      /rm\s+-rf\s+[\/\*]/i,
      /curl.*?\|\s*(ba)?sh/i,
      /wget.*?\|\s*(ba)?sh/i,
      /ssl_verify_client\s+off/i,
      /insecure-skip-tls-verify/i,
      /disable-security/i,
    ];

    const safeCommands: string[] = [];
    const blockedCommands: string[] = [];

    for (const cmd of commands) {
      const isDangerous = dangerousPatterns.some((pattern) => pattern.test(cmd));
      if (isDangerous) {
        this.logger.warn(`[Output Guardrail] Comando potencialmente inseguro bloqueado: ${cmd}`);
        blockedCommands.push(cmd);
      } else {
        safeCommands.push(cmd);
      }
    }

    return { safeCommands, blockedCommands };
  }
}
