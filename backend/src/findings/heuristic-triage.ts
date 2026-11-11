import { FindingTriageAnalysis, TriageContextFactor } from './triage.interface';

export interface TriageFindingInput {
  id: string;
  ruleId: string;
  category: string;
  severity: string;
  cvssScore: number;
  title: string;
  description: string;
  location: string;
  evidence: Record<string, unknown>;
  asset: {
    id: string;
    type: string;
    value: string;
    name: string | null;
    criticality?: string;
    tags?: string[];
  };
}

const API_INDICATOR_REGEX = /api|backend|gateway|microservice|rest|graphql|json|bff|webhook/i;
const DEV_ENV_REGEX = /dev|stage|staging|test|qa|lab|sandbox|internal|local/i;
const DNS_INDICATOR_REGEX = /ns[0-9]*|dns|named|bind/i;

export function evaluateHeuristicTriage(input: TriageFindingInput): FindingTriageAnalysis {
  const { id, ruleId, category, severity, title, description, location, evidence, asset } = input;
  const tags = asset.tags ?? [];
  const assetName = asset.name ?? '';
  const assetValue = asset.value;

  const isApiContext =
    tags.some((t) => API_INDICATOR_REGEX.test(t)) ||
    API_INDICATOR_REGEX.test(assetName) ||
    API_INDICATOR_REGEX.test(assetValue) ||
    location.includes('/api') ||
    location.includes('/v1') ||
    location.includes('/v2') ||
    location.includes('/graphql') ||
    String(evidence?.contentType ?? '').includes('json');

  const isDevEnv =
    tags.some((t) => DEV_ENV_REGEX.test(t)) ||
    DEV_ENV_REGEX.test(assetName) ||
    DEV_ENV_REGEX.test(assetValue);

  const isDnsContext =
    tags.some((t) => DNS_INDICATOR_REGEX.test(t)) ||
    DNS_INDICATOR_REGEX.test(assetName) ||
    DNS_INDICATOR_REGEX.test(assetValue);

  const contextFactors: TriageContextFactor[] = [];
  const reasoning: string[] = [];

  // Regla 1: Falta de cabeceras de navegación HTML en servicios API/Backend
  if (
    category === 'HTTP_HEADERS' &&
    ['HDR-CSP-MISSING', 'HDR-XFO-MISSING', 'HDR-X-FRAME-OPTIONS-MISSING', 'HDR-PERMISSIONS-POLICY-MISSING', 'HDR-PERMISSIONS-MISSING'].includes(ruleId) &&
    isApiContext
  ) {
    contextFactors.push({
      factor: 'Servicio orientado a APIs / Formato JSON',
      impact: 'INCREASES_FP_PROBABILITY',
      detail: 'El activo opera como interfaz programática o microservicio de intercambio de datos.',
    });
    reasoning.push(
      'Las cabeceras Content-Security-Policy (CSP) y X-Frame-Options están diseñadas exclusivamente para proteger documentos HTML procesados por motores de navegación web (contra XSS y clickjacking).',
    );
    reasoning.push(
      'En endpoints que sirven exclusivamente JSON o XML, los navegadores no interpretan scripts ni permiten renderizado en frames, haciendo que la ausencia de estas cabeceras carezca de vector de ataque ejecutable.',
    );

    return {
      findingId: id,
      verdict: 'PROBABLE_FALSE_POSITIVE',
      confidence: 'HIGH',
      confidenceScore: 88,
      summary: 'Alta probabilidad de falso positivo: el activo opera como API REST/datos donde las directivas de renderizado HTML no tienen impacto.',
      reasoning,
      contextFactors,
      recommendedAction: 'MARK_FALSE_POSITIVE',
      suggestedNote: 'Falso positivo confirmado: El activo opera como endpoint de API REST/datos. CSP y X-Frame-Options no aplican a respuestas de datos JSON.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Regla 2: Seguridad de correo (SPF/DMARC) reportada sobre direcciones IP
  if (category === 'EMAIL_SECURITY' && (asset.type === 'IP' || tags.includes('ip-address'))) {
    contextFactors.push({
      factor: 'Tipo de activo no compatible con correo de dominio',
      impact: 'INCREASES_FP_PROBABILITY',
      detail: 'El activo analizado es una dirección IP y no un nombre de dominio corporativo con zona DNS.',
    });
    reasoning.push(
      'Los registros de autenticación de correo (SPF, DMARC, DKIM) se publican exclusivamente en registros TXT de zonas DNS de dominios raíz.',
    );
    reasoning.push(
      'Una dirección IP directa no aloja políticas de correo independientes. La evaluación de SPF/DMARC solo es pertinente sobre los nombres de dominio de la organización.',
    );

    return {
      findingId: id,
      verdict: 'PROBABLE_FALSE_POSITIVE',
      confidence: 'HIGH',
      confidenceScore: 92,
      summary: 'Probable falso positivo: los registros SPF/DMARC deben gestionarse a nivel de dominio, no sobre IPs.',
      reasoning,
      contextFactors,
      recommendedAction: 'MARK_FALSE_POSITIVE',
      suggestedNote: 'Falso positivo: Las políticas de SPF y DMARC aplican al dominio de correo corporativo, no a direcciones IP individuales.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Regla 2b: Dominio que no recibe correos (outbound-only) o entorno no productivo
  if (category === 'EMAIL_SECURITY' && (tags.includes('outbound-only') || tags.includes('non-production') || tags.includes('staging'))) {
    return {
      findingId: id,
      verdict: 'PROBABLE_FALSE_POSITIVE',
      confidence: 'HIGH',
      confidenceScore: 85,
      summary: 'Probable falso positivo: dominio o entorno de solo salida o pruebas que no gestiona recepción de correo.',
      reasoning: ['Dominios dedicados a envíos automatizados salientes o entornos no productivos no requieren registros de recepción como MTA-STS o BIMI.'],
      contextFactors: [{ factor: 'Dominio o entorno secundario', impact: 'INCREASES_FP_PROBABILITY', detail: 'El dominio solo realiza envíos salientes o es de pruebas.' }],
      recommendedAction: 'MARK_FALSE_POSITIVE',
      suggestedNote: 'Falso positivo: Dominio de solo salida o entorno de pruebas sin buzones de correo entrante.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Regla 3: Puerto 53 abierto en infraestructura de nombres de dominio
  if ((location.includes('/53') || location.includes(':53') || ruleId.includes('PORT-DNS')) && isDnsContext) {
    contextFactors.push({
      factor: 'Servicio DNS legítimo',
      impact: 'INCREASES_FP_PROBABILITY',
      detail: 'El nombre o etiquetas del activo corresponden a un servidor de nombres o DNS institucional.',
    });
    reasoning.push(
      'El puerto UDP/TCP 53 es obligatorio para la operación de servidores DNS autoritativos o resolutores.',
    );

    return {
      findingId: id,
      verdict: 'PROBABLE_FALSE_POSITIVE',
      confidence: 'HIGH',
      confidenceScore: 85,
      summary: 'Probable falso positivo: puerto 53 legítimo para la función de resolución DNS del servidor.',
      reasoning,
      contextFactors,
      recommendedAction: 'ACCEPT_RISK',
      suggestedNote: 'Riesgo aceptado / Operación normal: Servidor con función de resolución DNS legítima en puerto 53.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Regla 3b: Puerto 80 con redirección 301 a HTTPS
  if (
    (location.includes(':80') || location.includes('/80') || ruleId.includes('PORT-HTTP') || ruleId.includes('HDR-HTTP-NO-REDIRECT')) &&
    (evidence?.statusCode === 301 || tags.includes('https-redirect'))
  ) {
    return {
      findingId: id,
      verdict: 'PROBABLE_FALSE_POSITIVE',
      confidence: 'HIGH',
      confidenceScore: 90,
      summary: 'Probable falso positivo: el puerto 80 implementa redirección 301 automática a HTTPS según el estándar web.',
      reasoning: ['El puerto 80 responde con código 301 hacia HTTPS para garantizar que todo el tráfico sea cifrado.'],
      contextFactors: [{ factor: 'Redirección 301 HTTPS verificada', impact: 'INCREASES_FP_PROBABILITY', detail: 'El servidor fuerza transporte seguro.' }],
      recommendedAction: 'MARK_FALSE_POSITIVE',
      suggestedNote: 'Falso positivo: Redirección automática 301 a HTTPS configurada correctamente en el puerto 80.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Regla 4: Entornos de desarrollo o pruebas con discrepancia de certificado TLS
  if ((category === 'TLS_CERTIFICATE' || category === 'SSL_TLS') && ['TLS-SELF-SIGNED', 'TLS-CERT-SELFSIGNED', 'TLS-HOSTNAME-MISMATCH'].includes(ruleId) && isDevEnv) {
    contextFactors.push({
      factor: 'Entorno de Desarrollo / Pruebas',
      impact: 'INCREASES_FP_PROBABILITY',
      detail: 'El activo pertenece a un entorno no productivo o laboratorio.',
    });
    reasoning.push(
      'En entornos de staging o laboratorio es habitual el uso de certificados autofirmados o genéricos.',
    );
    reasoning.push(
      'Aunque la advertencia técnica es verídica, el impacto en usuarios finales es nulo si el entorno no maneja tráfico comercial ni clientes reales.',
    );

    return {
      findingId: id,
      verdict: 'NEEDS_VERIFICATION',
      confidence: 'MEDIUM',
      confidenceScore: 72,
      summary: 'Certificado no oficial esperado en entorno no productivo; evaluar aceptación de riesgo temporal.',
      reasoning,
      contextFactors,
      recommendedAction: 'ACCEPT_RISK',
      suggestedNote: 'Aceptación de riesgo: Certificado interno en entorno de desarrollo/pruebas sin impacto en usuarios finales.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Regla 4b: HSTS en red interna o IP
  if (ruleId === 'HDR-HSTS-MISSING' && (tags.includes('internal') || tags.includes('rfc1918') || asset.type === 'IP')) {
    return {
      findingId: id,
      verdict: 'PROBABLE_FALSE_POSITIVE',
      confidence: 'HIGH',
      confidenceScore: 88,
      summary: 'Probable falso positivo: HSTS no aplica sobre direcciones IP privadas o activos internos sin dominio FQDN.',
      reasoning: ['La directiva HSTS opera a nivel de cabeceras en dominios públicos para su registro en listas de precarga de navegadores.'],
      contextFactors: [{ factor: 'Activo IP interno', impact: 'INCREASES_FP_PROBABILITY', detail: 'Dirección privada sin nombre de dominio público.' }],
      recommendedAction: 'MARK_FALSE_POSITIVE',
      suggestedNote: 'Falso positivo: Las direcciones IP internas no gestionan políticas HSTS.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Regla 4c: CORS o Documentación Pública Intencional
  if (
    (ruleId.includes('CORS') || ruleId.includes('SWAGGER') || ruleId.includes('DOCS')) &&
    (tags.includes('public-data') || tags.includes('public-api') || tags.includes('documentation') || location.includes('/public'))
  ) {
    return {
      findingId: id,
      verdict: 'PROBABLE_FALSE_POSITIVE',
      confidence: 'HIGH',
      confidenceScore: 85,
      summary: 'Probable falso positivo: recurso diseñado explícitamente para acceso público o documentación abierta.',
      reasoning: ['Los endpoints y portales de documentación pública no requieren restricciones de origen CORS estricto.'],
      contextFactors: [{ factor: 'Recurso público intencional', impact: 'INCREASES_FP_PROBABILITY', detail: 'Servicio diseñado para consumo abierto sin autenticación.' }],
      recommendedAction: 'MARK_FALSE_POSITIVE',
      suggestedNote: 'Falso positivo: Servicio o documentación concebida para acceso público.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Regla 4d: Cloud S3 bucket para activos estáticos web (CSS/JS/Imágenes)
  if (ruleId.includes('S3') && (tags.includes('static-assets') || tags.includes('cdn'))) {
    return {
      findingId: id,
      verdict: 'PROBABLE_FALSE_POSITIVE',
      confidence: 'HIGH',
      confidenceScore: 90,
      summary: 'Probable falso positivo: bucket S3 destinado a la distribución de recursos web estáticos públicos.',
      reasoning: ['Los activos estáticos del frontend (imágenes, hojas de estilo) requieren acceso público de lectura por diseño.'],
      contextFactors: [{ factor: 'Contenedor de activos estáticos', impact: 'INCREASES_FP_PROBABILITY', detail: 'Contenido público por arquitectura web.' }],
      recommendedAction: 'MARK_FALSE_POSITIVE',
      suggestedNote: 'Falso positivo: Bucket configurado para entrega pública de archivos estáticos.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Regla 4e: Actuator health check básico sin secretos
  if ((location.includes('/actuator/health') || ruleId.includes('ACTUATOR-HEALTH')) && !JSON.stringify(evidence || {}).includes('password')) {
    return {
      findingId: id,
      verdict: 'PROBABLE_FALSE_POSITIVE',
      confidence: 'HIGH',
      confidenceScore: 85,
      summary: 'Probable falso positivo: endpoint /health estándar sin exposición de secretos ni información sensible.',
      reasoning: ['El endpoint de health check solo confirma disponibilidad operativa para balanceadores de carga.'],
      contextFactors: [{ factor: 'Endpoint de monitoreo estándar', impact: 'INCREASES_FP_PROBABILITY', detail: 'No divulga datos sensibles ni variables de entorno.' }],
      recommendedAction: 'MARK_FALSE_POSITIVE',
      suggestedNote: 'Falso positivo: Health check estándar para monitoreo sin exposición de datos.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Regla 4f: Cabecera Server genérica sin versión expuesta
  if (
    (ruleId.includes('SERVER-LEAK') || ruleId.includes('SERVER-VERSION') || ruleId === 'HDR-SERVER-BANNER') &&
    (tags.includes('cdn') || tags.includes('waf') || evidence?.server === 'cloudflare' || description.includes('cloudflare'))
  ) {
    return {
      findingId: id,
      verdict: 'PROBABLE_FALSE_POSITIVE',
      confidence: 'HIGH',
      confidenceScore: 85,
      summary: 'Probable falso positivo: cabecera de CDN o WAF genérica que no divulga versiones vulnerables específicas.',
      reasoning: ['La identificación de un proveedor de CDN como Cloudflare no constituye una vulnerabilidad técnica explotable.'],
      contextFactors: [{ factor: 'Edge CDN genérico', impact: 'INCREASES_FP_PROBABILITY', detail: 'Cabecera estándar de red de distribución.' }],
      recommendedAction: 'MARK_FALSE_POSITIVE',
      suggestedNote: 'Falso positivo: Cabecera genérica de CDN perimetral.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Regla 5: Exposición crítica de credenciales, secretos o orquestación
  if (
    [
      'PATH-ACTUATOR-ENV',
      'PATH-ACTUATOR-HEAPDUMP',
      'PATH-GIT-EXPOSED',
      'PATH-ENV-FILE',
      'PATH-BACKUP-FILE',
      'SVC-ORCHESTRATION-EXPOSED',
    ].includes(ruleId) ||
    evidence?.cisaKev === true
  ) {
    contextFactors.push({
      factor: 'Exfiltración de credenciales / Explotación activa confirmada',
      impact: 'DECREASES_FP_PROBABILITY',
      detail: 'La regla detecta exposición directa de secretos, tokens o vulnerabilidades con exploits conocidos.',
    });
    reasoning.push(
      'Este tipo de exposición representa un vector directo de intrusión perimetral y elevación de privilegios.',
    );
    reasoning.push(
      'Bajo ningún estándar de seguridad se considera aceptable la exposición pública de archivos .env, repositorios git o interfaces de orquestación de contenedores.',
    );

    return {
      findingId: id,
      verdict: 'CONFIRMED_TRUE_POSITIVE',
      confidence: 'HIGH',
      confidenceScore: 98,
      summary: 'Riesgo confirmado y crítico: exposición perimetral directa de credenciales o componentes sensibles.',
      reasoning,
      contextFactors,
      recommendedAction: 'REMEDIATE',
      suggestedNote: 'Riesgo confirmado: Vector directo de intrusión y compromiso perimetral. No descartar como falso positivo.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Regla 6: Bases de datos y accesos remotos expuestos en internet
  if (
    [
      'SVC-DATABASE-EXPOSED',
      'SVC-REMOTE-DESKTOP',
      'SVC-CLEARTEXT-REMOTE-ADMIN',
      'SVC-REDIS-NOAUTH',
      'SVC-MONGODB-NOAUTH',
    ].includes(ruleId)
  ) {
    contextFactors.push({
      factor: 'Servicio central expuesto en perímetro público',
      impact: 'DECREASES_FP_PROBABILITY',
      detail: 'Puerto de almacenamiento de datos o acceso administrativo accesible sin túnel seguro.',
    });
    reasoning.push(
      `El servicio ${title} está expuesto directamente en ${location}. Esto facilita ataques automatizados de fuerza bruta y explotación directa.`,
    );

    return {
      findingId: id,
      verdict: 'CONFIRMED_TRUE_POSITIVE',
      confidence: 'HIGH',
      confidenceScore: 92,
      summary: 'Riesgo confirmado: servicio sensible o base de datos expuesta al internet público.',
      reasoning,
      contextFactors,
      recommendedAction: 'REMEDIATE',
      suggestedNote: 'Confirmado como riesgo prioritario. Restringir el puerto por firewall o VPN.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Regla 7: Divulgación de banner de servidor
  if (ruleId === 'HDR-SERVER-BANNER' || ruleId === 'SVC-SERVICE-BANNER') {
    contextFactors.push({
      factor: 'Divulgación de metadatos de baja criticidad',
      impact: 'NEUTRAL',
      detail: 'La cabecera o banner informa el motor de servidor, común en arquitecturas estándar.',
    });
    reasoning.push(
      'Ocultar el banner de servidor reduce la enumeración inicial por parte de atacantes casuales, pero no mitiga vulnerabilidades por sí solo.',
    );
    reasoning.push(
      'Si el software expuesto está en su versión más reciente y con parches de seguridad al día, este hallazgo suele considerarse de riesgo aceptable o baja prioridad.',
    );

    return {
      findingId: id,
      verdict: 'NEEDS_VERIFICATION',
      confidence: 'MEDIUM',
      confidenceScore: 68,
      summary: 'Divulgación de información de bajo impacto; verificar si revela versiones obsoletas o aceptar el riesgo.',
      reasoning,
      contextFactors,
      recommendedAction: 'ACCEPT_RISK',
      suggestedNote: 'Riesgo aceptado: Divulgación de banner sin vulnerabilidades activas asociadas.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Regla 8: Fallback adaptativo por severidad
  if (severity === 'CRITICAL' || severity === 'HIGH') {
    contextFactors.push({
      factor: `Severidad técnica ${severity}`,
      impact: 'DECREASES_FP_PROBABILITY',
      detail: `Puntuación CVSS de referencia: ${input.cvssScore}/10.`,
    });
    reasoning.push(
      `El hallazgo posee severidad técnica ${severity} (${title}). Se presume verdadero positivo salvo que exista una contramedida compensatoria documentada.`,
    );

    return {
      findingId: id,
      verdict: 'CONFIRMED_TRUE_POSITIVE',
      confidence: 'HIGH',
      confidenceScore: 82,
      summary: `Riesgo prioritario: severidad ${severity} requiere mitigación técnica en ${location}.`,
      reasoning,
      contextFactors,
      recommendedAction: 'REMEDIATE',
      suggestedNote: 'Verificado como riesgo real. Proceder con el plan de remediación técnica.',
      evaluatedAt: new Date().toISOString(),
      provider: 'heuristic-expert',
    };
  }

  // Para hallazgos MEDIUM / LOW / INFO generales
  contextFactors.push({
    factor: `Severidad técnica moderada o baja (${severity})`,
    impact: 'NEUTRAL',
    detail: 'No se identificaron patrones concluyentes de falso positivo automático.',
  });
  reasoning.push(
    `El hallazgo "${title}" en ${location} requiere validación manual por parte del analista para determinar si el comportamiento es intencional o remediable.`,
  );

  return {
    findingId: id,
    verdict: 'NEEDS_VERIFICATION',
    confidence: 'MEDIUM',
    confidenceScore: 60,
    summary: 'Requiere verificación manual: el contexto actual no permite clasificarlo como falso positivo automático.',
    reasoning,
    contextFactors,
    recommendedAction: 'RETEST',
    suggestedNote: 'Pendiente de confirmación tras validación de configuración en el activo.',
    evaluatedAt: new Date().toISOString(),
    provider: 'heuristic-expert',
  };
}
