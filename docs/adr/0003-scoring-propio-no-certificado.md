# ADR-0003: Motor de Security Score propio (inspirado en CVSS, no certificado)

## Estado

Aceptado.

## Contexto

El sistema necesita traducir hallazgos técnicos en una métrica única
comprensible para no-técnicos (Security Score). Existían dos caminos:
adoptar/embeber un motor de scoring de terceros (ej. calculadora CVSS
oficial, o un producto como OpenVAS/Qualys) o construir un modelo propio.

## Decisión

Se implementó un modelo propio (`backend/src/risk/scoring.ts`):

```
Score = 100 − Σ min(Tope_s, Peso_s × Abiertos_s), acotado a [0, 100]
```

con pesos y topes por severidad (ver README, sección "Motor de riesgo"),
usando el rango CVSS v3.1 solo como **referencia de clasificación** de cada
regla de hallazgo (CRITICAL/HIGH/MEDIUM/LOW/INFO), no como cálculo CVSS
completo (que requeriría vectores de explotabilidad e impacto por
vulnerabilidad, no aplicables a hallazgos de configuración).

## Consecuencias

- **Explicable de cara al cliente**: la fórmula es simple y su desglose se
  expone en `GET /risk-scores/model` y en el detalle de cada activo. Esto
  es una ventaja de venta (transparencia) frente a "cajas negras".
- **No es un estándar certificado**: al vender el producto, el material
  comercial y los reportes deben ser explícitos en que el "Security Score"
  es una métrica propia inspirada en CVSS, no una puntuación CVSS oficial
  ni una certificación de terceros. Prometer lo contrario es un riesgo
  legal y de credibilidad frente a clientes que conozcan CVSS/Qualys/Tenable.
- Los topes de penalización (sección 6.3.4 de la documentación académica)
  son una decisión de producto, no un cálculo objetivo: deben poder
  ajustarse por feedback de clientes reales sin romper el histórico
  (cada `risk_scores` guarda su propio `breakdown`, por lo que cambiar la
  fórmula no reescribe el pasado).
