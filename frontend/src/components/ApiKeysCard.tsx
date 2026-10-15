import {
  Check,
  ChevronDown,
  ChevronUp,
  Copy,
  Key,
  Plus,
  Terminal,
  Trash2,
} from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Alert } from '@/components/ui/Alert';
import { Pill } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Input, Label } from '@/components/ui/Field';
import { Modal } from '@/components/ui/Modal';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import {
  useApiKeys,
  useCreateApiKey,
  useDeleteApiKey,
  useRevokeApiKey,
} from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { formatDateTime, timeAgo } from '@/lib/format';
import type { CreatedApiKeyResponse } from '@/lib/types';

const SCOPES_CONFIG = [
  { id: 'findings:read', label: 'Hallazgos (findings:read)', desc: 'Exportación de hallazgos y estado de vulnerabilidades' },
  { id: 'alerts:read', label: 'Alertas (alerts:read)', desc: 'Exportación de alertas generadas en tiempo real' },
  { id: 'posture:read', label: 'Postura (posture:read)', desc: 'Lectura de métricas de score y desglose de riesgo' },
  { id: 'assets:read', label: 'Activos (assets:read)', desc: 'Inventario de activos, criticidad y resumen de hallazgos' },
];

export function ApiKeysCard() {
  const q = useApiKeys();
  const createMutation = useCreateApiKey();
  const revokeMutation = useRevokeApiKey();
  const deleteMutation = useDeleteApiKey();

  const [createOpen, setCreateOpen] = useState(false);
  const [createdSecret, setCreatedSecret] = useState<CreatedApiKeyResponse | null>(null);
  const [copied, setCopied] = useState(false);
  const [showDocs, setShowDocs] = useState(false);
  const [formName, setFormName] = useState('');
  const [formScopes, setFormScopes] = useState<string[]>(SCOPES_CONFIG.map((s) => s.id));
  const [formExpiresAt, setFormExpiresAt] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    setFormError(null);
    if (!formName.trim()) {
      setFormError('Ingresa un nombre para la llave.');
      return;
    }
    if (formScopes.length === 0) {
      setFormError('Selecciona al menos un permiso (scope).');
      return;
    }

    try {
      const res = await createMutation.mutateAsync({
        name: formName.trim(),
        scopes: formScopes,
        expiresAt: formExpiresAt ? new Date(formExpiresAt).toISOString() : undefined,
      });
      setCreateOpen(false);
      setCreatedSecret(res);
      setFormName('');
      setFormExpiresAt('');
      setFormScopes(SCOPES_CONFIG.map((s) => s.id));
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : 'No se pudo crear la llave de API.');
    }
  };

  const copyToClipboard = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  const handleRevoke = async (id: string, name: string) => {
    if (!confirm(`¿Estás seguro de revocar la llave "${name}"? Dejará de funcionar de inmediato en los sistemas conectados.`)) {
      return;
    }
    await revokeMutation.mutateAsync(id);
  };

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`¿Deseas eliminar definitivamente la llave "${name}"?`)) {
      return;
    }
    await deleteMutation.mutateAsync(id);
  };

  const toggleScope = (scopeId: string) => {
    setFormScopes((prev) =>
      prev.includes(scopeId) ? prev.filter((s) => s !== scopeId) : [...prev, scopeId],
    );
  };

  const keysList = q.data ?? [];

  return (
    <>
      <Card>
        <CardHeader
          title="Integración SIEM / SOAR & API Keys"
          subtitle="Genera credenciales seguras para exportar hallazgos, alertas e inventario hacia Splunk, Wazuh, Elastic, Datadog o pipelines CI/CD."
          action={
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="mr-1.5 h-4 w-4" />
              Nueva API Key
            </Button>
          }
        />
        <CardBody>
          {q.isPending ? (
            <Skeleton className="h-28" />
          ) : keysList.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border py-8 text-center">
              <Key className="mx-auto h-8 w-8 text-muted" />
              <p className="mt-2 text-sm font-medium text-ink">No hay llaves de API configuradas</p>
              <p className="mt-1 text-xs text-ink-2">
                Crea una llave para comenzar a transmitir eventos hacia tu plataforma de observabilidad o SIEM.
              </p>
              <Button size="sm" className="mt-4" onClick={() => setCreateOpen(true)}>
                <Plus className="mr-1.5 h-4 w-4" />
                Crear primera API Key
              </Button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <thead>
                  <tr>
                    <Th>Nombre</Th>
                    <Th>Prefijo</Th>
                    <Th>Permisos</Th>
                    <Th>Último uso</Th>
                    <Th>Caducidad</Th>
                    <Th>Estado</Th>
                    <Th className="text-right">Acciones</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {keysList.map((k) => (
                    <tr key={k.id}>
                      <Td className="font-medium text-ink">
                        {k.name}
                        {k.createdBy ? (
                          <span className="block text-xs text-muted">por {k.createdBy.fullName}</span>
                        ) : null}
                      </Td>
                      <Td>
                        <code className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-xs text-ink">
                          {k.keyPrefix}
                        </code>
                      </Td>
                      <Td>
                        <div className="flex flex-wrap gap-1">
                          {k.scopes.map((scope) => (
                            <Pill key={scope} className="text-[10px] py-0 px-1.5">
                              {scope.replace(':read', '')}
                            </Pill>
                          ))}
                        </div>
                      </Td>
                      <Td className="text-xs text-ink-2">
                        {k.lastUsedAt ? timeAgo(k.lastUsedAt) : 'Nunca usada'}
                      </Td>
                      <Td className="text-xs text-ink-2">
                        {k.expiresAt ? formatDateTime(k.expiresAt) : 'Sin caducidad'}
                      </Td>
                      <Td>
                        {k.isActive ? (
                          <span className="inline-flex items-center rounded-md bg-good/12 px-2 py-0.5 text-xs font-semibold text-good-text">
                            Activa
                          </span>
                        ) : (
                          <span className="inline-flex items-center rounded-md bg-surface-2 px-2 py-0.5 text-xs font-medium text-ink-2">
                            Revocada
                          </span>
                        )}
                      </Td>
                      <Td className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          {k.isActive ? (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-xs text-warning hover:bg-warning/10"
                              onClick={() => handleRevoke(k.id, k.name)}
                              disabled={revokeMutation.isPending}
                            >
                              Revocar
                            </Button>
                          ) : null}
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-xs text-danger hover:bg-danger/10"
                            onClick={() => handleDelete(k.id, k.name)}
                            disabled={deleteMutation.isPending}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
          )}

          {/* Sección desplegable con documentación y ejemplos SIEM */}
          <div className="mt-4 border-t border-line pt-3">
            <button
              type="button"
              onClick={() => setShowDocs(!showDocs)}
              className="flex w-full items-center justify-between text-xs font-semibold text-accent hover:underline"
            >
              <span className="flex items-center gap-1.5">
                <Terminal className="h-4 w-4" />
                Guía de integración SIEM / SOAR (Splunk, Elastic, Wazuh, Datadog)
              </span>
              {showDocs ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>

            {showDocs ? (
              <div className="mt-3 space-y-3 rounded-lg border border-border bg-surface-2 p-4 text-xs text-ink-2">
                <div>
                  <h4 className="font-semibold text-ink">Encabezado de Autenticación</h4>
                  <p className="mt-0.5">
                    Envía tu token en cada petición en el encabezado <code className="text-ink">X-API-Key: sspm_live_...</code> o <code className="text-ink">Authorization: Bearer sspm_live_...</code>.
                  </p>
                </div>

                <div>
                  <h4 className="font-semibold text-ink">Endpoints Públicos de Exportación</h4>
                  <ul className="mt-1 space-y-1 font-mono text-[11px] text-ink">
                    <li>GET /api/v1/public/findings?since=2026-10-01T00:00:00Z&format=ndjson</li>
                    <li>GET /api/v1/public/alerts?since=2026-10-01T00:00:00Z&format=ndjson</li>
                    <li>GET /api/v1/public/posture</li>
                    <li>GET /api/v1/public/assets?format=ndjson</li>
                  </ul>
                </div>

                <div>
                  <h4 className="font-semibold text-ink">Ejemplo de Ingesta Splunk / Wazuh (NDJSON)</h4>
                  <pre className="mt-1 overflow-x-auto rounded bg-ink/5 p-2 font-mono text-[11px] text-ink">
                    {`# Sincronización incremental de hallazgos hacia Splunk HEC o Logstash
curl -s -H "X-API-Key: sspm_live_TU_SECRETO" \\
     -H "Accept: application/x-ndjson" \\
     "https://api.tudominio.com/api/v1/public/findings?format=ndjson&since=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)" \\
     | splunk-forwarder --sourcetype="sspm:findings"`}
                  </pre>
                </div>
              </div>
            ) : null}
          </div>
        </CardBody>
      </Card>

      {/* Modal para Crear API Key */}
      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Crear Nueva API Key"
      >
        <form onSubmit={handleCreate} className="space-y-4">
          <p className="text-xs text-ink-2">
            La clave tendrá acceso de solo lectura a los recursos seleccionados mediante la API pública.
          </p>

          <div>
            <Label htmlFor="apiKeyName">Nombre de la integración / servicio</Label>
            <Input
              id="apiKeyName"
              placeholder="Ej: Splunk Forwarder Producción"
              value={formName}
              onChange={(e) => setFormName(e.target.value)}
              required
            />
          </div>

          <div>
            <Label>Permisos concedidos</Label>
            <div className="mt-1 space-y-2 rounded-lg border border-border p-3">
              {SCOPES_CONFIG.map((scope) => {
                const checked = formScopes.includes(scope.id);
                return (
                  <label key={scope.id} className="flex items-start gap-2.5 text-xs cursor-pointer">
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleScope(scope.id)}
                      className="mt-0.5 accent-[var(--accent)]"
                    />
                    <div>
                      <span className="font-medium text-ink">{scope.label}</span>
                      <p className="text-[11px] text-muted">{scope.desc}</p>
                    </div>
                  </label>
                );
              })}
            </div>
          </div>

          <div>
            <Label htmlFor="apiKeyExpiresAt">Fecha de expiración (opcional)</Label>
            <Input
              id="apiKeyExpiresAt"
              type="datetime-local"
              value={formExpiresAt}
              onChange={(e) => setFormExpiresAt(e.target.value)}
            />
            <span className="text-[11px] text-muted">
              Si se deja en blanco, la clave no caducará hasta que sea revocada manualmente.
            </span>
          </div>

          {formError ? <Alert kind="error">{formError}</Alert> : null}

          <div className="flex justify-end gap-2 pt-2">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => setCreateOpen(false)}
            >
              Cancelar
            </Button>
            <Button
              type="submit"
              size="sm"
              disabled={createMutation.isPending}
            >
              {createMutation.isPending ? 'Generando...' : 'Generar API Key'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Modal de visualización de clave secreta (solo se muestra una vez) */}
      <Modal
        open={createdSecret !== null}
        onClose={() => setCreatedSecret(null)}
        title="¡Guarda tu API Key de forma segura!"
      >
        {createdSecret ? (
          <div className="space-y-4">
            <Alert kind="error">
              <strong>Copia esta clave ahora.</strong> Por políticas de seguridad de conocimiento cero (Zero-Knowledge), este secreto nunca se almacena en texto claro y no podrás volver a consultarlo.
            </Alert>

            <div>
              <Label>Llave secreta generada</Label>
              <div className="mt-1 flex items-center gap-2">
                <input
                  readOnly
                  value={createdSecret.rawKey}
                  className="flex-1 rounded-md border border-border bg-surface-2 px-3 py-2 font-mono text-xs text-ink select-all focus:outline-none"
                />
                <Button
                  size="sm"
                  variant={copied ? 'secondary' : 'primary'}
                  onClick={() => copyToClipboard(createdSecret.rawKey)}
                  className="shrink-0"
                >
                  {copied ? (
                    <>
                      <Check className="mr-1 h-3.5 w-3.5 text-success" />
                      Copiada
                    </>
                  ) : (
                    <>
                      <Copy className="mr-1 h-3.5 w-3.5" />
                      Copiar
                    </>
                  )}
                </Button>
              </div>
            </div>

            <div className="rounded-lg border border-border bg-surface-2 p-3 text-xs text-ink-2">
              <span className="font-semibold text-ink">Ejemplo de uso inmediato:</span>
              <pre className="mt-1.5 overflow-x-auto rounded bg-ink/5 p-2 font-mono text-[11px] text-ink">
                {`curl -H "X-API-Key: ${createdSecret.rawKey}" \\
     "${window.location.origin}/api/v1/public/findings?format=ndjson"`}
              </pre>
            </div>

            <div className="flex justify-end pt-2">
              <Button size="sm" onClick={() => setCreatedSecret(null)}>
                He guardado la clave
              </Button>
            </div>
          </div>
        ) : null}
      </Modal>
    </>
  );
}
