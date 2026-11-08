import {
  AlertCircle,
  Check,
  CheckCircle2,
  ExternalLink,
  Layers,
  RefreshCw,
  Settings,
  Trash2,
  Workflow,
  Zap,
} from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Alert } from '@/components/ui/Alert';
import { Pill } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Input, Label } from '@/components/ui/Field';
import { Modal } from '@/components/ui/Modal';
import { Skeleton } from '@/components/ui/Spinner';
import {
  useConfigureTicketing,
  useDeleteTicketing,
  useTestTicketing,
  useTicketingConfig,
} from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { cn } from '@/lib/cn';
import { formatDateTime } from '@/lib/format';
import type {
  ConfigureTicketingInput,
  TestConnectionResult,
  TicketingAutoCreateThreshold,
  TicketingProvider,
} from '@/lib/types';

export function TicketingIntegrationCard() {
  const { data: config, isLoading, refetch } = useTicketingConfig();
  const configureMutation = useConfigureTicketing();
  const testMutation = useTestTicketing();
  const deleteMutation = useDeleteTicketing();

  const [modalOpen, setModalOpen] = useState(false);
  const [provider, setProvider] = useState<TicketingProvider>('JIRA');
  const [instanceUrl, setInstanceUrl] = useState('');
  const [projectKey, setProjectKey] = useState('');
  const [issueType, setIssueType] = useState('Bug');
  const [autoThreshold, setAutoThreshold] = useState<TicketingAutoCreateThreshold>('DISABLED');
  const [jiraEmail, setJiraEmail] = useState('');
  const [jiraToken, setJiraToken] = useState('');
  const [azurePat, setAzurePat] = useState('');
  const [testResult, setTestResult] = useState<TestConnectionResult | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const openConfigModal = () => {
    setFormError(null);
    setTestResult(null);
    if (config) {
      setProvider(config.provider);
      setInstanceUrl(config.instanceUrl);
      setProjectKey(config.projectKey);
      setIssueType(config.issueType);
      setAutoThreshold(config.autoCreateThreshold);
      setJiraEmail('');
      setJiraToken('');
      setAzurePat('');
    } else {
      setProvider('JIRA');
      setInstanceUrl('');
      setProjectKey('');
      setIssueType('Bug');
      setAutoThreshold('DISABLED');
      setJiraEmail('');
      setJiraToken('');
      setAzurePat('');
    }
    setModalOpen(true);
  };

  const handleRunStoredTest = async () => {
    if (!config) return;
    setTestResult(null);
    try {
      const res = await testMutation.mutateAsync({
        provider: config.provider,
        instanceUrl: config.instanceUrl,
        projectKey: config.projectKey,
      });
      setTestResult(res);
      refetch();
    } catch (err) {
      setTestResult({
        ok: false,
        provider: config.provider,
        error: err instanceof ApiError ? err.message : (err as Error).message,
      });
    }
  };

  const handleTestModal = async () => {
    setFormError(null);
    setTestResult(null);
    if (!instanceUrl.trim() || !projectKey.trim()) {
      setFormError('Ingresa la URL de la instancia y la clave del proyecto.');
      return;
    }

    const credentials: Record<string, string> = {};
    if (provider === 'JIRA') {
      if (!jiraEmail.trim() || !jiraToken.trim()) {
        setFormError('Para Jira debes ingresar tu correo y el API Token.');
        return;
      }
      credentials.email = jiraEmail.trim();
      credentials.apiToken = jiraToken.trim();
    } else {
      if (!azurePat.trim()) {
        setFormError('Para Azure Boards debes ingresar el Personal Access Token (PAT).');
        return;
      }
      credentials.personalAccessToken = azurePat.trim();
    }

    try {
      const res = await testMutation.mutateAsync({
        provider,
        instanceUrl: instanceUrl.trim(),
        projectKey: projectKey.trim(),
        credentials,
      });
      setTestResult(res);
    } catch (err) {
      setTestResult({
        ok: false,
        provider,
        error: err instanceof ApiError ? err.message : (err as Error).message,
      });
    }
  };

  const handleSubmitSave = async (e: FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!instanceUrl.trim() || !projectKey.trim()) {
      setFormError('URL de instancia y clave de proyecto son obligatorias.');
      return;
    }

    const credentials: Record<string, string> = {};
    if (provider === 'JIRA') {
      if (!config?.hasStoredCredentials && (!jiraEmail.trim() || !jiraToken.trim())) {
        setFormError('Ingresa correo y API Token de Atlassian Jira.');
        return;
      }
      if (jiraEmail.trim()) credentials.email = jiraEmail.trim();
      if (jiraToken.trim()) credentials.apiToken = jiraToken.trim();
    } else {
      if (!config?.hasStoredCredentials && !azurePat.trim()) {
        setFormError('Ingresa el Personal Access Token (PAT) de Azure DevOps.');
        return;
      }
      if (azurePat.trim()) credentials.personalAccessToken = azurePat.trim();
    }

    const payload: ConfigureTicketingInput = {
      provider,
      instanceUrl: instanceUrl.trim(),
      projectKey: projectKey.trim(),
      issueType: issueType.trim() || (provider === 'JIRA' ? 'Bug' : 'Issue'),
      autoCreateThreshold: autoThreshold,
      credentials,
    };

    try {
      await configureMutation.mutateAsync(payload);
      setModalOpen(false);
      refetch();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : (err as Error).message);
    }
  };

  const handleDelete = async () => {
    try {
      await deleteMutation.mutateAsync();
      setConfirmDelete(false);
      setTestResult(null);
      refetch();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : (err as Error).message);
    }
  };

  return (
    <>
      <Card className="mt-4">
        <CardHeader
          title="Integración de Remediación con Jira Software y Azure Boards"
          subtitle="Sincroniza y orquesta el ciclo de vida de tickets de ingeniería a partir de hallazgos de seguridad con 1 clic o automáticamente."
          action={
            config ? (
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={handleRunStoredTest}
                  disabled={testMutation.isPending}
                >
                  <RefreshCw className={`mr-1.5 h-3.5 w-3.5 ${testMutation.isPending ? 'animate-spin' : ''}`} />
                  Probar Conexión
                </Button>
                <Button size="sm" variant="secondary" onClick={openConfigModal}>
                  <Settings className="mr-1.5 h-3.5 w-3.5" />
                  Editar
                </Button>
                <Button
                  size="sm"
                  variant="danger"
                  onClick={() => setConfirmDelete(true)}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            ) : (
              <Button size="sm" onClick={openConfigModal}>
                <Workflow className="mr-1.5 h-3.5 w-3.5" />
                Vincular Plataforma
              </Button>
            )
          }
        />
        <CardBody>
          {isLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-6 w-1/3" />
              <Skeleton className="h-16 w-full" />
            </div>
          ) : !config ? (
            <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/40 p-6 text-center">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-cyan-500/10 text-cyan-400">
                <Workflow className="h-6 w-6" />
              </div>
              <h3 className="mt-3 text-sm font-semibold text-white">
                Ninguna plataforma de ingeniería conectada
              </h3>
              <p className="mx-auto mt-1 max-w-lg text-xs text-slate-400">
                Conecta tu instancia de Jira Cloud o Azure DevOps Boards para enviar hallazgos con 1 clic
                o en masa, enriquecidos con taxonomía GRC (CWE, OWASP Top 10, MITRE ATT&CK), evidencia técnica y seguimiento de estado bidireccional.
              </p>
              <div className="mt-5 flex justify-center gap-3">
                <Button size="sm" onClick={openConfigModal}>
                  <Zap className="mr-1.5 h-3.5 w-3.5 text-yellow-400" />
                  Configurar Jira Software o Azure Boards
                </Button>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Resumen de configuración activa */}
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5">
                  <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
                    Proveedor
                  </div>
                  <div className="mt-1.5 flex items-center gap-2">
                    <Pill
                      className={
                        config.provider === 'JIRA'
                          ? 'border border-cyan-500/30 bg-cyan-500/10 text-cyan-400'
                          : 'border border-blue-500/30 bg-blue-500/10 text-blue-400'
                      }
                    >
                      {config.provider === 'JIRA' ? 'Atlassian Jira' : 'Azure Boards'}
                    </Pill>
                    <span className="text-xs text-slate-400">
                      {config.enabled ? 'Activo' : 'Pausado'}
                    </span>
                  </div>
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5">
                  <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
                    Proyecto & Tipo
                  </div>
                  <div className="mt-1 text-sm font-medium text-white">
                    {config.projectKey}
                  </div>
                  <div className="text-xs text-slate-400">
                    Tipo de ítem: <span className="font-mono text-cyan-300">{config.issueType}</span>
                  </div>
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5">
                  <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
                    Auto-Creación tras Escaneo
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    <Pill
                      className={cn(
                        'border text-[11px] font-medium',
                        config.autoCreateThreshold === 'DISABLED'
                          ? 'border-slate-700 bg-slate-800 text-slate-300'
                          : config.autoCreateThreshold === 'CRITICAL'
                          ? 'border-red-500/30 bg-red-500/10 text-red-400'
                          : config.autoCreateThreshold === 'HIGH'
                          ? 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                          : 'border-yellow-500/30 bg-yellow-500/10 text-yellow-300',
                      )}
                    >
                      {config.autoCreateThreshold === 'DISABLED'
                        ? 'Desactivada (Manual)'
                        : `≥ ${config.autoCreateThreshold}`}
                    </Pill>
                  </div>
                  <div className="mt-1 text-[11px] text-slate-400">
                    {config.autoCreateThreshold === 'DISABLED'
                      ? 'Tickets se crean solo con 1 clic'
                      : 'Tickets creados automáticamente'}
                  </div>
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5">
                  <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
                    Estado de Conexión
                  </div>
                  <div className="mt-1 flex items-center gap-1.5">
                    {config.lastTestStatus === 'SUCCESS' ? (
                      <>
                        <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                        <span className="text-xs font-medium text-emerald-400">Conexión Verificada</span>
                      </>
                    ) : config.lastTestStatus === 'FAILED' ? (
                      <>
                        <AlertCircle className="h-4 w-4 text-red-400" />
                        <span className="text-xs font-medium text-red-400">Fallo de Validación</span>
                      </>
                    ) : (
                      <span className="text-xs text-slate-400">Sin validar</span>
                    )}
                  </div>
                  {config.lastTestedAt && (
                    <div className="mt-1 text-[11px] text-slate-400">
                      {formatDateTime(config.lastTestedAt)}
                    </div>
                  )}
                </div>
              </div>

              {/* URL y Detalles */}
              <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-900/40 px-4 py-2.5 text-xs text-slate-300">
                <div className="flex items-center gap-2">
                  <Layers className="h-4 w-4 text-slate-400" />
                  <span>Instancia:</span>
                  <a
                    href={config.instanceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 font-mono text-cyan-400 hover:underline"
                  >
                    {config.instanceUrl}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
                <div className="text-slate-400">
                  Credenciales cifradas con AES-256-GCM en el almacén de seguridad
                </div>
              </div>

              {/* Feedback de Test en vivo */}
              {testResult && (
                <Alert kind={testResult.ok ? 'success' : 'error'}>
                  <div className="text-xs">
                    {testResult.ok ? (
                      <div>
                        <strong>Conexión Exitosa:</strong> Se verificó el acceso al proyecto{' '}
                        <span className="font-semibold text-emerald-300">
                          {testResult.projectName || testResult.projectKey}
                        </span>
                        .{' '}
                        {testResult.issueTypes && testResult.issueTypes.length > 0 && (
                          <span>
                            Tipos de ítem disponibles: {testResult.issueTypes.slice(0, 5).join(', ')}.
                          </span>
                        )}
                      </div>
                    ) : (
                      <div>
                        <strong>Error de Conexión:</strong> {testResult.error}
                      </div>
                    )}
                  </div>
                </Alert>
              )}
            </div>
          )}
        </CardBody>
      </Card>

      {/* Modal de Configuración */}
      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title={config ? 'Editar Integración de Ticketing' : 'Conectar Jira Software o Azure Boards'}
      >
        <form onSubmit={handleSubmitSave} className="space-y-4">
          {formError && <Alert kind="error">{formError}</Alert>}

          {/* Selector de Proveedor */}
          <div>
            <Label>Plataforma de Ingeniería</Label>
            <div className="mt-2 grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => {
                  setProvider('JIRA');
                  setIssueType('Bug');
                }}
                className={`flex flex-col items-start rounded-lg border p-3 text-left transition-all ${
                  provider === 'JIRA'
                    ? 'border-cyan-500 bg-cyan-950/20 text-white'
                    : 'border-slate-800 bg-slate-900/40 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="text-xs font-bold text-white">Atlassian Jira Software</div>
                <div className="mt-1 text-[11px] text-slate-400">Cloud REST API v3 con ADF</div>
              </button>

              <button
                type="button"
                onClick={() => {
                  setProvider('AZURE_BOARDS');
                  setIssueType('Issue');
                }}
                className={`flex flex-col items-start rounded-lg border p-3 text-left transition-all ${
                  provider === 'AZURE_BOARDS'
                    ? 'border-blue-500 bg-blue-950/20 text-white'
                    : 'border-slate-800 bg-slate-900/40 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="text-xs font-bold text-white">Azure DevOps Boards</div>
                <div className="mt-1 text-[11px] text-slate-400">REST API v7.1 con JSON Patch</div>
              </button>
            </div>
          </div>

          {/* URL de instancia */}
          <div>
            <Label htmlFor="instanceUrl">
              {provider === 'JIRA' ? 'URL de Atlassian Jira Cloud' : 'URL de Organización Azure DevOps'}
            </Label>
            <Input
              id="instanceUrl"
              placeholder={
                provider === 'JIRA'
                  ? 'https://miempresa.atlassian.net'
                  : 'https://dev.azure.com/miorganizacion'
              }
              value={instanceUrl}
              onChange={(e) => setInstanceUrl(e.target.value)}
              required
            />
            <p className="mt-1 text-[11px] text-slate-400">
              {provider === 'JIRA'
                ? 'URL base de tu sitio Cloud (ej. https://empresa.atlassian.net).'
                : 'URL base de tu organización en Azure DevOps (ej. https://dev.azure.com/nombre-org).'}
            </p>
          </div>

          {/* Proyecto y Tipo */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label htmlFor="projectKey">
                {provider === 'JIRA' ? 'Clave de Proyecto (Key)' : 'Nombre de Proyecto'}
              </Label>
              <Input
                id="projectKey"
                placeholder={provider === 'JIRA' ? 'SEC' : 'DevOps - SRE'}
                value={projectKey}
                onChange={(e) => setProjectKey(e.target.value)}
                required
              />
            </div>
            <div>
              <Label htmlFor="issueType">Tipo de Ítem por defecto</Label>
              <Input
                id="issueType"
                placeholder={provider === 'JIRA' ? 'Bug / Task' : 'Issue / Task'}
                value={issueType}
                onChange={(e) => setIssueType(e.target.value)}
              />
            </div>
          </div>

          {/* Umbral de Auto-Creación */}
          <div>
            <Label htmlFor="autoThreshold">Auto-creación tras escaneo</Label>
            <select
              id="autoThreshold"
              value={autoThreshold}
              onChange={(e) => setAutoThreshold(e.target.value as TicketingAutoCreateThreshold)}
              className="mt-1 w-full rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
            >
              <option value="DISABLED">Desactivada — Solo crear con 1 clic desde la lista de hallazgos</option>
              <option value="CRITICAL">Solo hallazgos Críticos (Critical)</option>
              <option value="HIGH">Hallazgos Críticos y Altos (Critical + High)</option>
              <option value="MEDIUM">Hallazgos Críticos, Altos y Medios (Critical + High + Medium)</option>
            </select>
            <p className="mt-1 text-[11px] text-slate-400">
              Si se activa, el worker creará automáticamente el ticket en tu plataforma cada vez que un escaneo detecte un nuevo hallazgo con severidad igual o superior al umbral.
            </p>
          </div>

          {/* Credenciales */}
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5 space-y-3">
            <div className="flex items-center justify-between text-xs font-semibold text-white">
              <span>Credenciales de Autenticación</span>
              {config?.hasStoredCredentials && (
                <span className="text-[11px] font-normal text-emerald-400 flex items-center gap-1">
                  <Check className="h-3 w-3" /> Credenciales guardadas activas
                </span>
              )}
            </div>

            {provider === 'JIRA' ? (
              <>
                <div>
                  <Label htmlFor="jiraEmail">Correo de cuenta Atlassian</Label>
                  <Input
                    id="jiraEmail"
                    type="email"
                    placeholder="ingenieria@miempresa.com"
                    value={jiraEmail}
                    onChange={(e) => setJiraEmail(e.target.value)}
                  />
                </div>
                <div>
                  <Label htmlFor="jiraToken">Atlassian API Token</Label>
                  <Input
                    id="jiraToken"
                    type="password"
                    placeholder={config?.hasStoredCredentials ? '•••••••••••••••••••• (dejar en blanco para conservar)' : 'Genera tu API Token en id.atlassian.com'}
                    value={jiraToken}
                    onChange={(e) => setJiraToken(e.target.value)}
                  />
                  <div className="mt-1 flex items-center justify-between text-[11px] text-slate-400">
                    <span>Requiere permisos de creación y lectura de issues.</span>
                    <a
                      href="https://id.atlassian.com/manage-profile/security/api-tokens"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyan-400 hover:underline flex items-center gap-0.5"
                    >
                      Generar Token <ExternalLink className="h-2.5 w-2.5" />
                    </a>
                  </div>
                </div>
              </>
            ) : (
              <div>
                <Label htmlFor="azurePat">Azure DevOps Personal Access Token (PAT)</Label>
                <Input
                  id="azurePat"
                  type="password"
                  placeholder={config?.hasStoredCredentials ? '•••••••••••••••••••• (dejar en blanco para conservar)' : 'PAT con alcance Work Items (Read & Write)'}
                  value={azurePat}
                  onChange={(e) => setAzurePat(e.target.value)}
                />
                <div className="mt-1 flex items-center justify-between text-[11px] text-slate-400">
                  <span>Alcance mínimo: Work Items (Read & Write).</span>
                  <a
                    href="https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:underline flex items-center gap-0.5"
                  >
                    Guía PAT <ExternalLink className="h-2.5 w-2.5" />
                  </a>
                </div>
              </div>
            )}
          </div>

          {/* Test Feedback dentro del modal */}
          {testResult && (
            <Alert kind={testResult.ok ? 'success' : 'error'}>
              <div className="text-xs">
                {testResult.ok ? (
                  <span>
                    ✓ Conexión válida con el proyecto <strong>{testResult.projectName || testResult.projectKey}</strong>.
                  </span>
                ) : (
                  <span>✕ {testResult.error}</span>
                )}
              </div>
            </Alert>
          )}

          {/* Botones de acción del modal */}
          <div className="flex items-center justify-between pt-2">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={handleTestModal}
              disabled={testMutation.isPending}
            >
              <RefreshCw className={`mr-1.5 h-3.5 w-3.5 ${testMutation.isPending ? 'animate-spin' : ''}`} />
              Probar Credenciales
            </Button>

            <div className="flex items-center gap-2">
              <Button type="button" variant="secondary" size="sm" onClick={() => setModalOpen(false)}>
                Cancelar
              </Button>
              <Button type="submit" size="sm" disabled={configureMutation.isPending}>
                {configureMutation.isPending ? 'Guardando...' : 'Guardar y Vincular'}
              </Button>
            </div>
          </div>
        </form>
      </Modal>

      {/* Confirmar Desvinculación */}
      <Modal
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        title="Desvincular Integración de Ticketing"
      >
        <div className="space-y-4">
          <p className="text-sm text-slate-300">
            ¿Estás seguro de que deseas desvincular la integración con{' '}
            <strong className="text-white">
              {config?.provider === 'JIRA' ? 'Jira Software' : 'Azure Boards'}
            </strong>
            ? Las credenciales almacenadas serán eliminadas. Los tickets previamente creados en tu plataforma seguirán existiendo intactos.
          </p>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" size="sm" onClick={() => setConfirmDelete(false)}>
              Cancelar
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={handleDelete}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? 'Desvinculando...' : 'Confirmar y Eliminar'}
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
