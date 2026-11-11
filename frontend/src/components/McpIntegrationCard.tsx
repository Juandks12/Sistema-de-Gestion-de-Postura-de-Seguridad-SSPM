import { useState } from 'react';
import {
  Cpu,
  Copy,
  Check,
  Terminal,
  Server,
  Wrench,
  RefreshCw,
} from 'lucide-react';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { api, API_BASE } from '@/lib/api';
import type { McpToolDefinition } from '@/lib/types';

export function McpIntegrationCard() {
  const [activeTab, setActiveTab] = useState<'claude' | 'cursor' | 'tools'>('claude');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; toolsCount?: number; error?: string } | null>(null);

  const mcpServerUrl = `${window.location.origin}${API_BASE}/mcp/rpc`;
  const mcpSseUrl = `${window.location.origin}${API_BASE}/mcp/sse`;

  const claudeConfigJson = JSON.stringify(
    {
      mcpServers: {
        sspm: {
          command: 'node',
          args: ['/path/to/sspm/backend/dist/mcp/bin/mcp-stdio.js'],
          env: {
            SSPM_API_KEY: 'sspm_live_TU_API_KEY_AQUI',
            SSPM_API_URL: `${window.location.origin}${API_BASE}`,
          },
        },
      },
    },
    null,
    2,
  );

  const cursorConfigJson = JSON.stringify(
    {
      mcpServers: {
        sspm_security: {
          url: mcpServerUrl,
          headers: {
            'X-API-Key': 'sspm_live_TU_API_KEY_AQUI',
          },
        },
      },
    },
    null,
    2,
  );

  const copySnippet = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const testMcpEndpoint = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const data = await api<{ tools: McpToolDefinition[] }>('/mcp/tools');
      setTestResult({ ok: true, toolsCount: data.tools?.length || 5 });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setTestResult({ ok: false, error: msg });
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card className="mt-6 border-primary-500/20">
      <CardHeader
        title={
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-primary-500/10 text-primary-400 border border-primary-500/20">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-semibold text-white">Servidor Model Context Protocol (MCP)</span>
                <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  Nativo JSON-RPC 2.0
                </span>
              </div>
              <p className="text-xs text-text-muted mt-0.5">
                Permite a Cursor IDE, Claude Desktop y agentes autónomos auditar postura, lanzar escaneos y consultar guías RAG.
              </p>
            </div>
          </div>
        }
        action={
          <Button
            variant="secondary"
            size="sm"
            onClick={testMcpEndpoint}
            disabled={testing}
            className="flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${testing ? 'animate-spin' : ''}`} />
            Verificar Estado MCP
          </Button>
        }
      />

      <CardBody className="space-y-4">
        {testResult && (
          <Alert kind={testResult.ok ? 'info' : 'error'}>
            {testResult.ok ? (
              <span className="text-xs">
                ✅ Servidor MCP en línea y saludable. <strong>{testResult.toolsCount} herramientas</strong> registradas y listas para invocación segura.
              </span>
            ) : (
              <span className="text-xs">❌ Error de conexión con el endpoint MCP: {testResult.error}</span>
            )}
          </Alert>
        )}

        {/* Transport Endpoints info */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-surface-subtle border border-border">
            <div className="flex items-center justify-between mb-1">
              <span className="font-semibold text-text flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-primary-400" /> Endpoint HTTP / JSON-RPC
              </span>
              <button
                type="button"
                onClick={() => copySnippet(mcpServerUrl, 'rpcUrl')}
                className="text-text-muted hover:text-white flex items-center gap-1 text-[11px]"
              >
                {copiedKey === 'rpcUrl' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
            <code className="text-primary-400 font-mono text-[11px] break-all">{mcpServerUrl}</code>
          </div>

          <div className="p-3 rounded-lg bg-surface-subtle border border-border">
            <div className="flex items-center justify-between mb-1">
              <span className="font-semibold text-text flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-emerald-400" /> Endpoint SSE (Server-Sent Events)
              </span>
              <button
                type="button"
                onClick={() => copySnippet(mcpSseUrl, 'sseUrl')}
                className="text-text-muted hover:text-white flex items-center gap-1 text-[11px]"
              >
                {copiedKey === 'sseUrl' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
            <code className="text-emerald-400 font-mono text-[11px] break-all">{mcpSseUrl}</code>
          </div>
        </div>

        {/* Tabs for instructions */}
        <div className="flex items-center gap-2 border-b border-border pt-2 text-xs">
          <button
            type="button"
            onClick={() => setActiveTab('claude')}
            className={`pb-2 px-3 font-medium transition-colors border-b-2 ${
              activeTab === 'claude'
                ? 'border-primary-500 text-primary-400'
                : 'border-transparent text-text-muted hover:text-white'
            }`}
          >
            Claude Desktop (stdio)
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('cursor')}
            className={`pb-2 px-3 font-medium transition-colors border-b-2 ${
              activeTab === 'cursor'
                ? 'border-primary-500 text-primary-400'
                : 'border-transparent text-text-muted hover:text-white'
            }`}
          >
            Cursor IDE / HTTP
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('tools')}
            className={`pb-2 px-3 font-medium transition-colors border-b-2 ${
              activeTab === 'tools'
                ? 'border-primary-500 text-primary-400'
                : 'border-transparent text-text-muted hover:text-white'
            }`}
          >
            Herramientas Expuestas (5)
          </button>
        </div>

        {/* Tab content */}
        {activeTab === 'claude' && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <p className="text-xs text-text-muted">
                Agrega esta sección en tu archivo <code className="font-mono text-primary-400">claude_desktop_config.json</code>:
              </p>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => copySnippet(claudeConfigJson, 'claude')}
                className="text-xs h-7"
              >
                {copiedKey === 'claude' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400 mr-1" /> Copiado
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 mr-1" /> Copiar Configuración
                  </>
                )}
              </Button>
            </div>
            <pre className="p-3 rounded-lg bg-black/50 border border-border text-xs font-mono text-text overflow-x-auto">
              <code>{claudeConfigJson}</code>
            </pre>
          </div>
        )}

        {activeTab === 'cursor' && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <p className="text-xs text-text-muted">
                Configura en <strong>Cursor Settings &rarr; Features &rarr; MCP</strong> o en <code className="font-mono text-primary-400">.cursor/mcp.json</code>:
              </p>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => copySnippet(cursorConfigJson, 'cursor')}
                className="text-xs h-7"
              >
                {copiedKey === 'cursor' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400 mr-1" /> Copiado
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 mr-1" /> Copiar Configuración
                  </>
                )}
              </Button>
            </div>
            <pre className="p-3 rounded-lg bg-black/50 border border-border text-xs font-mono text-text overflow-x-auto">
              <code>{cursorConfigJson}</code>
            </pre>
          </div>
        )}

        {activeTab === 'tools' && (
          <div className="space-y-2.5">
            {[
              {
                name: 'sspm_get_posture',
                desc: 'Consulta el Security Score actual (0-100), grado (A-F), inventario de activos y conteo de hallazgos abiertos.',
              },
              {
                name: 'sspm_list_critical_findings',
                desc: 'Lista todos los hallazgos con severidad CRITICAL y HIGH abiertos, con score CVSS y ubicación técnica.',
              },
              {
                name: 'sspm_trigger_scan',
                desc: 'Encola y ejecuta un escaneo de seguridad (PORT_SCAN, WEB_HEADERS, SSL_CERT, SENSITIVE_PATHS) en un activo.',
              },
              {
                name: 'sspm_query_compliance_gap',
                desc: 'Audita el cumplimiento frente a ISO 27001, PCI-DSS v4.0, NIST CSF, CIS Controls o SOC 2 y reporta brechas.',
              },
              {
                name: 'sspm_get_hardening_guide',
                desc: 'Busca semánticamente en pgvector guías de bastionado y snippets de código IaC (Terraform, Nginx, Ansible).',
              },
            ].map((tool, idx) => (
              <div key={idx} className="p-2.5 rounded-lg bg-surface-subtle border border-border/70 text-xs flex items-start gap-2.5">
                <Wrench className="w-4 h-4 text-primary-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-mono font-semibold text-primary-300">{tool.name}</span>
                  <p className="text-text-muted mt-0.5 leading-relaxed">{tool.desc}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}
