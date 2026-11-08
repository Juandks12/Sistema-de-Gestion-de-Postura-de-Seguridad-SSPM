import {
  AlertTriangle,
  ArrowUpRight,
  Binary,
  Bug,
  Check,
  CheckCircle2,
  Copy,
  FileCode2,
  FileSearch,
  FileWarning,
  FlaskConical,
  Globe,
  Hash,
  Link2,
  Mail,
  MailWarning,
  Network,
  Paperclip,
  PlusCircle,
  Radar,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Upload,
} from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { Alert } from '@/components/ui/Alert';
import { SeverityBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Input, Label, Select, Textarea } from '@/components/ui/Field';
import { Modal } from '@/components/ui/Modal';
import { PageHeader } from '@/components/ui/PageHeader';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import {
  useAnalyzeEmail,
  useAnalyzeFile,
  useAnalyzeUrl,
  useAssignees,
  useDashboardAssets,
  usePromoteAnalysisToFinding,
  useThreatLabAnalyses,
  useThreatLabSummary,
} from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { cn } from '@/lib/cn';
import { formatDateTime, timeAgo } from '@/lib/format';
import type {
  MalwareAnalysisItem,
  MalwareArtifactType,
  MalwareIndicator,
  MalwareVerdict,
} from '@/lib/types';

type WorkbenchTab = 'EMAIL' | 'FILE' | 'URL';

const SAMPLE_PHISHING_EML = `Return-Path: <bounce-alert@security-mailer-09.top>
Received: from mail.security-mailer-09.top (mail.security-mailer-09.top [185.220.101.42])
        by mx.empresa-comercio.co with ESMTPS id 94A8F102
        for <tesoreria@empresa-comercio.co>; Fri, 07 Nov 2026 09:14:22 -0500
Authentication-Results: mx.empresa-comercio.co;
        spf=fail (sender IP is 185.220.101.42) smtp.mailfrom=security-mailer-09.top;
        dkim=fail header.d=bancolombia.com;
        dmarc=fail action=quarantine header.from=bancolombia.com
From: "Gerencia Financiera Corporativa" <gerencia@bancolombia.com>
Reply-To: "Soporte Urgente Tesoreria" <pagos.urgentes@ejecutivo-finanzas.xyz>
To: tesoreria@empresa-comercio.co
Subject: URGENTE: Transferencia inmediata pago proveedores internacionales y bloqueo de token
Date: Fri, 07 Nov 2026 09:14:10 -0500
Message-ID: <20261107091410.99812@security-mailer-09.top>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY_991"

--BOUNDARY_991
Content-Type: text/plain; charset="UTF-8"

Estimado equipo de Tesorería,
Por instrucción confidencial de Presidencia se requiere transferencia urgente hoy antes de las 11:00 AM.
Valide su clave dinámica corporativa en el siguiente enlace seguro para evitar suspensión de la cuenta:
https://bancol0mbia-sucursal-empresas.top/login/verify-token

Adjunto el soporte de la factura pendiente de autorización.

--BOUNDARY_991
Content-Type: application/octet-stream; name="Factura_Tesoreria_Noviembre.pdf.exe"
Content-Disposition: attachment; filename="Factura_Tesoreria_Noviembre.pdf.exe"

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
--BOUNDARY_991--`;

const SAMPLE_CLEAN_EML = `Return-Path: <notificaciones@empresa-comercio.co>
Received: from mta-out-01.empresa-comercio.co (mta-out-01.empresa-comercio.co [190.85.12.14])
        by mx.empresa-comercio.co with ESMTPS id 11B4C200
        for <auditoria@empresa-comercio.co>; Fri, 07 Nov 2026 08:30:00 -0500
Authentication-Results: mx.empresa-comercio.co;
        spf=pass smtp.mailfrom=empresa-comercio.co;
        dkim=pass header.d=empresa-comercio.co;
        dmarc=pass header.from=empresa-comercio.co
From: "Seguridad Corporativa" <notificaciones@empresa-comercio.co>
To: auditoria@empresa-comercio.co
Subject: Reporte mensual de postura de seguridad programado
Date: Fri, 07 Nov 2026 08:30:00 -0500
Message-ID: <20261107083000.1120@empresa-comercio.co>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hola equipo,
El reporte mensual de postura de seguridad se ha generado correctamente en el portal interno https://portal.empresa-comercio.co/reportes.
Saludos cordiales.`;

const VERDICT_CONFIG: Record<
  MalwareVerdict,
  { label: string; badgeClass: string; borderClass: string; barClass: string; textClass: string }
> = {
  MALICIOUS: {
    label: 'MALICIOSO CONFIRMADO',
    badgeClass: 'bg-critical/15 text-critical border-critical/30',
    borderClass: 'border-critical/40 bg-critical/5',
    barClass: 'bg-critical',
    textClass: 'text-critical',
  },
  SUSPICIOUS: {
    label: 'SOSPECHOSO / RIESGO MEDIO-ALTO',
    badgeClass: 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30',
    borderClass: 'border-amber-500/40 bg-amber-500/5',
    barClass: 'bg-amber-500',
    textClass: 'text-amber-600 dark:text-amber-400',
  },
  CLEAN: {
    label: 'LIMPIO / SIN INDICADORES ADVERSOS',
    badgeClass: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30',
    borderClass: 'border-emerald-500/30 bg-emerald-500/5',
    barClass: 'bg-emerald-500',
    textClass: 'text-emerald-600 dark:text-emerald-400',
  },
};

const ARTIFACT_TYPE_LABEL: Record<MalwareArtifactType, string> = {
  EMAIL: 'Correo (.eml / MIME)',
  FILE: 'Archivo / Hash',
  URL: 'URL / Enlace',
};

async function computeSha256Hex(buffer: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

export function ThreatLabPage() {
  const { canEdit } = useAuth();
  const summaryQ = useThreatLabSummary();
  const assetsQ = useDashboardAssets();
  const assigneesQ = useAssignees();

  const [activeStation, setActiveStation] = useState<WorkbenchTab>('EMAIL');
  const [selectedAnalysis, setSelectedAnalysis] = useState<MalwareAnalysisItem | null>(null);
  const [promoteModalOpen, setPromoteModalOpen] = useState(false);

  // History filters
  const [historyType, setHistoryType] = useState<MalwareArtifactType | ''>('');
  const [historyVerdict, setHistoryVerdict] = useState<MalwareVerdict | ''>('');
  const [historySearch, setHistorySearch] = useState('');
  const [historyPage, setHistoryPage] = useState(1);

  const historyQ = useThreatLabAnalyses({
    artifactType: historyType,
    verdict: historyVerdict,
    search: historySearch,
    page: historyPage,
    pageSize: 12,
  });

  const activeAnalysis = selectedAnalysis ?? historyQ.data?.items?.[0] ?? null;

  // Station 1: Email state
  const [emailArtifactName, setEmailArtifactName] = useState('correo_sospechoso.eml');
  const [emailRawContent, setEmailRawContent] = useState('');
  const [emailAssetId, setEmailAssetId] = useState('');
  const analyzeEmailMut = useAnalyzeEmail();

  // Station 2: File / Hash state
  const [fileName, setFileName] = useState('');
  const [fileMimeType, setFileMimeType] = useState('');
  const [fileBase64, setFileBase64] = useState('');
  const [fileRawText, setFileRawText] = useState('');
  const [fileSha256, setFileSha256] = useState('');
  const [fileAssetId, setFileAssetId] = useState('');
  const [fileSizeInfo, setFileSizeInfo] = useState<number | null>(null);
  const analyzeFileMut = useAnalyzeFile();

  // Station 3: URL state
  const [targetUrl, setTargetUrl] = useState('');
  const [urlAssetId, setUrlAssetId] = useState('');
  const analyzeUrlMut = useAnalyzeUrl();

  const handleEmlFileUpload = async (file: File) => {
    setEmailArtifactName(file.name);
    const text = await file.text();
    setEmailRawContent(text.slice(0, 490_000));
  };

  const handleArtifactFileUpload = async (file: File) => {
    setFileName(file.name);
    setFileMimeType(file.type || 'application/octet-stream');
    setFileSizeInfo(file.size);
    const buffer = await file.arrayBuffer();
    const sha256Hex = await computeSha256Hex(buffer);
    setFileSha256(sha256Hex);
    // Keep up to 1.8 MB for static byte inspection
    const slice = buffer.byteLength > 1_800_000 ? buffer.slice(0, 1_800_000) : buffer;
    setFileBase64(arrayBufferToBase64(slice));
  };

  const submitEmailAnalysis = (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailRawContent.trim()) return;
    analyzeEmailMut.mutate(
      {
        rawContent: emailRawContent,
        artifactName: emailArtifactName.trim() || 'correo_analizado.eml',
        assetId: emailAssetId || undefined,
      },
      {
        onSuccess: (res) => {
          setSelectedAnalysis(res);
        },
      },
    );
  };

  const submitFileAnalysis = (e: React.FormEvent) => {
    e.preventDefault();
    if (!fileName.trim()) return;
    analyzeFileMut.mutate(
      {
        fileName: fileName.trim(),
        mimeType: fileMimeType.trim() || undefined,
        contentBase64: fileBase64 || undefined,
        rawText: fileRawText.trim() || undefined,
        sha256: fileSha256.trim() || undefined,
        assetId: fileAssetId || undefined,
      },
      {
        onSuccess: (res) => {
          setSelectedAnalysis(res);
        },
      },
    );
  };

  const submitUrlAnalysis = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;
    analyzeUrlMut.mutate(
      {
        url: targetUrl.trim(),
        assetId: urlAssetId || undefined,
      },
      {
        onSuccess: (res) => {
          setSelectedAnalysis(res);
        },
      },
    );
  };

  const handleQuickAnalyzeExtractedUrl = (extractedUrl: string) => {
    setActiveStation('URL');
    setTargetUrl(extractedUrl);
    analyzeUrlMut.mutate(
      { url: extractedUrl, assetId: activeAnalysis?.assetId ?? undefined },
      {
        onSuccess: (res) => {
          setSelectedAnalysis(res);
        },
      },
    );
  };

  const summary = summaryQ.data;

  return (
    <>
      <PageHeader
        title="Laboratorio Forense de Malware, Phishing y Amenazas"
        description="Triaje estático seguro y enriquecimiento de inteligencia de amenazas para Correos (.eml / BEC / SPF-DKIM-DMARC), Archivos sospechosos (Magic Bytes, Entropía de Shannon, Macros VBA/XLM, PDF /JS y Hashes SHA-256) y URLs de Phishing, con promoción directa al Centro Maestro de Hallazgos y GRC."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Link to="/findings?domain=threat">
              <Button variant="secondary" icon={<ShieldAlert className="size-4" />}>
                Ver Hallazgos del Laboratorio ({summary?.promotedCount ?? 0})
              </Button>
            </Link>
          </div>
        }
      />

      {/* Executive KPI Summary Strip */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Total Analizados</span>
            <FlaskConical className="size-4 text-accent" />
          </div>
          <p className="mt-1.5 text-2xl font-bold text-ink">{summary?.total ?? 0}</p>
          <p className="mt-1 text-[11px] text-muted">
            {summary?.byType.EMAIL ?? 0} Correos · {summary?.byType.FILE ?? 0} Archivos · {summary?.byType.URL ?? 0} URLs
          </p>
        </Card>

        <Card className="border-critical/30 bg-critical/5 p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-critical">Maliciosos Confirmados</span>
            <Bug className="size-4 text-critical" />
          </div>
          <p className="mt-1.5 text-2xl font-bold text-critical">{summary?.byVerdict.MALICIOUS ?? 0}</p>
          <p className="mt-1 text-[11px] text-muted">Requieren contención o bloqueo</p>
        </Card>

        <Card className="border-amber-500/30 bg-amber-500/5 p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-amber-600 dark:text-amber-400">Sospechosos</span>
            <AlertTriangle className="size-4 text-amber-500" />
          </div>
          <p className="mt-1.5 text-2xl font-bold text-amber-600 dark:text-amber-400">
            {summary?.byVerdict.SUSPICIOUS ?? 0}
          </p>
          <p className="mt-1 text-[11px] text-muted">Anomalías heurísticas detectadas</p>
        </Card>

        <Card className="border-emerald-500/30 bg-emerald-500/5 p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-emerald-600 dark:text-emerald-400">Artefactos Limpios</span>
            <CheckCircle2 className="size-4 text-emerald-500" />
          </div>
          <p className="mt-1.5 text-2xl font-bold text-emerald-600 dark:text-emerald-400">
            {summary?.byVerdict.CLEAN ?? 0}
          </p>
          <p className="mt-1 text-[11px] text-muted">Sin indicadores maliciosos</p>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Promovidos a Hallazgos</span>
            <ShieldCheck className="size-4 text-accent" />
          </div>
          <div className="mt-1.5 flex items-baseline justify-between">
            <p className="text-2xl font-bold text-ink">{summary?.promotedCount ?? 0}</p>
            <Link
              to="/findings?domain=threat"
              className="inline-flex items-center gap-0.5 text-xs font-semibold text-accent hover:underline"
            >
              Abrir GRC <ArrowUpRight className="size-3" />
            </Link>
          </div>
          <p className="mt-1 text-[11px] text-muted">Integrados a ISO 27001 / PCI-DSS</p>
        </Card>
      </div>

      {/* Main Two-Column Forensic Workbench */}
      <div className="mb-8 grid gap-6 lg:grid-cols-12">
        {/* Left Column: 3 Forensic Input Stations (5 cols) */}
        <div className="lg:col-span-5">
          <Card className="p-5">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold text-ink">Estación de Triaje Forense</h2>
                <p className="text-xs text-muted">
                  Análisis estático determinista sin ejecución de binarios (Zero-Execution Sandbox).
                </p>
              </div>
            </div>

            {/* Station Tabs */}
            <div className="mb-5 grid grid-cols-3 gap-1.5 rounded-xl bg-surface-2 p-1">
              <button
                type="button"
                onClick={() => setActiveStation('EMAIL')}
                className={cn(
                  'flex items-center justify-center gap-1.5 rounded-lg px-2.5 py-2 text-xs font-semibold transition',
                  activeStation === 'EMAIL'
                    ? 'bg-surface text-accent shadow-xs'
                    : 'text-ink-2 hover:text-ink',
                )}
              >
                <Mail className="size-3.5" />
                Correo (.eml)
              </button>
              <button
                type="button"
                onClick={() => setActiveStation('FILE')}
                className={cn(
                  'flex items-center justify-center gap-1.5 rounded-lg px-2.5 py-2 text-xs font-semibold transition',
                  activeStation === 'FILE'
                    ? 'bg-surface text-accent shadow-xs'
                    : 'text-ink-2 hover:text-ink',
                )}
              >
                <FileSearch className="size-3.5" />
                Archivo / Hash
              </button>
              <button
                type="button"
                onClick={() => setActiveStation('URL')}
                className={cn(
                  'flex items-center justify-center gap-1.5 rounded-lg px-2.5 py-2 text-xs font-semibold transition',
                  activeStation === 'URL'
                    ? 'bg-surface text-accent shadow-xs'
                    : 'text-ink-2 hover:text-ink',
                )}
              >
                <Globe className="size-3.5" />
                URL Phishing
              </button>
            </div>

            {/* STATION 1: EMAIL (.EML / MIME HEADERS) */}
            {activeStation === 'EMAIL' ? (
              <form onSubmit={submitEmailAnalysis} className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border bg-surface-2/60 px-3 py-2">
                  <span className="text-[11px] font-medium text-ink-2">Muestras rápidas de prueba:</span>
                  <div className="flex flex-wrap gap-1.5">
                    <button
                      type="button"
                      onClick={() => {
                        setEmailArtifactName('bec_suplantacion_tesoreria.eml');
                        setEmailRawContent(SAMPLE_PHISHING_EML);
                      }}
                      className="rounded border border-critical/30 bg-critical/10 px-2 py-0.5 text-[11px] font-semibold text-critical hover:bg-critical/20"
                    >
                      Muestra BEC / Phishing
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setEmailArtifactName('notificacion_corporativa_legitima.eml');
                        setEmailRawContent(SAMPLE_CLEAN_EML);
                      }}
                      className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-semibold text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/20"
                    >
                      Correo Legítimo
                    </button>
                  </div>
                </div>

                <div>
                  <Label htmlFor="eml-upload">Cargar archivo .eml / .txt o pegar cabeceras RFC 5322</Label>
                  <label
                    htmlFor="eml-upload"
                    className="mt-1 flex cursor-pointer items-center justify-center gap-2 rounded-lg border border-dashed border-border bg-surface-2/40 px-4 py-3 text-xs font-medium text-ink-2 transition hover:border-accent hover:bg-surface-2"
                  >
                    <Upload className="size-4 text-accent" />
                    <span>Seleccionar archivo .eml desde su equipo</span>
                    <input
                      id="eml-upload"
                      type="file"
                      accept=".eml,.txt,.msg,message/rfc822"
                      className="hidden"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) void handleEmlFileUpload(file);
                      }}
                    />
                  </label>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <Label htmlFor="eml-name">Identificador / Nombre del correo</Label>
                    <Input
                      id="eml-name"
                      value={emailArtifactName}
                      onChange={(e) => setEmailArtifactName(e.target.value)}
                      placeholder="ej. reporte_sospechoso.eml"
                      required
                    />
                  </div>
                  <div>
                    <Label htmlFor="eml-asset">Activo asociado (Opcional)</Label>
                    <Select
                      id="eml-asset"
                      value={emailAssetId}
                      onChange={(e) => setEmailAssetId(e.target.value)}
                    >
                      <option value="">Sin asociar aún</option>
                      {(assetsQ.data?.items ?? []).map((a) => (
                        <option key={a.id} value={a.id}>
                          {a.name ?? a.value} ({a.value})
                        </option>
                      ))}
                    </Select>
                  </div>
                </div>

                <div>
                  <Label htmlFor="eml-raw">Contenido crudo del correo (Cabeceras SMTP + Cuerpo MIME) *</Label>
                  <Textarea
                    id="eml-raw"
                    rows={9}
                    className="font-mono text-xs"
                    value={emailRawContent}
                    onChange={(e) => setEmailRawContent(e.target.value)}
                    placeholder="Pegue aquí las cabeceras Received, Authentication-Results, From, Reply-To, Subject y el cuerpo del mensaje..."
                    required
                  />
                </div>

                {analyzeEmailMut.error ? (
                  <Alert kind="error">
                    {analyzeEmailMut.error instanceof ApiError
                      ? analyzeEmailMut.error.message
                      : 'Error al analizar el correo electrónico.'}
                  </Alert>
                ) : null}

                <Button
                  type="submit"
                  variant="primary"
                  className="w-full"
                  icon={<MailWarning className="size-4" />}
                  loading={analyzeEmailMut.isPending}
                  disabled={!canEdit || !emailRawContent.trim()}
                >
                  Ejecutar Análisis Forense de Correo (.eml)
                </Button>
              </form>
            ) : null}

            {/* STATION 2: FILE & SHA-256 HASH ANALYZER */}
            {activeStation === 'FILE' ? (
              <form onSubmit={submitFileAnalysis} className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border bg-surface-2/60 px-3 py-2">
                  <span className="text-[11px] font-medium text-ink-2">Muestras rápidas de prueba:</span>
                  <div className="flex flex-wrap gap-1.5">
                    <button
                      type="button"
                      onClick={() => {
                        setFileName('Factura_Proveedores_Octubre.pdf.exe');
                        setFileMimeType('application/pdf');
                        setFileBase64(btoa('MZ\x90\x00\x03\x00\x00\x00powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA='));
                        setFileRawText('');
                        setFileSha256('');
                        setFileSizeInfo(68);
                      }}
                      className="rounded border border-critical/30 bg-critical/10 px-2 py-0.5 text-[11px] font-semibold text-critical hover:bg-critical/20"
                    >
                      Doble Extensión PE (.pdf.exe)
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setFileName('Estado_Cuenta_Macros.docm');
                        setFileMimeType('application/vnd.ms-word.document.macroEnabled.12');
                        setFileBase64('');
                        setFileRawText('vbaProject.bin AutoOpen Document_Open CreateObject("WScript.Shell") powershell.exe -nop -w hidden -enc');
                        setFileSha256('');
                        setFileSizeInfo(104);
                      }}
                      className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[11px] font-semibold text-amber-600 dark:text-amber-400 hover:bg-amber-500/20"
                    >
                      Macro VBA Maliciosa
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setFileName('eicar_test_signature.com');
                        setFileMimeType('application/x-msdos-program');
                        setFileBase64('');
                        setFileRawText('');
                        setFileSha256('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
                        setFileSizeInfo(68);
                      }}
                      className="rounded border border-purple-500/30 bg-purple-500/10 px-2 py-0.5 text-[11px] font-semibold text-purple-600 dark:text-purple-400 hover:bg-purple-500/20"
                    >
                      Hash Threat Intel (EICAR)
                    </button>
                  </div>
                </div>

                <div>
                  <Label htmlFor="artifact-file-upload">
                    Inspección de archivo local (calcula SHA-256 en el navegador + extrae Magic Bytes)
                  </Label>
                  <label
                    htmlFor="artifact-file-upload"
                    className="mt-1 flex cursor-pointer flex-col items-center justify-center gap-1 rounded-lg border border-dashed border-border bg-surface-2/40 px-4 py-3.5 text-xs font-medium text-ink-2 transition hover:border-accent hover:bg-surface-2"
                  >
                    <div className="flex items-center gap-2">
                      <Upload className="size-4 text-accent" />
                      <span>Seleccionar documento, script o binario para análisis estático</span>
                    </div>
                    <span className="text-[11px] text-muted">
                      Soporta PDF, Office (.docm/.xlsm), ejecutables (.exe/.elf), scripts (.ps1/.js/.vbs)
                    </span>
                    <input
                      id="artifact-file-upload"
                      type="file"
                      className="hidden"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) void handleArtifactFileUpload(file);
                      }}
                    />
                  </label>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <Label htmlFor="file-name">Nombre del archivo (con extensión) *</Label>
                    <Input
                      id="file-name"
                      value={fileName}
                      onChange={(e) => setFileName(e.target.value)}
                      placeholder="ej. orden_compra.pdf.exe"
                      required
                    />
                  </div>
                  <div>
                    <Label htmlFor="file-asset">Activo asociado (Opcional)</Label>
                    <Select
                      id="file-asset"
                      value={fileAssetId}
                      onChange={(e) => setFileAssetId(e.target.value)}
                    >
                      <option value="">Sin asociar aún</option>
                      {(assetsQ.data?.items ?? []).map((a) => (
                        <option key={a.id} value={a.id}>
                          {a.name ?? a.value} ({a.value})
                        </option>
                      ))}
                    </Select>
                  </div>
                </div>

                <div>
                  <Label htmlFor="file-sha256">
                    Hash SHA-256 (calculado automáticamente o ingrese un hash de 64 caracteres para consulta Threat Intel)
                  </Label>
                  <Input
                    id="file-sha256"
                    className="font-mono text-xs"
                    value={fileSha256}
                    onChange={(e) => setFileSha256(e.target.value)}
                    placeholder="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                  />
                  {fileSizeInfo !== null ? (
                    <p className="mt-1 text-[11px] text-muted">
                      Tamaño leído: {fileSizeInfo.toLocaleString()} bytes · MIME declarado: {fileMimeType || 'N/D'}
                    </p>
                  ) : null}
                </div>

                <div>
                  <Label htmlFor="file-raw-text">
                    Fragmento de script / cadenas / objetos PDF (Opcional si no subió archivo binario)
                  </Label>
                  <Textarea
                    id="file-raw-text"
                    rows={4}
                    className="font-mono text-xs"
                    value={fileRawText}
                    onChange={(e) => setFileRawText(e.target.value)}
                    placeholder="Pegue contenido de script PowerShell, JS, macros o estructura PDF (/JS, /Launch)..."
                  />
                </div>

                {analyzeFileMut.error ? (
                  <Alert kind="error">
                    {analyzeFileMut.error instanceof ApiError
                      ? analyzeFileMut.error.message
                      : 'Error al analizar el archivo o hash.'}
                  </Alert>
                ) : null}

                <Button
                  type="submit"
                  variant="primary"
                  className="w-full"
                  icon={<Binary className="size-4" />}
                  loading={analyzeFileMut.isPending}
                  disabled={!canEdit || !fileName.trim() || (!fileBase64 && !fileRawText.trim() && !fileSha256.trim())}
                >
                  Analizar Archivo / Consultar Threat Intel
                </Button>
              </form>
            ) : null}

            {/* STATION 3: SUSPICIOUS URL ANALYZER */}
            {activeStation === 'URL' ? (
              <form onSubmit={submitUrlAnalysis} className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border bg-surface-2/60 px-3 py-2">
                  <span className="text-[11px] font-medium text-ink-2">Muestras rápidas de prueba:</span>
                  <div className="flex flex-wrap gap-1.5">
                    <button
                      type="button"
                      onClick={() =>
                        setTargetUrl('https://bancol0mbia-sucursal-personas.top/login/verify-token?redirect=http://evil.xyz')
                      }
                      className="rounded border border-critical/30 bg-critical/10 px-2 py-0.5 text-[11px] font-semibold text-critical hover:bg-critical/20"
                    >
                      Phishing Bancario
                    </button>
                    <button
                      type="button"
                      onClick={() => setTargetUrl('http://185.220.101.42:8080/dropper/factura_dian_2026.exe')}
                      className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[11px] font-semibold text-amber-600 dark:text-amber-400 hover:bg-amber-500/20"
                    >
                      Entrega Payload IP (.exe)
                    </button>
                    <button
                      type="button"
                      onClick={() => setTargetUrl('https://www.bancolombia.com/personas')}
                      className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-semibold text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/20"
                    >
                      URL Oficial Limpia
                    </button>
                  </div>
                </div>

                <div>
                  <Label htmlFor="target-url">URL sospechosa a inspeccionar *</Label>
                  <Input
                    id="target-url"
                    className="font-mono text-xs"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="https://m1crosoft-office365-login.top/auth/verify"
                    required
                  />
                  <p className="mt-1 text-[11px] text-muted">
                    Evalúa suplantación de marca (Typosquatting), homógrafos Punycode (xn--), TLDs de abuso, IP literal, credenciales embebidas (@), Open Redirects y descarga directa de ejecutables.
                  </p>
                </div>

                <div>
                  <Label htmlFor="url-asset">Activo asociado (Opcional)</Label>
                  <Select
                    id="url-asset"
                    value={urlAssetId}
                    onChange={(e) => setUrlAssetId(e.target.value)}
                  >
                    <option value="">Sin asociar aún</option>
                    {(assetsQ.data?.items ?? []).map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name ?? a.value} ({a.value})
                      </option>
                    ))}
                  </Select>
                </div>

                {analyzeUrlMut.error ? (
                  <Alert kind="error">
                    {analyzeUrlMut.error instanceof ApiError
                      ? analyzeUrlMut.error.message
                      : 'Error al analizar la URL.'}
                  </Alert>
                ) : null}

                <Button
                  type="submit"
                  variant="primary"
                  className="w-full"
                  icon={<Radar className="size-4" />}
                  loading={analyzeUrlMut.isPending}
                  disabled={!canEdit || !targetUrl.trim()}
                >
                  Inspeccionar URL y Reputación Threat Intel
                </Button>
              </form>
            ) : null}
          </Card>
        </div>

        {/* Right Column: Forensic Verdict & Telemetry Deep-Dive Panel (7 cols) */}
        <div className="lg:col-span-7">
          {activeAnalysis ? (
            <ForensicVerdictPanel
              analysis={activeAnalysis}
              canEdit={canEdit}
              onOpenPromoteModal={() => setPromoteModalOpen(true)}
              onAnalyzeExtractedUrl={handleQuickAnalyzeExtractedUrl}
            />
          ) : (
            <Card className="flex h-full min-h-[420px] items-center justify-center p-8">
              <EmptyState
                icon={FlaskConical}
                title="Seleccione o ejecute un análisis forense"
                description="Utilice la estación de triaje a la izquierda para analizar un correo (.eml), un archivo/hash SHA-256 o una URL sospechosa, o seleccione un registro del historial inferior."
              />
            </Card>
          )}
        </div>
      </div>

      {/* Historical Forensic Analyses Table */}
      <Card className="p-5">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-ink">Historial Forense de la Organización</h2>
            <p className="text-xs text-muted">
              Registro auditable de todos los artefactos inspeccionados y su trazabilidad con el Centro de Hallazgos.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Select
              value={historyType}
              onChange={(e) => {
                setHistoryType(e.target.value as MalwareArtifactType | '');
                setHistoryPage(1);
              }}
              aria-label="Filtrar por tipo de artefacto"
            >
              <option value="">Todos los artefactos</option>
              <option value="EMAIL">Correos (.eml)</option>
              <option value="FILE">Archivos / Hashes</option>
              <option value="URL">URLs</option>
            </Select>
            <Select
              value={historyVerdict}
              onChange={(e) => {
                setHistoryVerdict(e.target.value as MalwareVerdict | '');
                setHistoryPage(1);
              }}
              aria-label="Filtrar por veredicto"
            >
              <option value="">Todos los veredictos</option>
              <option value="MALICIOUS">Malicioso</option>
              <option value="SUSPICIOUS">Sospechoso</option>
              <option value="CLEAN">Limpio</option>
            </Select>
            <div className="relative">
              <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted" />
              <Input
                value={historySearch}
                onChange={(e) => {
                  setHistorySearch(e.target.value);
                  setHistoryPage(1);
                }}
                placeholder="Buscar nombre o SHA-256..."
                className="pl-8 text-xs"
              />
            </div>
          </div>
        </div>

        {historyQ.isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-10" />
            <Skeleton className="h-10" />
            <Skeleton className="h-10" />
          </div>
        ) : !historyQ.data || historyQ.data.items.length === 0 ? (
          <EmptyState
            icon={FileSearch}
            title="Sin análisis registrados con estos filtros"
            description="Ejecute su primer análisis en la estación superior usando sus propios artefactos o las muestras de prueba incluidas."
          />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Artefacto</Th>
                  <Th>Tipo</Th>
                  <Th>Veredicto</Th>
                  <Th>Riesgo</Th>
                  <Th className="hidden md:table-cell">SHA-256</Th>
                  <Th className="hidden lg:table-cell">Estado GRC</Th>
                  <Th className="text-right">Fecha</Th>
                </tr>
              </thead>
              <tbody>
                {historyQ.data.items.map((item) => {
                  const isSelected = activeAnalysis?.id === item.id;
                  const vCfg = VERDICT_CONFIG[item.verdict];
                  return (
                    <tr
                      key={item.id}
                      onClick={() => setSelectedAnalysis(item)}
                      className={cn(
                        'cursor-pointer transition-colors hover:bg-surface-2',
                        isSelected && 'bg-accent/5',
                      )}
                    >
                      <Td>
                        <p className="max-w-xs truncate font-medium text-ink">{item.artifactName}</p>
                        {item.asset ? (
                          <p className="text-[11px] text-muted">
                            Activo: {item.asset.name ?? item.asset.value}
                          </p>
                        ) : null}
                      </Td>
                      <Td>
                        <span className="inline-flex items-center gap-1 rounded bg-surface-2 px-2 py-0.5 text-xs font-medium text-ink-2">
                          {item.artifactType === 'EMAIL' && <Mail className="size-3 text-accent" />}
                          {item.artifactType === 'FILE' && <FileCode2 className="size-3 text-accent" />}
                          {item.artifactType === 'URL' && <Globe className="size-3 text-accent" />}
                          {ARTIFACT_TYPE_LABEL[item.artifactType]}
                        </span>
                      </Td>
                      <Td>
                        <span
                          className={cn(
                            'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase',
                            vCfg.badgeClass,
                          )}
                        >
                          {item.verdict === 'MALICIOUS'
                            ? 'Malicioso'
                            : item.verdict === 'SUSPICIOUS'
                              ? 'Sospechoso'
                              : 'Limpio'}
                        </span>
                      </Td>
                      <Td>
                        <div className="flex items-center gap-2">
                          <span className={cn('font-mono text-xs font-bold', vCfg.textClass)}>
                            {item.riskScore}/100
                          </span>
                          <SeverityBadge severity={item.severity} compact />
                        </div>
                      </Td>
                      <Td className="hidden font-mono text-xs text-muted md:table-cell">
                        {item.sha256 ? `${item.sha256.slice(0, 14)}…` : '—'}
                      </Td>
                      <Td className="hidden lg:table-cell">
                        {item.promotedFindingId ? (
                          <Link
                            to="/findings?domain=threat"
                            onClick={(e) => e.stopPropagation()}
                            className="inline-flex items-center gap-1 rounded border border-accent/30 bg-accent/10 px-2 py-0.5 text-[11px] font-semibold text-accent hover:bg-accent/20"
                          >
                            <ShieldAlert className="size-3" /> En Hallazgos GRC
                          </Link>
                        ) : (
                          <span className="text-xs text-muted">Sólo en laboratorio</span>
                        )}
                      </Td>
                      <Td className="text-right text-xs text-muted" title={formatDateTime(item.createdAt)}>
                        {timeAgo(item.createdAt)}
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>

            {historyQ.data.meta.totalPages > 1 ? (
              <div className="mt-4 flex items-center justify-between text-xs text-muted">
                <span>
                  Página {historyQ.data.meta.page} de {historyQ.data.meta.totalPages} ({historyQ.data.meta.total} análisis)
                </span>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={historyPage <= 1}
                    onClick={() => setHistoryPage((p) => p - 1)}
                  >
                    Anterior
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={historyPage >= historyQ.data.meta.totalPages}
                    onClick={() => setHistoryPage((p) => p + 1)}
                  >
                    Siguiente
                  </Button>
                </div>
              </div>
            ) : null}
          </>
        )}
      </Card>

      {promoteModalOpen && activeAnalysis ? (
        <PromoteToFindingModal
          analysis={activeAnalysis}
          assets={assetsQ.data?.items ?? []}
          assignees={assigneesQ.data ?? []}
          onClose={() => setPromoteModalOpen(false)}
          onPromoted={(updated) => {
            setSelectedAnalysis(updated);
            setPromoteModalOpen(false);
          }}
        />
      ) : null}
    </>
  );
}

function ForensicVerdictPanel({
  analysis,
  canEdit,
  onOpenPromoteModal,
  onAnalyzeExtractedUrl,
}: {
  analysis: MalwareAnalysisItem;
  canEdit: boolean;
  onOpenPromoteModal: () => void;
  onAnalyzeExtractedUrl: (url: string) => void;
}) {
  const [copiedHash, setCopiedHash] = useState(false);
  const vCfg = VERDICT_CONFIG[analysis.verdict];
  const st = (analysis.staticAnalysis ?? {}) as Record<string, unknown>;
  const ti = (analysis.threatIntel ?? {}) as Record<string, unknown>;
  const indicators = Array.isArray(analysis.indicators) ? analysis.indicators : [];
  const recommendations = Array.isArray(analysis.recommendations) ? analysis.recommendations : [];

  const copySha256 = () => {
    if (!analysis.sha256) return;
    void navigator.clipboard.writeText(analysis.sha256);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 1800);
  };

  return (
    <Card className="space-y-5 p-5">
      {/* Verdict Header Banner */}
      <div className={cn('rounded-xl border p-4', vCfg.borderClass)}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={cn(
                  'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-bold uppercase',
                  vCfg.badgeClass,
                )}
              >
                {vCfg.label}
              </span>
              <SeverityBadge severity={analysis.severity} />
              <span className="rounded bg-surface px-2 py-0.5 text-[11px] font-medium text-ink-2">
                {ARTIFACT_TYPE_LABEL[analysis.artifactType]}
              </span>
            </div>
            <h3 className="mt-1 break-all text-base font-bold text-ink">{analysis.artifactName}</h3>
            <p className="text-xs leading-relaxed text-ink-2">{analysis.summary}</p>
          </div>

          {/* Risk Score Gauge */}
          <div className="flex flex-col items-end rounded-lg border border-border bg-surface px-3.5 py-2.5 text-right">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-muted">
              Índice de Riesgo Forense
            </span>
            <div className="flex items-baseline gap-1">
              <span className={cn('font-mono text-2xl font-extrabold', vCfg.textClass)}>
                {analysis.riskScore}
              </span>
              <span className="text-xs font-medium text-muted">/ 100</span>
            </div>
            <div className="mt-1.5 h-1.5 w-28 overflow-hidden rounded-full bg-surface-2">
              <div
                className={cn('h-full transition-all', vCfg.barClass)}
                style={{ width: `${Math.min(100, Math.max(4, analysis.riskScore))}%` }}
              />
            </div>
          </div>
        </div>

        {/* Fingerprints & Action Bar */}
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border/60 pt-3">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {analysis.sha256 ? (
              <button
                type="button"
                onClick={copySha256}
                className="inline-flex items-center gap-1.5 rounded border border-border bg-surface px-2 py-1 font-mono text-[11px] text-ink-2 hover:border-accent"
                title="Copiar SHA-256 completo"
              >
                <Hash className="size-3 text-accent" />
                <span>SHA-256: {analysis.sha256.slice(0, 20)}…</span>
                {copiedHash ? <Check className="size-3 text-emerald-500" /> : <Copy className="size-3 text-muted" />}
              </button>
            ) : null}
            {analysis.asset ? (
              <Link
                to={`/assets/${analysis.asset.id}`}
                className="inline-flex items-center gap-1 rounded border border-border bg-surface px-2 py-1 text-[11px] font-medium text-ink-2 hover:text-accent"
              >
                <Server className="size-3 text-accent" />
                {analysis.asset.name ?? analysis.asset.value}
              </Link>
            ) : null}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {analysis.promotedFindingId ? (
              <Link to="/findings?domain=threat">
                <Button size="sm" variant="secondary" icon={<ShieldCheck className="size-3.5 text-emerald-500" />}>
                  Promovido al Centro de Hallazgos GRC
                </Button>
              </Link>
            ) : canEdit ? (
              <Button
                size="sm"
                variant="primary"
                icon={<PlusCircle className="size-3.5" />}
                onClick={onOpenPromoteModal}
              >
                Promover a Hallazgo de Seguridad y GRC
              </Button>
            ) : null}
          </div>
        </div>
      </div>

      {/* Artifact-Specific Static Analysis Section */}
      {analysis.artifactType === 'EMAIL' ? (
        <EmailForensicDetails st={st} onAnalyzeExtractedUrl={onAnalyzeExtractedUrl} />
      ) : null}

      {analysis.artifactType === 'FILE' ? <FileForensicDetails st={st} ti={ti} /> : null}

      {analysis.artifactType === 'URL' ? <UrlForensicDetails st={st} ti={ti} /> : null}

      {/* Triggered Indicators & MITRE ATT&CK Mapping */}
      <div>
        <div className="mb-2.5 flex items-center justify-between">
          <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted">
            <ShieldAlert className="size-3.5 text-accent" />
            Indicadores Forenses y Técnicas MITRE ATT&amp;CK ({indicators.length})
          </h4>
        </div>

        {indicators.length === 0 ? (
          <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 text-xs text-emerald-700 dark:text-emerald-300">
            No se dispararon reglas de compromiso ni anomalías heurísticas en este artefacto.
          </div>
        ) : (
          <div className="space-y-2">
            {indicators.map((ind: MalwareIndicator, idx: number) => (
              <div
                key={`${ind.code}-${idx}`}
                className="rounded-lg border border-border bg-surface-2/50 p-3 text-xs"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={ind.severity} compact />
                    <span className="font-semibold text-ink">{ind.title}</span>
                    <span className="font-mono text-[10px] text-muted">[{ind.code}]</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    {ind.mitreTechnique ? (
                      <span className="rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-rose-600 dark:text-rose-400">
                        MITRE {ind.mitreTechnique}
                      </span>
                    ) : null}
                    {typeof ind.scoreImpact === 'number' ? (
                      <span className="rounded bg-surface px-1.5 py-0.5 font-mono text-[10px] font-bold text-ink-2">
                        +{ind.scoreImpact} pts
                      </span>
                    ) : null}
                  </div>
                </div>
                <p className="mt-1.5 text-ink-2">{ind.detail ?? ind.description}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Actionable Containment & Remediation Recommendations */}
      {recommendations.length > 0 ? (
        <div className="rounded-xl border border-border bg-surface-2/40 p-4">
          <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-ink">
            <Sparkles className="size-3.5 text-accent" />
            Plan de Contención y Remediación Recomendado
          </h4>
          <ul className="list-disc space-y-1.5 pl-4 text-xs text-ink-2">
            {recommendations.map((rec, i) => (
              <li key={i}>{rec}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </Card>
  );
}

function EmailForensicDetails({
  st,
  onAnalyzeExtractedUrl,
}: {
  st: Record<string, unknown>;
  onAnalyzeExtractedUrl: (url: string) => void;
}) {
  const auth = (st.authentication ?? {}) as Record<string, string>;
  const hops = Array.isArray(st.receivedHops)
    ? (st.receivedHops as Array<{ hop: number; fromHost: string | null; byHost: string | null; ip: string | null }>)
    : [];
  const urls = Array.isArray(st.extractedUrls)
    ? (st.extractedUrls as Array<{ url: string; domain: string | null; suspicious: boolean; reason?: string }>)
    : [];
  const attachments = Array.isArray(st.attachments)
    ? (st.attachments as Array<{
        fileName: string;
        contentType: string;
        sizeBytes: number;
        sha256: string;
        dangerousExtension: boolean;
        doubleExtension: boolean;
      }>)
    : [];
  const becKeywords = Array.isArray(st.becKeywordsMatched) ? (st.becKeywordsMatched as string[]) : [];

  const badgeForAuth = (val?: string) => {
    const v = (val ?? 'none').toLowerCase();
    if (v === 'pass') return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400';
    if (v === 'fail' || v === 'softfail') return 'border-critical/30 bg-critical/10 text-critical';
    return 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400';
  };

  return (
    <div className="space-y-4">
      {/* SPF / DKIM / DMARC Matrix & Headers */}
      <div className="rounded-xl border border-border bg-surface-2/40 p-3.5">
        <p className="mb-2.5 text-xs font-semibold uppercase tracking-wider text-muted">
          Autenticación de Correo (RFC 5322) y Alineación de Dominios
        </p>
        <div className="mb-3 grid grid-cols-3 gap-2">
          {(['spf', 'dkim', 'dmarc'] as const).map((proto) => (
            <div key={proto} className={cn('rounded-lg border p-2.5 text-center', badgeForAuth(auth[proto]))}>
              <p className="text-[10px] font-bold uppercase">{proto.toUpperCase()}</p>
              <p className="mt-0.5 font-mono text-sm font-extrabold uppercase">{auth[proto] ?? 'none'}</p>
            </div>
          ))}
        </div>

        <div className="grid gap-2 text-xs sm:grid-cols-2">
          <div className="rounded border border-border bg-surface p-2">
            <span className="text-[10px] font-semibold uppercase text-muted">From (Remitente visible)</span>
            <p className="truncate font-mono text-ink">{String(st.from ?? '—')}</p>
          </div>
          <div className="rounded border border-border bg-surface p-2">
            <span className="text-[10px] font-semibold uppercase text-muted">Reply-To (Respuesta a)</span>
            <p className="truncate font-mono text-ink">{String(st.replyTo ?? 'Igual al remitente')}</p>
          </div>
          <div className="rounded border border-border bg-surface p-2">
            <span className="text-[10px] font-semibold uppercase text-muted">Return-Path (Bounce)</span>
            <p className="truncate font-mono text-ink">{String(st.returnPath ?? '—')}</p>
          </div>
          <div className="rounded border border-border bg-surface p-2">
            <span className="text-[10px] font-semibold uppercase text-muted">Asunto (Subject)</span>
            <p className="truncate font-medium text-ink">{String(st.subject ?? '—')}</p>
          </div>
        </div>

        {becKeywords.length > 0 ? (
          <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-semibold text-amber-600 dark:text-amber-400">
              Patrones BEC / Ingeniería Social detectados:
            </span>
            {becKeywords.map((kw) => (
              <span
                key={kw}
                className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-amber-600 dark:text-amber-400"
              >
                {kw}
              </span>
            ))}
          </div>
        ) : null}
      </div>

      {/* Extracted URLs with 1-Click Pivot to URL Analyzer */}
      {urls.length > 0 ? (
        <div className="rounded-xl border border-border bg-surface-2/40 p-3.5">
          <p className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted">
            <Link2 className="size-3.5 text-accent" />
            URLs Extraídas del Cuerpo ({urls.length})
          </p>
          <div className="space-y-1.5">
            {urls.map((u, idx) => (
              <div
                key={idx}
                className="flex flex-wrap items-center justify-between gap-2 rounded border border-border bg-surface px-2.5 py-1.5 text-xs"
              >
                <div className="min-w-0 flex-1">
                  <p className="truncate font-mono text-ink">{u.url}</p>
                  {u.reason ? <p className="text-[11px] text-critical">{u.reason}</p> : null}
                </div>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => onAnalyzeExtractedUrl(u.url)}
                >
                  Analizar esta URL
                </Button>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {/* Attachments Table */}
      {attachments.length > 0 ? (
        <div className="rounded-xl border border-border bg-surface-2/40 p-3.5">
          <p className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted">
            <Paperclip className="size-3.5 text-accent" />
            Archivos Adjuntos Detectados ({attachments.length})
          </p>
          <div className="space-y-1.5">
            {attachments.map((att, idx) => (
              <div
                key={idx}
                className="flex flex-wrap items-center justify-between gap-2 rounded border border-border bg-surface px-2.5 py-2 text-xs"
              >
                <div>
                  <p className="font-mono font-semibold text-ink">{att.fileName}</p>
                  <p className="font-mono text-[11px] text-muted">
                    SHA-256: {att.sha256.slice(0, 24)}… · {att.sizeBytes} bytes
                  </p>
                </div>
                <div className="flex gap-1.5">
                  {att.doubleExtension ? (
                    <span className="rounded border border-critical/30 bg-critical/10 px-2 py-0.5 text-[10px] font-bold text-critical">
                      Doble Extensión
                    </span>
                  ) : null}
                  {att.dangerousExtension ? (
                    <span className="rounded border border-critical/30 bg-critical/10 px-2 py-0.5 text-[10px] font-bold text-critical">
                      Ejecutable Peligroso
                    </span>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {/* SMTP Received Hops */}
      {hops.length > 0 ? (
        <div className="rounded-xl border border-border bg-surface-2/40 p-3.5">
          <p className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted">
            <Network className="size-3.5 text-accent" />
            Trazabilidad de Saltos SMTP Received ({hops.length})
          </p>
          <div className="space-y-1 text-xs">
            {hops.map((h) => (
              <div key={h.hop} className="flex flex-wrap items-center gap-2 rounded bg-surface px-2.5 py-1.5 font-mono text-[11px]">
                <span className="font-bold text-accent">#{h.hop}</span>
                <span className="text-ink">de {h.fromHost ?? 'desconocido'}</span>
                {h.ip ? <span className="rounded bg-surface-2 px-1.5 py-0.5 text-ink-2">IP: {h.ip}</span> : null}
                <span className="text-muted">→ por {h.byHost ?? 'MTA'}</span>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function FileForensicDetails({
  st,
  ti,
}: {
  st: Record<string, unknown>;
  ti: Record<string, unknown>;
}) {
  const entropy = typeof st.shannonEntropy === 'number' ? st.shannonEntropy : 0;
  const macros = Array.isArray(st.macroIndicators) ? (st.macroIndicators as string[]) : [];
  const pdfActions = Array.isArray(st.pdfDangerousActions) ? (st.pdfDangerousActions as string[]) : [];
  const suspiciousStrings = Array.isArray(st.suspiciousStrings) ? (st.suspiciousStrings as string[]) : [];
  const tags = Array.isArray(ti.tags) ? (ti.tags as string[]) : [];

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-border bg-surface-2/40 p-3.5">
        <p className="mb-2.5 text-xs font-semibold uppercase tracking-wider text-muted">
          Anatomía Estática del Archivo y Entropía de Shannon
        </p>
        <div className="grid gap-2 text-xs sm:grid-cols-3">
          <div className="rounded border border-border bg-surface p-2.5">
            <span className="text-[10px] font-semibold uppercase text-muted">Extensión Declarada</span>
            <p className="mt-0.5 font-mono font-bold text-ink">.{String(st.declaredExtension || 'N/A')}</p>
            {st.doubleExtension ? (
              <span className="mt-1 inline-block rounded bg-critical/15 px-1.5 py-0.5 text-[10px] font-bold text-critical">
                Doble Extensión Detectada
              </span>
            ) : null}
          </div>
          <div className="rounded border border-border bg-surface p-2.5">
            <span className="text-[10px] font-semibold uppercase text-muted">Formato Real (Magic Bytes)</span>
            <p className="mt-0.5 font-mono font-bold text-ink">{String(st.detectedMagicFormat || 'TEXT_OR_UNKNOWN')}</p>
            {st.extensionMismatch ? (
              <span className="mt-1 inline-block rounded bg-critical/15 px-1.5 py-0.5 text-[10px] font-bold text-critical">
                Camuflaje de Cabecera
              </span>
            ) : null}
          </div>
          <div className="rounded border border-border bg-surface p-2.5">
            <span className="text-[10px] font-semibold uppercase text-muted">Entropía de Shannon</span>
            <p className="mt-0.5 font-mono font-bold text-ink">{entropy.toFixed(2)} / 8.00 bits</p>
            <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
              <div
                className={cn('h-full', entropy >= 7.2 ? 'bg-critical' : entropy >= 6.5 ? 'bg-amber-500' : 'bg-emerald-500')}
                style={{ width: `${Math.min(100, (entropy / 8) * 100)}%` }}
              />
            </div>
          </div>
        </div>

        {(macros.length > 0 || pdfActions.length > 0 || suspiciousStrings.length > 0) ? (
          <div className="mt-3 space-y-2 border-t border-border/60 pt-2.5 text-xs">
            {macros.length > 0 ? (
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-semibold text-critical">Macros VBA/XLM:</span>
                {macros.map((m) => (
                  <span key={m} className="rounded bg-critical/10 px-1.5 py-0.5 font-mono text-[11px] text-critical">
                    {m}
                  </span>
                ))}
              </div>
            ) : null}
            {pdfActions.length > 0 ? (
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-semibold text-critical">Objetos PDF Peligrosos:</span>
                {pdfActions.map((p) => (
                  <span key={p} className="rounded bg-critical/10 px-1.5 py-0.5 font-mono text-[11px] text-critical">
                    {p}
                  </span>
                ))}
              </div>
            ) : null}
            {suspiciousStrings.length > 0 ? (
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-semibold text-amber-600 dark:text-amber-400">Patrones Sospechosos:</span>
                {suspiciousStrings.map((s) => (
                  <span
                    key={s}
                    className="rounded bg-amber-500/10 px-1.5 py-0.5 font-mono text-[11px] text-amber-600 dark:text-amber-400"
                  >
                    {s}
                  </span>
                ))}
              </div>
            ) : null}
          </div>
        ) : null}
      </div>

      {/* Threat Intel Summary */}
      <div className="rounded-xl border border-border bg-surface-2/40 p-3.5 text-xs">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="font-semibold uppercase tracking-wider text-muted">
            Correlación Threat Intelligence (MalwareBazaar / ThreatFox / Firmas)
          </span>
          <span className="font-mono font-bold text-ink">
            Detecciones: {Number(ti.detectionsCount ?? 0)} / {Number(ti.totalEngines ?? 72)} motores
          </span>
        </div>
        {ti.malwareFamily ? (
          <p className="mt-1.5 font-mono text-sm font-bold text-critical">
            Familia Identificada: {String(ti.malwareFamily)} ({String(ti.signatureName ?? '')})
          </p>
        ) : (
          <p className="mt-1 text-muted">Sin coincidencia exacta en bases de hashes maliciosos conocidos.</p>
        )}
        {tags.length > 0 ? (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {tags.map((t) => (
              <span key={t} className="rounded border border-border bg-surface px-2 py-0.5 font-mono text-[10px] text-ink-2">
                #{t}
              </span>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}

function UrlForensicDetails({
  st,
  ti,
}: {
  st: Record<string, unknown>;
  ti: Record<string, unknown>;
}) {
  const keywords = Array.isArray(st.credentialHarvestingKeywords)
    ? (st.credentialHarvestingKeywords as string[])
    : [];

  return (
    <div className="rounded-xl border border-border bg-surface-2/40 p-3.5 text-xs">
      <p className="mb-2.5 font-semibold uppercase tracking-wider text-muted">
        Descomposición Estructural de URL y Reputación Anti-Phishing
      </p>
      <div className="grid gap-2 sm:grid-cols-3">
        <div className="rounded border border-border bg-surface p-2.5">
          <span className="text-[10px] font-semibold uppercase text-muted">Hostname &amp; TLD</span>
          <p className="mt-0.5 truncate font-mono font-bold text-ink">{String(st.hostname ?? '—')}</p>
          <span className="text-[11px] text-muted">TLD: .{String(st.tld ?? '')}</span>
        </div>
        <div className="rounded border border-border bg-surface p-2.5">
          <span className="text-[10px] font-semibold uppercase text-muted">Marca Suplantada</span>
          <p className="mt-0.5 font-bold text-ink">
            {st.impersonatedBrand ? (
              <span className="text-critical">{String(st.impersonatedBrand)}</span>
            ) : (
              'Ninguna detectada'
            )}
          </p>
        </div>
        <div className="rounded border border-border bg-surface p-2.5">
          <span className="text-[10px] font-semibold uppercase text-muted">Categoría Threat Intel</span>
          <p className="mt-0.5 font-mono font-bold text-ink">{String(ti.threatCategory ?? 'CLEAN')}</p>
          <span className="text-[11px] text-muted">
            Detecciones: {Number(ti.detectionsCount ?? 0)}/{Number(ti.totalEngines ?? 68)}
          </span>
        </div>
      </div>

      {keywords.length > 0 || st.openRedirectParam || st.directPayloadExtension ? (
        <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-border/60 pt-2.5">
          {keywords.map((kw) => (
            <span
              key={kw}
              className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-amber-600 dark:text-amber-400"
            >
              Keyword: {kw}
            </span>
          ))}
          {st.openRedirectParam ? (
            <span className="rounded border border-critical/30 bg-critical/10 px-2 py-0.5 font-mono text-[10px] font-bold text-critical">
              Open Redirect: ?{String(st.openRedirectParam)}=
            </span>
          ) : null}
          {st.directPayloadExtension ? (
            <span className="rounded border border-critical/30 bg-critical/10 px-2 py-0.5 font-mono text-[10px] font-bold text-critical">
              Payload Ejecutable: .{String(st.directPayloadExtension)}
            </span>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function PromoteToFindingModal({
  analysis,
  assets,
  assignees,
  onClose,
  onPromoted,
}: {
  analysis: MalwareAnalysisItem;
  assets: Array<{ id: string; name: string | null; value: string }>;
  assignees: Array<{ id: string; fullName: string; email: string }>;
  onClose: () => void;
  onPromoted: (updated: MalwareAnalysisItem) => void;
}) {
  const [assetId, setAssetId] = useState(analysis.assetId ?? assets[0]?.id ?? '');
  const [assignedToId, setAssignedToId] = useState('');
  const [customTitle, setCustomTitle] = useState(
    `Amenaza confirmada en Laboratorio (${analysis.artifactType}): ${analysis.artifactName}`.slice(0, 190),
  );
  const promoteMut = usePromoteAnalysisToFinding();

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!assetId) return;
    promoteMut.mutate(
      {
        id: analysis.id,
        assetId,
        assignedToId: assignedToId || undefined,
        customTitle: customTitle.trim() || undefined,
      },
      {
        onSuccess: (res) => {
          onPromoted(res.analysis);
        },
      },
    );
  };

  return (
    <Modal
      open
      onClose={onClose}
      title="Promover Análisis Forense al Centro Maestro de Hallazgos y GRC"
    >
      <form onSubmit={submit} className="space-y-4">
        <div className="rounded-lg border border-border bg-surface-2 p-3 text-xs">
          <p className="font-semibold text-ink">{analysis.artifactName}</p>
          <p className="mt-1 text-muted">
            Al promover este análisis, se registrará un hallazgo formal bajo la categoría{' '}
            <strong className="text-ink">Amenaza de Malware / Phishing (MALWARE_THREAT)</strong> con mapeo automático a{' '}
            <strong className="text-ink">ISO 27001 (A.8.7, A.8.23), PCI-DSS v4.0 (5.2, 5.4), NIST CSF 2.0 y CIS Controls v8</strong>, y se recalculará el Security Score del activo afectado.
          </p>
        </div>

        <div>
          <Label htmlFor="promote-asset">Activo Afectado / Asociado *</Label>
          <Select
            id="promote-asset"
            value={assetId}
            onChange={(e) => setAssetId(e.target.value)}
            required
          >
            <option value="">Seleccione un activo del inventario...</option>
            {assets.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name ?? a.value} ({a.value})
              </option>
            ))}
          </Select>
        </div>

        <div>
          <Label htmlFor="promote-title">Título del Hallazgo en el Centro Maestro</Label>
          <Input
            id="promote-title"
            value={customTitle}
            onChange={(e) => setCustomTitle(e.target.value)}
            required
          />
        </div>

        <div>
          <Label htmlFor="promote-assignee">Asignar Responsable de Contención / Remediación</Label>
          <Select
            id="promote-assignee"
            value={assignedToId}
            onChange={(e) => setAssignedToId(e.target.value)}
          >
            <option value="">Sin asignar por ahora</option>
            {assignees.map((u) => (
              <option key={u.id} value={u.id}>
                {u.fullName} ({u.email})
              </option>
            ))}
          </Select>
        </div>

        {promoteMut.error ? (
          <Alert kind="error">
            {promoteMut.error instanceof ApiError
              ? promoteMut.error.message
              : 'No fue posible promover el análisis a hallazgo.'}
          </Alert>
        ) : null}

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancelar
          </Button>
          <Button
            type="submit"
            variant="primary"
            icon={<FileWarning className="size-4" />}
            loading={promoteMut.isPending}
            disabled={!assetId}
          >
            Crear Hallazgo Formal y Mapear GRC
          </Button>
        </div>
      </form>
    </Modal>
  );
}
