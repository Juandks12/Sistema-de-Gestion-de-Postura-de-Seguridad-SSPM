import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { keys } from '@/hooks/queries';
import { ApiError, downloadFile, qs } from '@/lib/api';
import type { ReportType } from '@/lib/types';

const PATH: Record<ReportType, string> = { EXECUTIVE: 'executive', TECHNICAL: 'technical' };

/** Descarga un reporte PDF y refresca el historial de reportes. */
export function useReportDownload() {
  const qc = useQueryClient();
  const [busy, setBusy] = useState<ReportType | null>(null);
  const [error, setError] = useState<string | null>(null);

  const download = async (type: ReportType, assetId?: string) => {
    setBusy(type);
    setError(null);
    try {
      await downloadFile(`/reports/${PATH[type]}${qs({ assetId })}`, `sspm-reporte-${PATH[type]}.pdf`);
      void qc.invalidateQueries({ queryKey: keys.reports });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo generar el reporte.');
    } finally {
      setBusy(null);
    }
  };

  return { download, busy, error };
}
