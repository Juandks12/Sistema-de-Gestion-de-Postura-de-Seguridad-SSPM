import { FileDown } from 'lucide-react';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { useReportDownload } from '@/hooks/useReportDownload';
import type { ReportType } from '@/lib/types';

const LABEL: Record<ReportType, string> = { EXECUTIVE: 'Reporte ejecutivo', TECHNICAL: 'Reporte técnico' };

export function ReportButtons({ assetId, types = ['EXECUTIVE', 'TECHNICAL'] }: { assetId?: string; types?: ReportType[] }) {
  const { download, busy, error } = useReportDownload();
  return (
    <>
      {types.map((type) => (
        <Button
          key={type}
          variant="secondary"
          icon={<FileDown className="size-4" />}
          loading={busy === type}
          disabled={busy !== null && busy !== type}
          onClick={() => download(type, assetId)}
          title={`Descargar ${LABEL[type].toLowerCase()} en PDF`}
        >
          {LABEL[type]}
        </Button>
      ))}
      {error ? (
        <Alert kind="error" className="w-full">
          {error}
        </Alert>
      ) : null}
    </>
  );
}
