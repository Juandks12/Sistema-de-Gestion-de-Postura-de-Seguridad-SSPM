import { AlertTriangle, Trash2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Input, Label } from '@/components/ui/Field';
import { Modal } from '@/components/ui/Modal';
import { useDeleteAsset } from '@/hooks/queries';
import { ApiError } from '@/lib/api';

export interface DeleteAssetTarget {
  id: string;
  value: string;
  name?: string | null;
  type?: string;
}

export function DeleteAssetModal({
  open,
  onClose,
  asset,
  onDeleted,
}: {
  open: boolean;
  onClose: () => void;
  asset: DeleteAssetTarget | null;
  onDeleted?: (assetLabel: string) => void;
}) {
  const deleteMutation = useDeleteAsset();
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);

  if (!asset) return null;

  const label = asset.name ? `${asset.name} (${asset.value})` : asset.value;

  const handleClose = () => {
    if (deleteMutation.isPending) return;
    setReason('');
    setError(null);
    onClose();
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await deleteMutation.mutateAsync({
        id: asset.id,
        reason: reason.trim() || undefined,
      });
      setReason('');
      onClose();
      onDeleted?.(label);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : 'No se pudo eliminar el activo. Comprueba los permisos de administrador.',
      );
    }
  };

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title="Eliminar activo"
      footer={
        <>
          <Button variant="secondary" onClick={handleClose} disabled={deleteMutation.isPending}>
            Cancelar
          </Button>
          <Button
            variant="danger"
            icon={<Trash2 className="size-4" />}
            onClick={handleSubmit}
            loading={deleteMutation.isPending}
          >
            Confirmar eliminación
          </Button>
        </>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {error ? <Alert kind="error">{error}</Alert> : null}

        <div className="flex items-start gap-3 rounded-lg border border-warning/30 bg-warning/10 p-3.5 text-xs text-ink-2">
          <AlertTriangle className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden />
          <div className="space-y-1.5">
            <p className="font-medium text-ink">
              ¿Estás seguro de que deseas eliminar <strong className="text-ink">{label}</strong>?
            </p>
            <p>
              El activo dejará de figurar en el inventario activo y se recalculará el Security Score de la organización.
            </p>
            <p className="text-muted">
              <strong>Auditoría inmutable:</strong> Quedará registrado en el historial de auditoría (RNF-06) que el activo estuvo presente, junto con el balance de todas sus acciones, escaneos realizados y hallazgos históricos.
            </p>
          </div>
        </div>

        <div>
          <Label htmlFor="del-reason">
            Motivo o justificación de la baja <span className="text-muted text-xs font-normal">(opcional)</span>
          </Label>
          <Input
            id="del-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Ej. Servidor desmantelado, migración a Kubernetes o cambio de IP"
            disabled={deleteMutation.isPending}
            maxLength={500}
          />
          <p className="mt-1 text-[11px] text-muted">
            Este motivo se guardará en el registro de auditoría de tu organización.
          </p>
        </div>
      </form>
    </Modal>
  );
}
