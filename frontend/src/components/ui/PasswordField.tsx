import { Check, Circle, Eye, EyeOff, Wand2 } from 'lucide-react';
import { useId, useState } from 'react';
import { cn } from '@/lib/cn';
import { PASSWORD_RULES, generatePassword } from '@/lib/password';
import { Input, Label } from './Field';

/**
 * Campo de contraseña con botón para mostrarla, generador opcional y la lista de
 * requisitos de la política, que se marcan a medida que se cumplen.
 */
export function PasswordField({
  label,
  value,
  onChange,
  autoComplete = 'new-password',
  showRules = true,
  allowGenerate = false,
  id,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  autoComplete?: string;
  showRules?: boolean;
  allowGenerate?: boolean;
  id?: string;
}) {
  const autoId = useId();
  const fieldId = id ?? autoId;
  const [visible, setVisible] = useState(false);

  return (
    <div>
      <div className="flex items-end justify-between gap-2">
        <Label htmlFor={fieldId}>{label}</Label>
        {allowGenerate ? (
          <button
            type="button"
            onClick={() => {
              onChange(generatePassword());
              setVisible(true);
            }}
            className="mb-1.5 inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline"
          >
            <Wand2 className="size-3.5" aria-hidden /> Generar
          </button>
        ) : null}
      </div>
      <div className="relative">
        <Input id={fieldId} type={visible ? 'text' : 'password'} autoComplete={autoComplete} value={value} onChange={(e) => onChange(e.target.value)} className="pr-10" required />
        <button
          type="button"
          onClick={() => setVisible((v) => !v)}
          aria-label={visible ? 'Ocultar contraseña' : 'Mostrar contraseña'}
          className="absolute inset-y-0 right-0 flex w-10 items-center justify-center text-muted hover:text-ink"
        >
          {visible ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
        </button>
      </div>
      {showRules ? (
        <ul className="mt-2 grid grid-cols-1 gap-x-4 gap-y-1 text-xs sm:grid-cols-2" aria-label="Requisitos de la contraseña">
          {PASSWORD_RULES.map((r) => {
            const ok = r.test(value);
            return (
              <li key={r.id} className={cn('flex items-center gap-1.5', ok ? 'text-good-text' : 'text-muted')}>
                {ok ? <Check className="size-3.5" aria-hidden /> : <Circle className="size-3" aria-hidden />}
                {r.label}
                <span className="sr-only">{ok ? '(cumplido)' : '(pendiente)'}</span>
              </li>
            );
          })}
        </ul>
      ) : null}
    </div>
  );
}
