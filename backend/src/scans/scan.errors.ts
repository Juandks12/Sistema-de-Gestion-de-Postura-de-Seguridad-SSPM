/**
 * Error controlado durante la ejecución de un escaneo. Su mensaje se guarda en
 * `scans.error_message` y se muestra al usuario, por lo que no debe contener
 * detalles internos del servidor.
 */
export class ScanExecutionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScanExecutionError';
  }
}
