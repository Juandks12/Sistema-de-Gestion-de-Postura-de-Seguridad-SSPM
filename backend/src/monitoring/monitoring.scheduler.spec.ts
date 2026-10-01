import { MonitoringFrequency } from '@prisma/client';
import { nextRunAt, SCHEDULE_SLACK_MS } from './monitoring.scheduler';

describe('nextRunAt', () => {
  const now = new Date('2026-09-26T12:00:00Z');
  const day = 24 * 60 * 60 * 1000;

  it('sin monitoreo no hay próxima ejecución', () => {
    expect(nextRunAt(now, MonitoringFrequency.OFF, now)).toBeNull();
  });

  it('un activo nunca auditado por el monitoreo está vencido ya', () => {
    expect(nextRunAt(null, MonitoringFrequency.DAILY, now)).toEqual(now);
  });

  it('suma el periodo menos el margen del planificador', () => {
    expect(nextRunAt(now, MonitoringFrequency.DAILY, now)!.getTime()).toBe(now.getTime() + day - SCHEDULE_SLACK_MS);
    expect(nextRunAt(now, MonitoringFrequency.WEEKLY, now)!.getTime()).toBe(now.getTime() + 7 * day - SCHEDULE_SLACK_MS);
  });
});
