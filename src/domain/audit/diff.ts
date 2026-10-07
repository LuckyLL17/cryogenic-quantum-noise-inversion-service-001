import type { ChangedValue, DiffOutcome, ReplayTolerance } from './types.ts';

export const DEFAULT_TOLERANCE: ReplayTolerance = { absolute: 1e-12, relative: 1e-9 };

const MAX_REPORTED_CHANGES = 100;

function typeName(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function numbersEqual(left: number, right: number): boolean {
  // IEEE bit-equal reproduction, including -0 and NaN.
  return Object.is(left, right);
}

function withinTolerance(left: number, right: number, tolerance: ReplayTolerance): boolean {
  if (!Number.isFinite(left) || !Number.isFinite(right)) return false;
  const absoluteError = Math.abs(left - right);
  if (absoluteError <= tolerance.absolute) return true;
  const scale = Math.max(Math.abs(left), Math.abs(right), 1);
  return absoluteError / scale <= tolerance.relative;
}

function pushChange(changes: ChangedValue[], change: ChangedValue): void {
  if (changes.length < MAX_REPORTED_CHANGES) changes.push(change);
}

function compare(stored: unknown, replayed: unknown, path: string, tolerance: ReplayTolerance, changes: ChangedValue[], structuralHolder: { any: boolean }): void {
  // Both NaN (same float bit pattern intent) is considered an exact reproduction.
  if (typeof stored === 'number' && typeof replayed === 'number') {
    if (numbersEqual(stored, replayed)) return;
    const delta = Number.isFinite(stored) && Number.isFinite(replayed) ? Math.abs(stored - replayed) : null;
    if (delta !== null && withinTolerance(stored, replayed, tolerance)) {
      pushChange(changes, { path, stored, replayed, delta, kind: 'value' });
      return;
    }
    structuralHolder.any = true;
    pushChange(changes, { path, stored, replayed, delta, kind: 'value' });
    return;
  }

  if (typeName(stored) !== typeName(replayed)) {
    structuralHolder.any = true;
    pushChange(changes, { path, stored, replayed, delta: null, kind: 'structural' });
    return;
  }

  if (Array.isArray(stored) && Array.isArray(replayed)) {
    const length = Math.max(stored.length, replayed.length);
    if (stored.length !== replayed.length) {
      structuralHolder.any = true;
      pushChange(changes, { path: `${path}[length]`, stored: stored.length, replayed: replayed.length, delta: null, kind: 'structural' });
    }
    for (let index = 0; index < length; index += 1) {
      if (index >= stored.length || index >= replayed.length) {
        structuralHolder.any = true;
        pushChange(changes, { path: `${path}[${index}]`, stored: stored[index] ?? null, replayed: replayed[index] ?? null, delta: null, kind: 'structural' });
        continue;
      }
      compare(stored[index], replayed[index], `${path}[${index}]`, tolerance, changes, structuralHolder);
    }
    return;
  }

  if (stored !== null && replayed !== null && typeof stored === 'object' && typeof replayed === 'object') {
    const storedRecord = stored as Record<string, unknown>;
    const replayedRecord = replayed as Record<string, unknown>;
    const keys = new Set([...Object.keys(storedRecord), ...Object.keys(replayedRecord)]);
    for (const key of [...keys].sort()) {
      const childPath = path ? `${path}.${key}` : key;
      if (!(key in storedRecord) || !(key in replayedRecord)) {
        structuralHolder.any = true;
        pushChange(changes, { path: childPath, stored: storedRecord[key] ?? null, replayed: replayedRecord[key] ?? null, delta: null, kind: 'structural' });
        continue;
      }
      compare(storedRecord[key], replayedRecord[key], childPath, tolerance, changes, structuralHolder);
    }
    return;
  }

  if (stored === replayed) return;
  structuralHolder.any = true;
  pushChange(changes, { path, stored, replayed, delta: null, kind: 'structural' });
}

/**
 * Deep comparison of two deterministic result trees.
 *
 * Match levels:
 *  - exact:             bit-identical reproduction;
 *  - within-tolerance:  only floating-point leaves moved, all inside abs/rel tolerance;
 *  - different:         structural change or numeric divergence beyond tolerance.
 */
export function diffResults(stored: unknown, replayed: unknown, tolerance: ReplayTolerance): DiffOutcome {
  const changes: ChangedValue[] = [];
  const structuralHolder = { any: false };
  compare(stored, replayed, '', tolerance, changes, structuralHolder);
  if (changes.length === 0) return { match: 'exact', changes: [] };
  if (!structuralHolder.any) return { match: 'within-tolerance', changes };
  return { match: 'different', changes };
}
