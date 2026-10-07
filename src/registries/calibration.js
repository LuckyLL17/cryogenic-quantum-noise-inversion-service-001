import { canonicalJSON, sha256Canonical, contentRef, atomicWrite } from '../util/hash.js';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * Append-only calibration registry.
 *
 * A calibration version is an immutable (calibrationId, version) -> content
 * binding.  Re-registering the SAME id+version with different content throws,
 * so a version string can never silently mean two different calibrations.
 *
 * The audit store additionally freezes every calibration used by an analysis
 * in its own content-addressed area: replay never depends on this registry
 * still containing the historical version, and any divergence between the
 * registry's current binding and the frozen copy is detectable.
 */
export class CalibrationConflictError extends Error {
  constructor(calibrationId, version) {
    super(
      `Calibration ${calibrationId}@${version} is already registered ` +
      `with different immutable content`,
    );
    this.code = 'CALIBRATION_CONFLICT';
    this.calibrationId = calibrationId;
    this.version = version;
  }
}

export class CalibrationRegistry {
  /** @param {{backingFile?:string, now?:()=>string}} [opts] */
  constructor({ backingFile, now } = {}) {
    this._backingFile = backingFile;
    this._now = now ?? (() => new Date().toISOString());
    /** @type {Map<string, any[]>} id -> entries */
    this._byId = new Map();
    /** @type {Map<string, any>} sha -> entry */
    this._bySha = new Map();
    /** @type {Map<string, string>} id -> current version */
    this._current = new Map();
    this._loaded = !backingFile;
  }

  static _key(id, version) { return `${id}@${version}`; }

  /**
   * Register an immutable calibration version.
   * @param {object} args
   * @param {string} args.calibrationId
   * @param {string} args.version
   * @param {unknown} args.payload calibration data (gains, offsets, ...)
   * @param {Record<string,string>} [args.metadata]
   */
  register({ calibrationId, version, payload, metadata = {} }) {
    const entry = {
      calibrationId,
      version,
      content: contentRef(payload),
      payload,
      metadata,
      registeredAt: this._now(),
    };
    const list = this._byId.get(calibrationId);
    if (list) {
      const existing = list.find((e) => e.version === version);
      if (existing) {
        if (existing.content.sha256 !== entry.content.sha256) {
          throw new CalibrationConflictError(calibrationId, version);
        }
        return existing; // idempotent re-registration of identical content
      }
      list.push(entry);
    } else {
      this._byId.set(calibrationId, [entry]);
    }
    this._bySha.set(entry.content.sha256, entry);
    return entry;
  }

  /** Mark a registered version as the current default for an id. */
  publish(calibrationId, version) {
    const entry = this.get(calibrationId, version);
    if (!entry) {
      throw new Error(
        `Cannot publish unknown calibration ${CalibrationRegistry._key(calibrationId, version)}`,
      );
    }
    this._current.set(calibrationId, version);
    return entry;
  }

  /** @returns {any|undefined} */
  get(calibrationId, version) {
    return this._byId.get(calibrationId)?.find((e) => e.version === version);
  }

  /** @returns {any} */
  require(calibrationId, version) {
    const e = this.get(calibrationId, version);
    if (!e) throw new Error(`Unknown calibration ${CalibrationRegistry._key(calibrationId, version)}`);
    return e;
  }

  /** @returns {any|undefined} */
  getCurrent(calibrationId) {
    const v = this._current.get(calibrationId);
    return v ? this.get(calibrationId, v) : undefined;
  }

  /** @returns {any|undefined} */
  getBySha(sha) {
    return this._bySha.get(sha);
  }

  listVersions(calibrationId) {
    return (this._byId.get(calibrationId) ?? []).map((e) => ({
      version: e.version,
      sha256: e.content.sha256,
      registeredAt: e.registeredAt,
    }));
  }

  currentVersion(calibrationId) {
    return this._current.get(calibrationId);
  }

  ids() {
    return [...this._byId.keys()];
  }

  /** Persist all bindings to the backing file (called after register/publish). */
  async persist() {
    if (!this._backingFile) return;
    const data = {
      type: 'calibration-registry',
      bindings: [...this._byId.values()].flat().map((e) => ({
        calibrationId: e.calibrationId,
        version: e.version,
        content: e.content,
        payload: e.payload,
        metadata: e.metadata,
        registeredAt: e.registeredAt,
      })),
      current: Object.fromEntries(this._current),
    };
    await atomicWrite(this._backingFile, canonicalJSON(data));
  }

  /** Load bindings from the backing file if present. */
  async load() {
    if (this._loaded || !this._backingFile) return;
    try {
      const raw = JSON.parse(await readFile(this._backingFile, 'utf8'));
      for (const b of raw.bindings ?? []) {
        const entry = {
          calibrationId: b.calibrationId,
          version: b.version,
          content: b.content,
          payload: b.payload,
          metadata: b.metadata ?? {},
          registeredAt: b.registeredAt,
        };
        if (b.content.sha256 !== sha256Canonical(b.payload)) {
          throw new Error(
            `Calibration registry backing file is inconsistent: ` +
            `${b.calibrationId}@${b.version} content hash mismatch`,
          );
        }
        const list = this._byId.get(b.calibrationId) ?? [];
        if (!list.some((e) => e.version === b.version)) list.push(entry);
        this._byId.set(b.calibrationId, list);
        this._bySha.set(b.content.sha256, entry);
      }
      for (const [id, v] of Object.entries(raw.current ?? {})) {
        if (this.get(id, v)) this._current.set(id, v);
      }
      this._loaded = true;
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      this._loaded = true;
    }
  }
}
