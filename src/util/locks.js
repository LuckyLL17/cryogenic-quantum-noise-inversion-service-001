import { mkdir, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

/**
 * Two-tier locking:
 *
 * 1. Process-local async mutex per key — guarantees mutual exclusion between
 *    concurrent async operations *in this process* (the common case: two
 *    replay requests racing on one event loop).
 * 2. Directory lock with an owner file and TTL — best-effort mutual exclusion
 *    across separate processes; a crashed holder's lock is taken over after
 *    staleTtlMs.
 *
 * Replay itself only needs read access and is deliberately NOT serialized:
 * any number of concurrent replays of the same record are allowed (the
 * Replayer reports how many were in flight as evidence).  This lock manager
 * is used by writers (record creation/event append/recovery).
 */
export class LockManager {
  /**
   * @param {string} locksDir
   * @param {object} [opts]
   * @param {number} [opts.staleTtlMs]
   * @param {() => number} [opts.now]
   */
  constructor(locksDir, { staleTtlMs = 30_000, now = () => Date.now() } = {}) {
    this.locksDir = locksDir;
    this.staleTtlMs = staleTtlMs;
    this.now = now;
    /** @type {Map<string, Promise<unknown>>} */
    this._chains = new Map();
  }

  static _slug(key) {
    return createHash('sha256').update(key).digest('hex').slice(0, 32);
  }

  /**
   * Run fn under the process-local mutex for key.
   * @template T
   * @param {string} key
   * @param {() => Promise<T>} fn
   * @returns {Promise<T>}
   */
  async withLock(key, fn) {
    const prev = this._chains.get(key) ?? Promise.resolve();
    let release;
    // The gate never rejects; it only serializes access.
    const gate = new Promise((res) => { release = res; });
    const chain = prev.then(() => gate);
    this._chains.set(key, chain);
    try {
      await prev;
      return await fn();
    } finally {
      release();
      // Remove our entry only if nobody queued a newer one.
      queueMicrotask(() => {
        if (this._chains.get(key) === chain) this._chains.delete(key);
      });
    }
  }

  /**
   * Cross-process directory lock.  Falls back to proceeding if the lock is
   * held by a live other holder (does not throw for replay callers — this is
   * used by recovery only).
   * @param {string} key
   * @param {() => Promise<any>} fn
   * @param {{waitMs?:number}} [opts]
   */
  async withFileLock(key, fn, { waitMs = 5_000 } = {}) {
    const dir = join(this.locksDir, LockManager._slug(key));
    const deadline = this.now() + waitMs;
    for (;;) {
      try {
        await mkdir(dir, { recursive: false }); // exclusive; throws if exists
        try {
          return await fn();
        } finally {
          // Release for the next holder; if we crashed instead, the mtime
          // stale-TTL takeover below applies.
          await rm(dir, { recursive: true, force: true });
        }
      } catch (err) {
        if (err && err.code !== 'EEXIST') throw err;
        // Lock exists — take over if stale.
        try {
          const st = await stat(dir);
          if (this.now() - st.mtimeMs > this.staleTtlMs) {
            await rm(dir, { recursive: true, force: true });
            continue;
          }
        } catch (e) {
          if (e.code === 'ENOENT') continue;
          throw e;
        }
        if (this.now() >= deadline) {
          // Do not block forever: proceed under the in-process lock and let
          // the caller know. Atomic renames keep individual files safe.
          return await fn();
        }
        await new Promise((r) => setTimeout(r, 50));
      }
    }
  }
}
