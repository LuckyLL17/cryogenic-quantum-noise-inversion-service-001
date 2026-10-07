import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { fileURLToPath } from 'node:url';
import { DomainError } from '../domain/errors.ts';
import { analyzeExperiment } from '../application/analysis-service.ts';
import { cancel, findAuditRecordId, get, setAuditStore, submit } from '../application/job-store.ts';
import { AuditStore } from '../application/audit-store.ts';
import { ReplayService } from '../application/replay.ts';
import type { AuditKind, ReplayOptions } from '../domain/audit/types.ts';

const MAX_BODY_BYTES = 12 * 1024 * 1024;
async function readJson(request: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of request) { const part = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); size += part.length; if (size > MAX_BODY_BYTES) throw new DomainError('REQUEST_TOO_LARGE', 'Request body exceeds 12 MiB', 413); chunks.push(part); }
  if (!size) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new DomainError('INVALID_JSON', 'Request body must be valid JSON', 400); }
}
function send(response: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
  response.end(JSON.stringify(body));
}

export type ServerDeps = { auditStore?: AuditStore };

export function createServer(deps: ServerDeps = {}) {
  const auditStore = deps.auditStore ?? new AuditStore({ dir: process.env.AUDIT_STORE_DIR ?? '.audit-store' });
  setAuditStore(auditStore);
  const replays = new ReplayService(auditStore);

  return createHttpServer(async (req, response) => {
    try {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');

      if (req.method === 'GET' && url.pathname === '/health') return send(response, 200, { status: 'ok', service: 'cryogenic-quantum-noise-inversion-service' });

      // Preview: response body unchanged; evidence is sealed and linked via header.
      if (req.method === 'POST' && url.pathname === '/v1/experiments/preview') {
        const input = await readJson(req);
        try {
          const result = analyzeExperiment(input);
          const record = await auditStore.sealSuccess('preview', input, result);
          return send(response, 200, result, { 'x-audit-record-id': record.recordId });
        } catch (error) {
          // Failed previews are sealed too, so the rejected input is replayable.
          const domain = error instanceof DomainError ? error : new DomainError('INTERNAL_ERROR', error instanceof Error ? error.message : 'Unknown error', 500);
          const record = await auditStore.sealFailure('preview', input, { code: domain.code, message: domain.message });
          return send(response, domain.status, { error: { code: domain.code, message: domain.message, details: domain.details } }, { 'x-audit-record-id': record.recordId });
        }
      }

      if (req.method === 'POST' && url.pathname === '/v1/analyses') {
        const input = await readJson(req);
        const accepted = submit(input, req.headers['idempotency-key']?.toString());
        return send(response, 202, accepted);
      }

      const analysisMatch = url.pathname.match(/^\/v1\/analyses\/([^/]+)(?:\/(cancel))?$/);
      if (analysisMatch && req.method === 'GET' && !analysisMatch[2]) {
        const body = get(analysisMatch[1]);
        const recordId = findAuditRecordId(analysisMatch[1]);
        return send(response, 200, body, recordId ? { 'x-audit-record-id': recordId } : {});
      }
      if (analysisMatch && req.method === 'POST' && analysisMatch[2] === 'cancel') return send(response, 200, cancel(analysisMatch[1]));

      // Replay a sealed evidence record.
      if (req.method === 'POST' && url.pathname.match(/^\/v1\/audit\/records\/([^/]+)\/replay$/)) {
        const recordId = url.pathname.split('/')[4];
        const body = await readJson(req);
        const report = await replays.replay(recordId, parseReplayOptions(body));
        const status = report.status === 'not-found' ? 404 : 200;
        return send(response, status, report);
      }

      if (req.method === 'GET' && url.pathname.match(/^\/v1\/audit\/records\/[^/]+$/)) {
        const recordId = url.pathname.split('/')[4];
        const located = auditStore.locate(recordId);
        if (!located.exists || located.state === 'not-found') {
          return send(response, 404, { error: { code: 'AUDIT_RECORD_NOT_FOUND', message: 'Audit record was not found' } });
        }
        if (!located.record) {
          // Partial write / quarantined id without a readable body.
          return send(response, 422, { error: { code: located.state.toUpperCase(), message: located.reason ?? 'Evidence record is not usable', details: { recordId, state: located.state } } });
        }
        return send(response, 200, auditStore.getHead(located.record));
      }

      if (req.method === 'GET' && url.pathname === '/v1/audit/records') {
        const kind = url.searchParams.get('kind') as AuditKind | null;
        const jobId = url.searchParams.get('jobId');
        const experimentId = url.searchParams.get('experimentId');
        return send(response, 200, { records: auditStore.list({ ...(kind ? { kind } : {}), ...(jobId ? { jobId } : {}), ...(experimentId ? { experimentId } : {}) }) });
      }

      if (req.method === 'GET' && url.pathname === '/v1/audit/health') return send(response, 200, auditStore.health());

      return send(response, 404, { error: { code: 'NOT_FOUND', message: 'Unknown endpoint' } });
    } catch (error) {
      const domain = error instanceof DomainError ? error : new DomainError('INTERNAL_ERROR', error instanceof Error ? error.message : 'Unknown error', 500);
      return send(response, domain.status, { error: { code: domain.code, message: domain.message, details: domain.details } });
    }
  });
}

function parseReplayOptions(body: any): ReplayOptions {
  if (!body || typeof body !== 'object') return {};
  const options: ReplayOptions = {};
  if (body.calibration) {
    if (body.calibration.mode === 'sealed') options.calibration = { mode: 'sealed' };
    else if (body.calibration.mode === 'registry') {
      if (!Array.isArray(body.calibration.profiles)) throw new DomainError('INVALID_REPLAY_OPTIONS', 'Registry replay requires a calibration profiles array', 422);
      options.calibration = { mode: 'registry', profiles: body.calibration.profiles };
    } else throw new DomainError('INVALID_REPLAY_OPTIONS', 'calibration.mode must be "sealed" or "registry"', 422);
  }
  if (body.tolerance !== undefined) {
    if (typeof body.tolerance !== 'object') throw new DomainError('INVALID_REPLAY_OPTIONS', 'tolerance must be an object', 422);
    options.tolerance = {};
    if (body.tolerance.absolute !== undefined) options.tolerance.absolute = Number(body.tolerance.absolute);
    if (body.tolerance.relative !== undefined) options.tolerance.relative = Number(body.tolerance.relative);
  }
  return options;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const port = Number(process.env.PORT ?? 4387);
  createServer().listen(port, '127.0.0.1', () => console.log('quantum analysis service listening on http://127.0.0.1:%d', port));
}
