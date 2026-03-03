import { createHash, randomUUID } from 'node:crypto';

import type { VerificationEnvelope, VerificationHook, VerificationOptions } from './nextjs';

export interface NextMiddlewareRequestLike {
  method?: string;
  url?: string;
  nextUrl?: { href?: string; pathname?: string; search?: string };
  headers?: Headers;
}

export type NextMiddlewareHandler<Req extends NextMiddlewareRequestLike = NextMiddlewareRequestLike, Evt = unknown> = (
  request: Req,
  event: Evt,
) => Response | Promise<Response>;

export interface NextMiddlewareVerificationOptions extends VerificationOptions {
  matcherId?: string;
}

function stableNormalize(value: unknown): unknown {
  if (value === null || value === undefined) return value ?? null;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) {
    return { __bytes__: (value as Buffer).toString('base64') };
  }
  if (value instanceof Uint8Array) {
    return { __bytes__: Buffer.from(value).toString('base64') };
  }
  if (Array.isArray(value)) {
    return value.map(stableNormalize);
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (value && typeof value === 'object') {
    const maybeSerializable = value as { toJSON?: () => unknown };
    if (typeof maybeSerializable.toJSON === 'function') {
      try {
        return stableNormalize(maybeSerializable.toJSON());
      } catch {
        // fall through
      }
    }
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = stableNormalize((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return String(value);
}

function hashPayload(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(stableNormalize(value))).digest('hex');
}

function normalizedPrefix(prefix?: string): string {
  return (prefix ?? 'x-aethelred').toLowerCase().replace(/-+$/, '');
}

function fireAndForget(hook: VerificationHook | undefined, envelope: VerificationEnvelope): void {
  if (!hook) return;
  Promise.resolve(hook(envelope)).catch(() => undefined);
}

function setHeaders(response: Response, envelope: VerificationEnvelope, prefix?: string): void {
  const p = normalizedPrefix(prefix);
  response.headers.set(`${p}-trace-id`, envelope.traceId);
  response.headers.set(`${p}-framework`, envelope.framework);
  response.headers.set(`${p}-operation`, envelope.operation);
  response.headers.set(`${p}-input-hash`, envelope.inputHash);
  response.headers.set(`${p}-output-hash`, envelope.outputHash);
  response.headers.set(`${p}-ts-ms`, String(envelope.timestampMs));
}

function requestMetadata(request: NextMiddlewareRequestLike): Record<string, unknown> {
  const url = request.nextUrl?.href ?? request.url ?? '';
  const pathname = request.nextUrl?.pathname ?? undefined;
  const search = request.nextUrl?.search ?? undefined;
  const headers = request.headers ? Object.fromEntries(request.headers.entries()) : {};
  return {
    method: request.method ?? 'GET',
    url,
    pathname,
    search,
    headers,
  };
}

export function withAethelredMiddleware<Req extends NextMiddlewareRequestLike = NextMiddlewareRequestLike, Evt = unknown>(
  handler: NextMiddlewareHandler<Req, Evt>,
  options: NextMiddlewareVerificationOptions = {},
): NextMiddlewareHandler<Req, Evt> {
  return async (request: Req, event: Evt) => {
    const inputData = requestMetadata(request);
    let response = await handler(request, event);

    if (!(response instanceof Response)) {
      response = new Response(null, { status: 204 });
    }

    let responseBody: unknown = null;
    try {
      responseBody = await response.clone().text();
    } catch {
      responseBody = { stream: true };
    }

    const envelope: VerificationEnvelope = {
      traceId: randomUUID(),
      framework: 'nextjs',
      operation: 'middleware',
      inputHash: hashPayload(inputData),
      outputHash: hashPayload({
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body: responseBody,
      }),
      timestampMs: Date.now(),
      metadata: {
        service: options.service ?? 'nextjs-middleware',
        component: options.component ?? 'middleware',
        matcherId: options.matcherId ?? null,
        statusCode: response.status,
      },
    };

    setHeaders(response, envelope, options.headerPrefix);
    fireAndForget(options.onRecord, envelope);
    return response;
  };
}

export const __internal = {
  hashPayload,
  stableNormalize,
  requestMetadata,
};
