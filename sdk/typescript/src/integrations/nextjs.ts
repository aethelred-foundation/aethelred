import { createHash, randomUUID } from "node:crypto";

export interface VerificationEnvelope {
  traceId: string;
  framework: string;
  operation: string;
  inputHash: string;
  outputHash: string;
  timestampMs: number;
  metadata: Record<string, unknown>;
}

export type VerificationHook = (envelope: VerificationEnvelope) => void | Promise<void>;

export interface VerificationOptions {
  onRecord?: VerificationHook;
  headerPrefix?: string;
  service?: string;
  component?: string;
}

export interface NextApiRequestLike {
  method?: string;
  url?: string;
  query?: unknown;
  body?: unknown;
  headers?: Record<string, string | string[] | undefined>;
}

export interface NextApiResponseLike {
  statusCode?: number;
  setHeader(name: string, value: string): unknown;
  json?: (body: unknown) => unknown;
  send?: (body: unknown) => unknown;
  end?: (chunk?: unknown) => unknown;
}

export type NextApiHandlerLike<
  Req extends NextApiRequestLike = NextApiRequestLike,
  Res extends NextApiResponseLike = NextApiResponseLike,
> = (req: Req, res: Res) => unknown | Promise<unknown>;

function stableNormalize(value: unknown): unknown {
  if (value === null || value === undefined) return value ?? null;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return value;
  if (typeof Buffer !== "undefined" && Buffer.isBuffer(value)) {
    return { __bytes__: (value as Buffer).toString("base64") };
  }
  if (value instanceof Uint8Array) {
    return { __bytes__: Buffer.from(value).toString("base64") };
  }
  if (Array.isArray(value)) {
    return value.map(stableNormalize);
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (value && typeof value === "object") {
    const maybeModel = value as { toJSON?: () => unknown; toString?: () => string };
    if (typeof maybeModel.toJSON === "function") {
      try {
        return stableNormalize(maybeModel.toJSON());
      } catch {
        // fall through
      }
    }
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      out[key] = stableNormalize(obj[key]);
    }
    return out;
  }
  return String(value);
}

function hashPayload(value: unknown): string {
  const canonical = JSON.stringify(stableNormalize(value));
  return createHash("sha256").update(canonical).digest("hex");
}

function normalizedPrefix(prefix?: string): string {
  return (prefix ?? "x-aethelred").toLowerCase().replace(/-+$/, "");
}

function fireAndForget(hook: VerificationHook | undefined, envelope: VerificationEnvelope): void {
  if (!hook) return;
  Promise.resolve(hook(envelope)).catch(() => {
    // Intentionally swallow to avoid impacting application response path.
  });
}

function buildEnvelope(
  inputData: unknown,
  outputData: unknown,
  metadata: Record<string, unknown>,
): VerificationEnvelope {
  return {
    traceId: randomUUID(),
    framework: "nextjs",
    operation: "api.route",
    inputHash: hashPayload(inputData),
    outputHash: hashPayload(outputData),
    timestampMs: Date.now(),
    metadata,
  };
}

function setVerificationHeaders(
  resLike: { setHeader(name: string, value: string): unknown },
  envelope: VerificationEnvelope,
  headerPrefix?: string,
): void {
  const prefix = normalizedPrefix(headerPrefix);
  resLike.setHeader(`${prefix}-trace-id`, envelope.traceId);
  resLike.setHeader(`${prefix}-framework`, envelope.framework);
  resLike.setHeader(`${prefix}-operation`, envelope.operation);
  resLike.setHeader(`${prefix}-input-hash`, envelope.inputHash);
  resLike.setHeader(`${prefix}-output-hash`, envelope.outputHash);
  resLike.setHeader(`${prefix}-ts-ms`, String(envelope.timestampMs));
}

export function withAethelredApiRoute<
  Req extends NextApiRequestLike,
  Res extends NextApiResponseLike,
>(
  handler: NextApiHandlerLike<Req, Res>,
  options: VerificationOptions = {},
): NextApiHandlerLike<Req, Res> {
  return async (req: Req, res: Res) => {
    const inputData = {
      method: req.method,
      url: req.url,
      headers: req.headers ?? {},
      query: req.query ?? null,
      body: req.body ?? null,
    };
    const baseMetadata = {
      service: options.service ?? "nextjs-api",
      component: options.component ?? "api-route",
    };

    let recorded = false;
    const originalJson = res.json?.bind(res);
    const originalSend = res.send?.bind(res);
    const originalEnd = res.end?.bind(res);

    const recordResponse = (outputData: unknown, operation = "api.route"): void => {
      if (recorded) return;
      recorded = true;
      const envelope = buildEnvelope(inputData, outputData, {
        ...baseMetadata,
        operation,
        statusCode: res.statusCode ?? 200,
      });
      setVerificationHeaders(res, envelope, options.headerPrefix);
      fireAndForget(options.onRecord, envelope);
    };

    if (originalJson) {
      res.json = ((body: unknown) => {
        recordResponse(body, "api.route.json");
        return originalJson(body);
      }) as Res["json"];
    }
    if (originalSend) {
      res.send = ((body: unknown) => {
        recordResponse(body, "api.route.send");
        return originalSend(body);
      }) as Res["send"];
    }
    if (originalEnd) {
      res.end = ((chunk?: unknown) => {
        recordResponse(chunk ?? { ended: true }, "api.route.end");
        return originalEnd(chunk);
      }) as Res["end"];
    }

    try {
      const result = await handler(req, res);
      if (!recorded && result !== undefined) {
        recordResponse(result, "api.route.return");
      }
      return result;
    } catch (error) {
      if (!recorded) {
        recordResponse(
          { error: error instanceof Error ? error.message : String(error) },
          "api.route.error",
        );
      }
      throw error;
    }
  };
}

export type AppRouteHandler<Ctx = unknown> = (request: Request, context: Ctx) => Response | Promise<Response>;

export function withAethelredRouteHandler<Ctx = unknown>(
  handler: AppRouteHandler<Ctx>,
  options: VerificationOptions = {},
): AppRouteHandler<Ctx> {
  return async (request: Request, context: Ctx) => {
    let requestBody: unknown = null;
    try {
      const clone = request.clone();
      const text = await clone.text();
      requestBody = text;
    } catch {
      requestBody = { stream: true };
    }

    const response = await handler(request, context);

    let responseBody: unknown = null;
    try {
      const clone = response.clone();
      responseBody = await clone.text();
    } catch {
      responseBody = { stream: true };
    }

    const inputData = {
      method: request.method,
      url: request.url,
      headers: Object.fromEntries(request.headers.entries()),
      body: requestBody,
    };
    const envelope: VerificationEnvelope = {
      traceId: randomUUID(),
      framework: "nextjs",
      operation: "app.route",
      inputHash: hashPayload(inputData),
      outputHash: hashPayload({
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body: responseBody,
      }),
      timestampMs: Date.now(),
      metadata: {
        service: options.service ?? "nextjs-app-route",
        component: options.component ?? "route-handler",
        statusCode: response.status,
      },
    };

    const prefix = normalizedPrefix(options.headerPrefix);
    response.headers.set(`${prefix}-trace-id`, envelope.traceId);
    response.headers.set(`${prefix}-framework`, envelope.framework);
    response.headers.set(`${prefix}-operation`, envelope.operation);
    response.headers.set(`${prefix}-input-hash`, envelope.inputHash);
    response.headers.set(`${prefix}-output-hash`, envelope.outputHash);
    response.headers.set(`${prefix}-ts-ms`, String(envelope.timestampMs));
    fireAndForget(options.onRecord, envelope);

    return response;
  };
}

export const __internal = {
  hashPayload,
  stableNormalize,
};
