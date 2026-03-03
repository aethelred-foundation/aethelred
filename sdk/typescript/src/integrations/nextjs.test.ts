import { describe, expect, it, vi } from "vitest";

import {
  __internal,
  withAethelredApiRoute,
  withAethelredRouteHandler,
  type NextApiRequestLike,
  type NextApiResponseLike,
  type VerificationEnvelope,
} from "./nextjs";

class MockRes implements NextApiResponseLike {
  statusCode = 200;
  headers = new Map<string, string>();
  payload: unknown = undefined;

  setHeader(name: string, value: string): void {
    this.headers.set(name.toLowerCase(), value);
  }

  json = (body: unknown): MockRes => {
    this.payload = body;
    return this;
  };

  send = (body: unknown): MockRes => {
    this.payload = body;
    return this;
  };

  end = (chunk?: unknown): MockRes => {
    if (chunk !== undefined) {
      this.payload = chunk;
    }
    return this;
  };
}

describe("Next.js integration wrappers", () => {
  it("wraps API route json responses and emits headers + record", async () => {
    const records: VerificationEnvelope[] = [];
    const handler = withAethelredApiRoute(
      async (_req: NextApiRequestLike, res: MockRes) => {
        return res.json?.({ ok: true, score: 0.99 });
      },
      { onRecord: (e) => void records.push(e) },
    );

    const req: NextApiRequestLike = {
      method: "POST",
      url: "/api/score",
      headers: { host: "example.test" },
      body: { input: "hello" },
      query: { model: "credit" },
    };
    const res = new MockRes();

    await handler(req, res);

    expect(res.payload).toEqual({ ok: true, score: 0.99 });
    expect(records).toHaveLength(1);
    expect(records[0].framework).toBe("nextjs");
    expect(records[0].operation).toBe("api.route");
    expect(res.headers.get("x-aethelred-input-hash")).toMatch(/^[a-f0-9]{64}$/);
    expect(res.headers.get("x-aethelred-output-hash")).toMatch(/^[a-f0-9]{64}$/);
  });

  it("records send() responses once", async () => {
    const onRecord = vi.fn();
    const handler = withAethelredApiRoute(async (_req, res: MockRes) => {
      res.statusCode = 202;
      res.send?.("accepted");
    }, { onRecord });

    await handler({ method: "POST", url: "/api/jobs", body: { job: 1 } }, new MockRes());

    expect(onRecord).toHaveBeenCalledTimes(1);
    const env = onRecord.mock.calls[0][0] as VerificationEnvelope;
    expect(env.metadata.statusCode).toBe(202);
  });

  it("records error envelopes and rethrows", async () => {
    const onRecord = vi.fn();
    const handler = withAethelredApiRoute(async () => {
      throw new Error("boom");
    }, { onRecord });

    await expect(handler({ method: "GET", url: "/api/fail" }, new MockRes())).rejects.toThrow("boom");
    expect(onRecord).toHaveBeenCalledTimes(1);
    expect((onRecord.mock.calls[0][0] as VerificationEnvelope).metadata.operation).toBe("api.route.error");
  });

  it("records returned values when handler does not use res", async () => {
    const records: VerificationEnvelope[] = [];
    const handler = withAethelredApiRoute(async () => ({ dryRun: true }), {
      onRecord: (e) => void records.push(e),
    });

    const res = new MockRes();
    const ret = await handler({ method: "GET", url: "/api/dryrun" }, res);

    expect(ret).toEqual({ dryRun: true });
    expect(records).toHaveLength(1);
    expect(records[0].metadata.operation).toBe("api.route.return");
  });

  it("wraps Next.js app route handlers and injects verification headers", async () => {
    const onRecord = vi.fn();
    const handler = withAethelredRouteHandler(
      async (request: Request) => {
        const input = await request.json();
        return new Response(JSON.stringify({ echoed: input.prompt }), {
          status: 201,
          headers: { "content-type": "application/json" },
        });
      },
      { onRecord, component: "chat-route" },
    );

    const response = await handler(
      new Request("https://example.test/api/chat", {
        method: "POST",
        body: JSON.stringify({ prompt: "hello" }),
        headers: { "content-type": "application/json" },
      }),
      {},
    );

    expect(response.status).toBe(201);
    expect(response.headers.get("x-aethelred-trace-id")).toBeTruthy();
    expect(response.headers.get("x-aethelred-output-hash")).toMatch(/^[a-f0-9]{64}$/);
    expect(onRecord).toHaveBeenCalledTimes(1);
    expect((onRecord.mock.calls[0][0] as VerificationEnvelope).metadata.component).toBe("chat-route");
  });

  it("uses stable normalization for deterministic hashes", () => {
    const a = { b: 2, a: { y: 2, x: 1 } };
    const b = { a: { x: 1, y: 2 }, b: 2 };
    expect(__internal.hashPayload(a)).toBe(__internal.hashPayload(b));
  });
});
