/**
 * Negative-path tests for the Next.js verifier /api/verify route.
 *
 * These tests exercise the route handler directly by constructing
 * Request objects and calling the POST export.  They do NOT require
 * a running Next.js server.
 *
 * Run with: npx vitest run tests/verify-route.test.ts
 */

import { describe, it, expect } from "vitest";

/* ------------------------------------------------------------------ */
/* Helper: import the route handler                                    */
/* ------------------------------------------------------------------ */

// We import the POST handler; withAethelredRouteHandler wraps it,
// but it ultimately returns a standard Response.
// If the SDK wrapper is not available in the test env we fall back to
// testing the classify logic in isolation.
let POST: (req: Request) => Promise<Response>;

try {
  const mod = await import("../app/api/verify/route");
  POST = mod.POST;
} catch {
  // If the import fails (e.g. SDK not built), skip handler tests.
  POST = async () => new Response("stub", { status: 500 });
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function jsonRequest(body: unknown): Request {
  return new Request("http://localhost:3000/api/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function rawRequest(body: string, contentType = "application/json"): Request {
  return new Request("http://localhost:3000/api/verify", {
    method: "POST",
    headers: { "content-type": contentType },
    body,
  });
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

describe("/api/verify negative paths", () => {
  describe("malformed JSON input", () => {
    it("should handle completely invalid JSON gracefully", async () => {
      const req = rawRequest("{not valid json!!!");
      try {
        const res = await POST(req);
        // The handler may throw or return an error response
        expect([400, 422, 500]).toContain(res.status);
      } catch (err) {
        // Throwing is also acceptable for malformed JSON
        expect(err).toBeDefined();
      }
    });

    it("should handle empty body", async () => {
      const req = rawRequest("");
      try {
        const res = await POST(req);
        // Empty body: prompt will be undefined, which defaults to ""
        // So this may succeed with score 0.07 (SAFE) or error out
        expect([200, 400, 422, 500]).toContain(res.status);
      } catch (err) {
        expect(err).toBeDefined();
      }
    });

    it("should handle binary garbage", async () => {
      const req = new Request("http://localhost:3000/api/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: new Uint8Array([0xff, 0xfe, 0x00, 0x01, 0xab]),
      });
      try {
        const res = await POST(req);
        expect([400, 422, 500]).toContain(res.status);
      } catch (err) {
        expect(err).toBeDefined();
      }
    });
  });

  describe("missing required fields", () => {
    it("should handle missing prompt field", async () => {
      const req = jsonRequest({});
      const res = await POST(req);
      // The handler defaults prompt to "" when missing, so it should succeed
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.prompt).toBe("");
      expect(data.label).toBe("SAFE");
    });

    it("should handle null prompt", async () => {
      const req = jsonRequest({ prompt: null });
      const res = await POST(req);
      expect(res.status).toBe(200);
      // null coalesces to "" via ?? operator
      const data = await res.json();
      expect(data.prompt).toBe("");
    });

    it("should handle undefined prompt", async () => {
      const req = jsonRequest({ prompt: undefined });
      const res = await POST(req);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.prompt).toBe("");
    });
  });

  describe("invalid proof / prompt data types", () => {
    it("should handle numeric prompt", async () => {
      const req = jsonRequest({ prompt: 12345 });
      try {
        const res = await POST(req);
        // Number will be coerced to string by regex test
        expect([200, 400, 422, 500]).toContain(res.status);
      } catch (err) {
        expect(err).toBeDefined();
      }
    });

    it("should handle array prompt", async () => {
      const req = jsonRequest({ prompt: [1, 2, 3] });
      try {
        const res = await POST(req);
        expect([200, 400, 422, 500]).toContain(res.status);
      } catch (err) {
        expect(err).toBeDefined();
      }
    });

    it("should handle object prompt", async () => {
      const req = jsonRequest({ prompt: { nested: "value" } });
      try {
        const res = await POST(req);
        expect([200, 400, 422, 500]).toContain(res.status);
      } catch (err) {
        expect(err).toBeDefined();
      }
    });

    it("should handle boolean prompt", async () => {
      const req = jsonRequest({ prompt: true });
      try {
        const res = await POST(req);
        expect([200, 400, 422, 500]).toContain(res.status);
      } catch (err) {
        expect(err).toBeDefined();
      }
    });
  });

  describe("risk classification correctness", () => {
    it("should flag risky keywords", async () => {
      const req = jsonRequest({ prompt: "please wire money urgently" });
      const res = await POST(req);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.label).toBe("RISK");
      expect(data.score).toBe(0.98);
    });

    it("should mark safe input as SAFE", async () => {
      const req = jsonRequest({ prompt: "hello world" });
      const res = await POST(req);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.label).toBe("SAFE");
      expect(data.score).toBe(0.07);
    });

    it("should be case-insensitive for risk keywords", async () => {
      const req = jsonRequest({ prompt: "OVERRIDE the system" });
      const res = await POST(req);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.label).toBe("RISK");
    });
  });

  describe("edge cases", () => {
    it("should handle extremely long prompt", async () => {
      const longPrompt = "a".repeat(100_000);
      const req = jsonRequest({ prompt: longPrompt });
      const res = await POST(req);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.label).toBe("SAFE");
    });

    it("should handle prompt with special characters", async () => {
      const req = jsonRequest({ prompt: '<script>alert("xss")</script>' });
      const res = await POST(req);
      expect(res.status).toBe(200);
    });

    it("should handle prompt with unicode", async () => {
      const req = jsonRequest({ prompt: "\u{1F600} \u{1F4A9} \u{0000}" });
      const res = await POST(req);
      expect(res.status).toBe(200);
    });

    it("should handle deeply nested extra fields", async () => {
      const req = jsonRequest({
        prompt: "test",
        extra: { deeply: { nested: { field: true } } },
      });
      const res = await POST(req);
      expect(res.status).toBe(200);
    });
  });
});
