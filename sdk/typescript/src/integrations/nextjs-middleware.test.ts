import { describe, expect, it, vi } from 'vitest';

import { withAethelredMiddleware } from './nextjs-middleware';

describe('integrations/nextjs-middleware', () => {
  it('adds verification headers to middleware response', async () => {
    const handler = withAethelredMiddleware(async () => new Response('ok', { status: 200 }));

    const response = await handler(new Request('https://example.test/foo?bar=1'), {});

    expect(response.headers.get('x-aethelred-trace-id')).toBeTruthy();
    expect(response.headers.get('x-aethelred-framework')).toBe('nextjs');
    expect(response.headers.get('x-aethelred-operation')).toBe('middleware');
    expect(response.headers.get('x-aethelred-input-hash')).toMatch(/^[a-f0-9]{64}$/);
    expect(response.headers.get('x-aethelred-output-hash')).toMatch(/^[a-f0-9]{64}$/);
  });

  it('invokes onRecord without affecting response path', async () => {
    const onRecord = vi.fn().mockRejectedValue(new Error('ignore me'));
    const handler = withAethelredMiddleware(async () => new Response(JSON.stringify({ ok: true })), {
      onRecord,
      headerPrefix: 'x-proof',
      matcherId: 'api/*',
    });

    const response = await handler(new Request('https://example.test/api/test', { method: 'POST' }), {});

    expect(response.status).toBe(200);
    expect(response.headers.get('x-proof-framework')).toBe('nextjs');
    expect(onRecord).toHaveBeenCalledTimes(1);
    const envelope = onRecord.mock.calls[0][0];
    expect(envelope.metadata.matcherId).toBe('api/*');
    expect(envelope.metadata.statusCode).toBe(200);
  });
});
