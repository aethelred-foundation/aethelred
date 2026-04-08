/**
 * Mock transport for Aethelred SDK offline development and testing.
 *
 * Provides a deterministic Axios adapter that returns canned responses
 * for common Aethelred API endpoints.  No network connection is required.
 *
 * @example
 * ```typescript
 * import axios from 'axios';
 * import { MockTransport } from './testing';
 *
 * const mock = new MockTransport();
 * const client = axios.create({ adapter: mock.adapter() });
 *
 * const resp = await client.get('/health');
 * console.log(resp.data); // { status: 'ok' }
 * ```
 */

import type { AxiosRequestConfig, AxiosResponse } from 'axios';

/** Shape of a single mock response entry. */
export interface MockResponse {
  status: number;
  data: Record<string, unknown>;
}

// ------------------------------------------------------------------ //
// Default mock response payloads
// ------------------------------------------------------------------ //

export const mockResponses: Map<string, MockResponse> = new Map([
  // Health check
  ['GET /health', {
    status: 200,
    data: { status: 'ok' },
  }],

  // Node information
  ['GET /cosmos/base/tendermint/v1beta1/node_info', {
    status: 200,
    data: {
      default_node_info: {
        protocol_version: { p2p: '8', block: '11', app: '0' },
        default_node_id: 'mock-node-0000000000000000000000000000000000000000',
        listen_addr: 'tcp://0.0.0.0:26656',
        network: 'aethelred-mock-1',
        version: '0.37.0',
        channels: '40202122233038606100',
        moniker: 'mock-validator',
        other: { tx_index: 'on', rpc_address: 'tcp://127.0.0.1:26657' },
      },
      application_version: {
        name: 'aethelred',
        app_name: 'aethelredd',
        version: '1.0.0-mock',
        git_commit: '0000000000000000000000000000000000000000',
        go_version: 'go1.22.0',
        cosmos_sdk_version: 'v0.50.0',
      },
    },
  }],

  // Latest block
  ['GET /cosmos/base/tendermint/v1beta1/blocks/latest', {
    status: 200,
    data: {
      block_id: {
        hash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        part_set_header: { total: 1, hash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' },
      },
      block: {
        header: {
          version: { block: '11' },
          chain_id: 'aethelred-mock-1',
          height: '1000',
          time: '2025-01-01T00:00:00.000000000Z',
          last_block_id: { hash: '', part_set_header: { total: 0, hash: '' } },
          proposer_address: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        },
        data: { txs: [] },
      },
    },
  }],

  // Submit a PoUW job
  ['POST /aethelred/pouw/v1/jobs', {
    status: 200,
    data: {
      job_id: 'mock-job-001',
      status: 'SUBMITTED',
      created_at: '2025-01-01T00:00:00Z',
      tx_hash: '0'.repeat(64),
    },
  }],

  // Retrieve job details
  ['GET /aethelred/pouw/v1/jobs/mock-job-001', {
    status: 200,
    data: {
      job: {
        job_id: 'mock-job-001',
        status: 'COMPLETED',
        model_cid: 'QmMockModelCID000000000000000000000000000000',
        result_cid: 'QmMockResultCID00000000000000000000000000000',
        creator: 'aethelred1mockaddress000000000000000000000000',
        created_at: '2025-01-01T00:00:00Z',
        completed_at: '2025-01-01T00:01:00Z',
      },
    },
  }],

  // Retrieve seal details
  ['GET /aethelred/seal/v1/seals/mock-seal-001', {
    status: 200,
    data: {
      seal: {
        seal_id: 'mock-seal-001',
        job_id: 'mock-job-001',
        attestation: '0'.repeat(128),
        validator: 'aethelredvaloper1mockvalidator0000000000000000000',
        created_at: '2025-01-01T00:01:30Z',
      },
    },
  }],

  // Verify a seal
  ['POST /aethelred/seal/v1/seals/mock-seal-001/verify', {
    status: 200,
    data: {
      valid: true,
      seal_id: 'mock-seal-001',
      verified_at: '2025-01-01T00:02:00Z',
    },
  }],
]);

// ------------------------------------------------------------------ //
// Pattern-based route matching
// ------------------------------------------------------------------ //

interface RoutePattern {
  method: string;
  pattern: RegExp;
  buildResponse: (match: RegExpMatchArray) => MockResponse;
}

const routePatterns: RoutePattern[] = [
  // GET /aethelred/pouw/v1/jobs/:jobId
  {
    method: 'GET',
    pattern: /^\/aethelred\/pouw\/v1\/jobs\/([^/]+)$/,
    buildResponse: (match) => ({
      status: 200,
      data: {
        job: {
          job_id: match[1],
          status: 'COMPLETED',
          model_cid: 'QmMockModelCID000000000000000000000000000000',
          result_cid: 'QmMockResultCID00000000000000000000000000000',
          creator: 'aethelred1mockaddress000000000000000000000000',
          created_at: '2025-01-01T00:00:00Z',
          completed_at: '2025-01-01T00:01:00Z',
        },
      },
    }),
  },
  // GET /aethelred/seal/v1/seals/:sealId
  {
    method: 'GET',
    pattern: /^\/aethelred\/seal\/v1\/seals\/([^/]+)$/,
    buildResponse: (match) => ({
      status: 200,
      data: {
        seal: {
          seal_id: match[1],
          job_id: 'mock-job-001',
          attestation: '0'.repeat(128),
          validator: 'aethelredvaloper1mockvalidator0000000000000000000',
          created_at: '2025-01-01T00:01:30Z',
        },
      },
    }),
  },
  // POST /aethelred/seal/v1/seals/:sealId/verify
  {
    method: 'POST',
    pattern: /^\/aethelred\/seal\/v1\/seals\/([^/]+)\/verify$/,
    buildResponse: (match) => ({
      status: 200,
      data: {
        valid: true,
        seal_id: match[1],
        verified_at: '2025-01-01T00:02:00Z',
      },
    }),
  },
];

function matchRoute(method: string, path: string): MockResponse | null {
  for (const route of routePatterns) {
    if (route.method !== method) continue;
    const match = path.match(route.pattern);
    if (match) return route.buildResponse(match);
  }
  return null;
}

// ------------------------------------------------------------------ //
// MockTransport
// ------------------------------------------------------------------ //

/**
 * A mock Axios adapter that serves deterministic responses for
 * Aethelred API endpoints.
 *
 * Responses are looked up by ``METHOD /path`` in {@link mockResponses}.
 * If no exact match is found, pattern-based routes are tried.
 * Customise by mutating {@link mockResponses} before creating the
 * transport, or by passing a custom map to the constructor.
 */
export class MockTransport {
  private readonly responses: Map<string, MockResponse>;

  constructor(responses?: Map<string, MockResponse>) {
    this.responses = responses ?? mockResponses;
  }

  /**
   * Returns an Axios adapter function suitable for ``axios.create({ adapter })``.
   */
  adapter(): (config: AxiosRequestConfig) => Promise<AxiosResponse> {
    return (config: AxiosRequestConfig) => this.handleRequest(config);
  }

  /**
   * Process a single request and return a deterministic response.
   */
  async handleRequest(config: AxiosRequestConfig): Promise<AxiosResponse> {
    const method = (config.method ?? 'GET').toUpperCase();
    const url = new URL(config.url ?? '/', config.baseURL ?? 'http://127.0.0.1:26657');
    const path = url.pathname;

    // 1. Exact match
    const key = `${method} ${path}`;
    let mockResp = this.responses.get(key) ?? null;

    // 2. Pattern-based fallback
    if (!mockResp) {
      mockResp = matchRoute(method, path);
    }

    // 3. Not found
    if (!mockResp) {
      return {
        data: { error: `mock: no response configured for ${method} ${path}` },
        status: 404,
        statusText: 'Not Found',
        headers: { 'content-type': 'application/json' },
        config,
      } as AxiosResponse;
    }

    return {
      data: mockResp.data,
      status: mockResp.status,
      statusText: 'OK',
      headers: { 'content-type': 'application/json' },
      config,
    } as AxiosResponse;
  }
}
