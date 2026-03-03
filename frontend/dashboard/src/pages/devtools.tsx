import type { ComponentType } from 'react';
import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  CheckCircle2,
  Cpu,
  ExternalLink,
  RefreshCw,
  Server,
  ShieldCheck,
  XCircle,
} from 'lucide-react';

const FASTAPI_URL = process.env.NEXT_PUBLIC_DEVTOOLS_FASTAPI_URL || 'http://127.0.0.1:8000';
const NEXTJS_URL = process.env.NEXT_PUBLIC_DEVTOOLS_NEXTJS_URL || 'http://127.0.0.1:3000';
const RPC_URL = process.env.NEXT_PUBLIC_DEVTOOLS_RPC_URL || 'http://127.0.0.1:26657';

type HealthCheck = {
  name: string;
  url: string;
  ok: boolean;
  latencyMs: number | null;
  payload?: unknown;
  error?: string;
};

async function timedFetchJson(name: string, url: string): Promise<HealthCheck> {
  const start = Date.now();
  try {
    const response = await fetch(url);
    const latencyMs = Math.max(0, Date.now() - start);
    const contentType = response.headers.get('content-type') || '';
    const payload = contentType.includes('application/json')
      ? await response.json()
      : await response.text();
    return { name, url, ok: response.ok, latencyMs, payload, error: response.ok ? undefined : `HTTP ${response.status}` };
  } catch (error) {
    return {
      name,
      url,
      ok: false,
      latencyMs: null,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

async function timedPostJson(name: string, url: string, body: unknown): Promise<HealthCheck> {
  const start = Date.now();
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const latencyMs = Math.max(0, Date.now() - start);
    const payload = await response.json();
    return {
      name,
      url,
      ok: response.ok,
      latencyMs,
      payload,
      error: response.ok ? undefined : `HTTP ${response.status}`,
    };
  } catch (error) {
    return {
      name,
      url,
      ok: false,
      latencyMs: null,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export default function DeveloperToolsDashboard() {
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['devtools-health'],
    queryFn: async () => {
      const [rpc, fastapi, nextjsHealth, nextjsVerify, fastapiRecent] = await Promise.all([
        timedFetchJson('Mock RPC', `${RPC_URL}/health`),
        timedFetchJson('FastAPI Verifier', `${FASTAPI_URL}/health`),
        timedFetchJson('Next.js Verifier Health', `${NEXTJS_URL}/api/health`),
        timedPostJson('Next.js Verify Route', `${NEXTJS_URL}/api/verify`, {
          prompt: 'urgent wire transfer override',
        }),
        timedFetchJson('FastAPI Recent Verifications', `${FASTAPI_URL}/verify/recent?limit=5`),
      ]);

      return { checks: [rpc, fastapi, nextjsHealth, nextjsVerify, fastapiRecent] };
    },
    refetchInterval: 10000,
  });

  const summary = useMemo(() => {
    const checks = data?.checks ?? [];
    const healthy = checks.filter((c) => c.ok).length;
    const unhealthy = checks.length - healthy;
    const avgLatency = checks
      .map((c) => c.latencyMs)
      .filter((n): n is number => typeof n === 'number');
    return {
      total: checks.length,
      healthy,
      unhealthy,
      avgLatencyMs:
        avgLatency.length > 0 ? Math.round(avgLatency.reduce((a, b) => a + b, 0) / avgLatency.length) : null,
    };
  }, [data]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-cyan-300">Aethelred Developer Tools</p>
            <h1 className="mt-2 text-3xl font-bold">Local Testnet Control Surface</h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-300">
              Monitor the local RPC, verifier gateways, seal activity, and integration routes in one page while
              developing SDK and protocol integrations.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => refetch()}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm hover:border-cyan-400"
            >
              <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <a
              href="/"
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm hover:border-slate-500"
            >
              Main Explorer
              <ExternalLink className="h-4 w-4" />
            </a>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
          <StatCard title="Services Checked" value={summary.total} icon={Server} tone="cyan" />
          <StatCard title="Healthy" value={summary.healthy} icon={CheckCircle2} tone="green" />
          <StatCard title="Unhealthy" value={summary.unhealthy} icon={XCircle} tone="red" />
          <StatCard
            title="Avg Latency"
            value={summary.avgLatencyMs !== null ? `${summary.avgLatencyMs} ms` : 'n/a'}
            icon={Activity}
            tone="amber"
          />
        </div>

        <div className="mt-8 grid grid-cols-1 gap-6 xl:grid-cols-[1.2fr_0.8fr]">
          <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-lg font-semibold">Service Health Matrix</h2>
              {isLoading && <span className="text-sm text-slate-400">Loading...</span>}
            </div>

            <div className="space-y-3">
              {(data?.checks ?? []).map((check) => (
                <div
                  key={check.name}
                  className="rounded-xl border border-slate-800 bg-slate-950/70 p-4"
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <StatusDot ok={check.ok} />
                      <div>
                        <div className="font-medium">{check.name}</div>
                        <div className="text-xs text-slate-400">{check.url}</div>
                      </div>
                    </div>
                    <div className="text-right text-sm">
                      <div className={check.ok ? 'text-green-300' : 'text-red-300'}>
                        {check.ok ? 'OK' : 'FAIL'}
                      </div>
                      <div className="text-xs text-slate-400">
                        {check.latencyMs !== null ? `${check.latencyMs} ms` : 'no latency sample'}
                      </div>
                    </div>
                  </div>
                  {check.error && (
                    <div className="mt-3 rounded-md border border-red-900 bg-red-950/40 px-3 py-2 text-xs text-red-200">
                      {check.error}
                    </div>
                  )}
                  {check.payload !== undefined && check.payload !== null && (
                    <pre className="mt-3 max-h-52 overflow-auto rounded-md border border-slate-800 bg-slate-900 p-3 text-xs text-slate-200">
                      {JSON.stringify(check.payload, null, 2)}
                    </pre>
                  )}
                </div>
              ))}
            </div>
          </section>

          <section className="space-y-6">
            <Panel
              title="Developer Workflow"
              icon={ShieldCheck}
              items={[
                `CLI: aethel local up`,
                `CLI: aethel diagnostics doctor`,
                `CLI: seal-verifier verify-file ./seal.json`,
                `VS Code: “Aethelred: Verify Seal In Editor”`,
              ]}
            />
            <Panel
              title="Local Endpoints"
              icon={Cpu}
              items={[
                `Mock RPC: ${RPC_URL}`,
                `FastAPI Verifier: ${FASTAPI_URL}`,
                `Next.js Verifier: ${NEXTJS_URL}`,
                `Dashboard: http://127.0.0.1:3101/devtools`,
              ]}
            />
          </section>
        </div>
      </div>
    </div>
  );
}

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span
      className={`inline-block h-2.5 w-2.5 rounded-full ${ok ? 'bg-green-400 shadow-[0_0_10px_#4ade80]' : 'bg-red-400 shadow-[0_0_10px_#f87171]'}`}
    />
  );
}

function StatCard({
  title,
  value,
  icon: Icon,
  tone,
}: {
  title: string;
  value: string | number;
  icon: ComponentType<{ className?: string }>;
  tone: 'cyan' | 'green' | 'red' | 'amber';
}) {
  const toneClass: Record<string, string> = {
    cyan: 'from-cyan-500/20 to-cyan-900/20 text-cyan-200 border-cyan-900/50',
    green: 'from-emerald-500/20 to-emerald-900/20 text-emerald-200 border-emerald-900/50',
    red: 'from-rose-500/20 to-rose-900/20 text-rose-200 border-rose-900/50',
    amber: 'from-amber-500/20 to-amber-900/20 text-amber-200 border-amber-900/50',
  };
  return (
    <div className={`rounded-2xl border bg-gradient-to-br p-4 ${toneClass[tone]}`}>
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-300">{title}</div>
          <div className="mt-2 text-2xl font-semibold text-white">{value}</div>
        </div>
        <Icon className="h-5 w-5" />
      </div>
    </div>
  );
}

function Panel({
  title,
  icon: Icon,
  items,
}: {
  title: string;
  icon: ComponentType<{ className?: string }>;
  items: string[];
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
      <div className="mb-3 flex items-center gap-2">
        <Icon className="h-4 w-4 text-cyan-300" />
        <h3 className="font-semibold">{title}</h3>
      </div>
      <ul className="space-y-2 text-sm text-slate-300">
        {items.map((item) => (
          <li key={item} className="rounded-md border border-slate-800 bg-slate-950/50 px-3 py-2">
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}
