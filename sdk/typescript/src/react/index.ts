import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import type { AethelredClient } from '../core/client';
import type { ComputeJob, DigitalSeal, VerifySealResponse } from '../core/types';
import { isTerminalJobStatus } from './utils';

export type AsyncQueryStatus = 'idle' | 'loading' | 'success' | 'error';

export interface AethelredQueryState<T> {
  status: AsyncQueryStatus;
  data: T | null;
  error: Error | null;
  loading: boolean;
  refresh: () => Promise<void>;
}

export interface AethelredQueryOptions {
  enabled?: boolean;
  pollIntervalMs?: number;
  immediate?: boolean;
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

export function useAethelredQuery<T>(
  fetcher: (() => Promise<T>) | undefined,
  deps: ReadonlyArray<unknown>,
  options: AethelredQueryOptions = {},
): AethelredQueryState<T> {
  const enabled = options.enabled ?? true;
  const immediate = options.immediate ?? true;
  const pollIntervalMs = options.pollIntervalMs;

  const [status, setStatus] = useState<AsyncQueryStatus>('idle');
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const mountedRef = useRef(true);
  const runningRef = useRef(false);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const run = useCallback(async () => {
    if (!enabled || !fetcher || runningRef.current) return;
    runningRef.current = true;
    setStatus((prev) => (prev === 'success' ? prev : 'loading'));
    setError(null);
    try {
      const result = await fetcher();
      if (!mountedRef.current) return;
      setData(result);
      setStatus('success');
    } catch (e) {
      if (!mountedRef.current) return;
      setError(asError(e));
      setStatus('error');
    } finally {
      runningRef.current = false;
    }
  }, [enabled, fetcher]);

  useEffect(() => {
    if (!enabled || !fetcher) {
      setStatus('idle');
      return;
    }
    if (immediate) {
      void run();
    }
    if (!pollIntervalMs || pollIntervalMs <= 0) return;
    const id = setInterval(() => void run(), pollIntervalMs);
    return () => clearInterval(id);
  }, [enabled, fetcher, immediate, pollIntervalMs, run, ...deps]);

  return useMemo(
    () => ({
      status,
      data,
      error,
      loading: status === 'loading',
      refresh: run,
    }),
    [status, data, error, run],
  );
}

export function useSeal(
  client: AethelredClient | null | undefined,
  sealId: string | null | undefined,
  options: AethelredQueryOptions = {},
): AethelredQueryState<DigitalSeal> {
  const fetcher = useMemo(() => {
    if (!client || !sealId) return undefined;
    return async () => client.seals.get(sealId);
  }, [client, sealId]);
  return useAethelredQuery(fetcher, [client, sealId], {
    ...options,
    enabled: (options.enabled ?? true) && Boolean(client && sealId),
  });
}

export function useSealVerification(
  client: AethelredClient | null | undefined,
  sealId: string | null | undefined,
  options: AethelredQueryOptions = {},
): AethelredQueryState<VerifySealResponse> {
  const fetcher = useMemo(() => {
    if (!client || !sealId) return undefined;
    return async () => client.seals.verify(sealId);
  }, [client, sealId]);
  return useAethelredQuery(fetcher, [client, sealId], {
    ...options,
    enabled: (options.enabled ?? true) && Boolean(client && sealId),
  });
}

export interface UseJobOptions extends AethelredQueryOptions {
  stopOnTerminal?: boolean;
}

export function useJob(
  client: AethelredClient | null | undefined,
  jobId: string | null | undefined,
  options: UseJobOptions = {},
): AethelredQueryState<ComputeJob> {
  const [terminal, setTerminal] = useState(false);
  const fetcher = useMemo(() => {
    if (!client || !jobId) return undefined;
    return async () => {
      const job = await client.jobs.get(jobId);
      if (options.stopOnTerminal !== false && isTerminalJobStatus(job.status)) {
        setTerminal(true);
      }
      return job;
    };
  }, [client, jobId, options.stopOnTerminal]);

  useEffect(() => {
    setTerminal(false);
  }, [jobId]);

  return useAethelredQuery(fetcher, [client, jobId, terminal], {
    ...options,
    pollIntervalMs: terminal ? undefined : options.pollIntervalMs,
    enabled: (options.enabled ?? true) && Boolean(client && jobId),
  });
}
