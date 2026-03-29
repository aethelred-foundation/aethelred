/**
 * Jobs module for Aethelred SDK.
 */

import type { AethelredClient } from '../core/client';
import { ComputeJob, JobStatus, ProofType, SubmitJobRequest, SubmitJobResponse, PageRequest } from '../core/types';
import { TimeoutError } from '../core/errors';

export class JobsModule {
  private readonly basePath = '/aethelred/pouw/v1';

  constructor(private readonly client: AethelredClient) {}

  /**
   * Submit a compute job.
   * Enterprise default: proofType defaults to HYBRID (TEE + zkML) for
   * maximum assurance and audit compliance.
   */
  async submit(request: SubmitJobRequest): Promise<SubmitJobResponse> {
    const withDefaults = {
      proofType: ProofType.HYBRID,
      ...request,
    };
    return this.client.post(`${this.basePath}/jobs`, withDefaults);
  }

  async get(jobId: string): Promise<ComputeJob> {
    const data = await this.client.get<{ job: ComputeJob }>(`${this.basePath}/jobs/${jobId}`);
    return data.job;
  }

  async list(options?: { status?: JobStatus; creator?: string; pagination?: PageRequest }): Promise<ComputeJob[]> {
    const data = await this.client.get<{ jobs: ComputeJob[] }>(`${this.basePath}/jobs`, options);
    return data.jobs || [];
  }

  async listPending(pagination?: PageRequest): Promise<ComputeJob[]> {
    const query = pagination ? { ...pagination } : undefined;
    const data = await this.client.get<{ jobs: ComputeJob[] }>(`${this.basePath}/jobs/pending`, query);
    return data.jobs || [];
  }

  async cancel(jobId: string): Promise<boolean> {
    await this.client.post(`${this.basePath}/jobs/${jobId}/cancel`);
    return true;
  }

  async waitForCompletion(jobId: string, options?: { pollInterval?: number; timeout?: number }): Promise<ComputeJob> {
    const pollInterval = options?.pollInterval ?? 2000;
    const timeout = options?.timeout ?? 300000;
    const start = Date.now();

    while (Date.now() - start < timeout) {
      const job = await this.get(jobId);
      if ([JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED].includes(job.status)) {
        return job;
      }
      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }

    throw new TimeoutError(`Job ${jobId} did not complete within ${timeout}ms`);
  }
}
