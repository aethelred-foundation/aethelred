/**
 * Compute Module - AI Computation job operations
 */

import { AxiosInstance } from 'axios';
import { SigningStargateClient } from '@cosmjs/stargate';
import { AethelredConfig } from '../client/config';
import {
  ComputeJob,
  ComputeResult,
  JobStatus,
  JobPriority,
  ProofType,
  SubmitJobRequest,
  SubmitJobResponse,
  JobQuery,
  JobListResponse,
  RegisteredModel,
  ModelQuery,
} from '../types/compute';

export class ComputeModule {
  private httpClient: AxiosInstance;
  private signingClient: SigningStargateClient | null;
  private config: AethelredConfig;

  constructor(
    httpClient: AxiosInstance,
    signingClient: SigningStargateClient | null,
    config: AethelredConfig
  ) {
    this.httpClient = httpClient;
    this.signingClient = signingClient;
    this.config = config;
  }

  /**
   * Submit a compute job
   */
  async submitJob(request: SubmitJobRequest): Promise<SubmitJobResponse> {
    if (!this.signingClient) {
      // Use REST API for unsigned submission
      const response = await this.httpClient.post<SubmitJobResponse>(
        '/aethelred/compute/v1/submit',
        request
      );
      return response.data;
    }

    // Build and sign the transaction
    const msg = {
      typeUrl: '/aethelred.compute.v1.MsgSubmitJob',
      value: {
        modelHash: request.modelHash,
        inputHash: request.inputHash,
        inputData: request.inputData,
        purpose: request.purpose,
        proofType: request.proofType || 'hybrid',
        priority: request.priority || 'normal',
        maxWaitTime: request.maxWaitTime,
        callbackUrl: request.callbackUrl,
        metadata: request.metadata,
      },
    };

    const signerAddress = await this.getSignerAddress();
    if (!signerAddress) {
      throw new Error('No signer address available');
    }

    const result = await this.signingClient.signAndBroadcast(
      signerAddress,
      [msg],
      'auto',
      request.purpose || 'Submit compute job'
    );

    const jobId = this.extractJobIdFromEvents(result);

    return {
      jobId: jobId || '',
      status: 'pending',
      txHash: result.transactionHash,
    };
  }

  /**
   * Get a job by ID
   */
  async getJob(jobId: string): Promise<ComputeJob | null> {
    try {
      const response = await this.httpClient.get<ComputeJob>(
        `/aethelred/compute/v1/job/${jobId}`
      );
      return response.data;
    } catch (error: any) {
      if (error.response?.status === 404) {
        return null;
      }
      throw error;
    }
  }

  /**
   * List jobs with optional filters
   */
  async listJobs(query?: JobQuery): Promise<JobListResponse> {
    const params = new URLSearchParams();

    if (query?.requester) params.append('requester', query.requester);
    if (query?.status) params.append('status', query.status);
    if (query?.modelHash) params.append('model_hash', query.modelHash);
    if (query?.proofType) params.append('proof_type', query.proofType);
    if (query?.minCreatedAt) params.append('min_created_at', query.minCreatedAt);
    if (query?.maxCreatedAt) params.append('max_created_at', query.maxCreatedAt);
    if (query?.limit) params.append('limit', query.limit.toString());
    if (query?.offset) params.append('offset', query.offset.toString());

    const response = await this.httpClient.get<JobListResponse>(
      `/aethelred/compute/v1/jobs?${params.toString()}`
    );
    return response.data;
  }

  /**
   * Get job result
   */
  async getResult(jobId: string): Promise<ComputeResult | null> {
    const job = await this.getJob(jobId);
    return job?.result || null;
  }

  /**
   * Wait for job completion
   */
  async waitForCompletion(
    jobId: string,
    timeoutMs: number = 60000,
    pollIntervalMs: number = 1000
  ): Promise<ComputeJob> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      const job = await this.getJob(jobId);

      if (!job) {
        throw new Error(`Job ${jobId} not found`);
      }

      if (job.status === 'completed' || job.status === 'failed' || job.status === 'expired') {
        return job;
      }

      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }

    throw new Error(`Timeout waiting for job ${jobId} to complete`);
  }

  /**
   * Submit job and wait for result
   */
  async submitAndWait(
    request: SubmitJobRequest,
    timeoutMs: number = 60000
  ): Promise<ComputeJob> {
    const response = await this.submitJob(request);
    return this.waitForCompletion(response.jobId, timeoutMs);
  }

  /**
   * Cancel a pending job
   */
  async cancelJob(jobId: string): Promise<boolean> {
    if (!this.signingClient) {
      throw new Error('Signing client required for canceling jobs');
    }

    const msg = {
      typeUrl: '/aethelred.compute.v1.MsgCancelJob',
      value: { jobId },
    };

    const signerAddress = await this.getSignerAddress();
    if (!signerAddress) {
      throw new Error('No signer address available');
    }

    const result = await this.signingClient.signAndBroadcast(
      signerAddress,
      [msg],
      'auto',
      'Cancel compute job'
    );

    return result.code === 0;
  }

  /**
   * Retry a failed job
   */
  async retryJob(jobId: string): Promise<SubmitJobResponse> {
    const response = await this.httpClient.post<SubmitJobResponse>(
      `/aethelred/compute/v1/job/${jobId}/retry`
    );
    return response.data;
  }

  // ============ Model Operations ============

  /**
   * Get a registered model
   */
  async getModel(modelId: string): Promise<RegisteredModel | null> {
    try {
      const response = await this.httpClient.get<RegisteredModel>(
        `/aethelred/compute/v1/model/${modelId}`
      );
      return response.data;
    } catch (error: any) {
      if (error.response?.status === 404) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Get model by hash
   */
  async getModelByHash(modelHash: string): Promise<RegisteredModel | null> {
    try {
      const response = await this.httpClient.get<RegisteredModel>(
        `/aethelred/compute/v1/model/hash/${modelHash}`
      );
      return response.data;
    } catch (error: any) {
      if (error.response?.status === 404) {
        return null;
      }
      throw error;
    }
  }

  /**
   * List registered models
   */
  async listModels(query?: ModelQuery): Promise<RegisteredModel[]> {
    const params = new URLSearchParams();

    if (query?.status) params.append('status', query.status);
    if (query?.owner) params.append('owner', query.owner);
    if (query?.nameContains) params.append('name_contains', query.nameContains);
    if (query?.limit) params.append('limit', query.limit.toString());
    if (query?.offset) params.append('offset', query.offset.toString());

    const response = await this.httpClient.get<{ models: RegisteredModel[] }>(
      `/aethelred/compute/v1/models?${params.toString()}`
    );
    return response.data.models;
  }

  /**
   * Register a new model (requires signer)
   */
  async registerModel(request: RegisterModelRequest): Promise<RegisterModelResponse> {
    if (!this.signingClient) {
      throw new Error('Signing client required for registering models');
    }

    const msg = {
      typeUrl: '/aethelred.compute.v1.MsgRegisterModel',
      value: {
        name: request.name,
        version: request.version,
        description: request.description,
        modelHash: request.modelHash,
        circuitHash: request.circuitHash,
        teeMeasurement: request.teeMeasurement,
        metadata: request.metadata,
      },
    };

    const signerAddress = await this.getSignerAddress();
    if (!signerAddress) {
      throw new Error('No signer address available');
    }

    const result = await this.signingClient.signAndBroadcast(
      signerAddress,
      [msg],
      'auto',
      `Register model: ${request.name}`
    );

    const modelId = this.extractModelIdFromEvents(result);

    return {
      modelId: modelId || '',
      modelHash: request.modelHash,
      txHash: result.transactionHash,
    };
  }

  // ============ Statistics ============

  /**
   * Get compute statistics
   */
  async getStats(): Promise<ComputeStats> {
    const response = await this.httpClient.get<ComputeStats>(
      '/aethelred/compute/v1/stats'
    );
    return response.data;
  }

  /**
   * Get queue status
   */
  async getQueueStatus(): Promise<QueueStatus> {
    const response = await this.httpClient.get<QueueStatus>(
      '/aethelred/compute/v1/queue'
    );
    return response.data;
  }

  /**
   * Estimate job completion time
   */
  async estimateTime(
    modelHash: string,
    proofType: ProofType,
    priority: JobPriority
  ): Promise<TimeEstimate> {
    const response = await this.httpClient.post<TimeEstimate>(
      '/aethelred/compute/v1/estimate',
      { modelHash, proofType, priority }
    );
    return response.data;
  }

  // Private helpers

  private async getSignerAddress(): Promise<string | null> {
    // Will be implemented through parent client
    return null;
  }

  private extractJobIdFromEvents(result: any): string | null {
    for (const event of result.events || []) {
      if (event.type === 'submit_job') {
        for (const attr of event.attributes) {
          if (attr.key === 'job_id') {
            return attr.value;
          }
        }
      }
    }
    return null;
  }

  private extractModelIdFromEvents(result: any): string | null {
    for (const event of result.events || []) {
      if (event.type === 'register_model') {
        for (const attr of event.attributes) {
          if (attr.key === 'model_id') {
            return attr.value;
          }
        }
      }
    }
    return null;
  }
}

// Additional types

export interface RegisterModelRequest {
  name: string;
  version: string;
  description?: string;
  modelHash: string;
  circuitHash?: string;
  teeMeasurement?: string;
  metadata?: Record<string, string>;
}

export interface RegisterModelResponse {
  modelId: string;
  modelHash: string;
  txHash: string;
}

export interface ComputeStats {
  totalJobs: number;
  pendingJobs: number;
  executingJobs: number;
  completedJobs: number;
  failedJobs: number;
  averageProcessingTimeMs: number;
  jobsByProofType: Record<ProofType, number>;
  jobsByPriority: Record<JobPriority, number>;
  registeredModels: number;
  activeValidators: number;
}

export interface QueueStatus {
  pendingJobs: number;
  executingJobs: number;
  estimatedWaitTimeMs: number;
  jobsByPriority: Record<JobPriority, number>;
  validatorCapacity: number;
  currentUtilization: number;
}

export interface TimeEstimate {
  estimatedTimeMs: number;
  queueWaitMs: number;
  executionTimeMs: number;
  queuePosition: number;
}
