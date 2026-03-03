/**
 * Credit Scoring Module - Financial AI Demo
 */

import { AxiosInstance } from 'axios';
import { AethelredConfig } from '../client/config';
import {
  CreditFeatures,
  CreditScoringResult,
  CreditScoringModel,
  LoanApplicationRequest,
  LoanApplicationResponse,
  BatchScoringRequest,
  BatchScoringResponse,
  DemoScenario,
  PipelineMetrics,
  LoanType,
  LoanDecision,
  ScoreCategory,
} from '../types/credit-scoring';

export class CreditScoringModule {
  private httpClient: AxiosInstance;
  private config: AethelredConfig;

  constructor(httpClient: AxiosInstance, config: AethelredConfig) {
    this.httpClient = httpClient;
    this.config = config;
  }

  /**
   * Score a loan application
   */
  async score(request: LoanApplicationRequest): Promise<CreditScoringResult> {
    const response = await this.httpClient.post<CreditScoringResult>(
      '/api/v1/score',
      request
    );
    return response.data;
  }

  /**
   * Score with verification (TEE + zkML)
   */
  async scoreVerified(request: LoanApplicationRequest): Promise<CreditScoringResult> {
    const response = await this.httpClient.post<CreditScoringResult>(
      '/api/v1/score/verified',
      { ...request, withVerification: true }
    );
    return response.data;
  }

  /**
   * Batch score multiple applications
   */
  async batchScore(request: BatchScoringRequest): Promise<BatchScoringResponse> {
    const response = await this.httpClient.post<BatchScoringResponse>(
      '/api/v1/score/batch',
      request
    );
    return response.data;
  }

  /**
   * Get application status
   */
  async getApplication(applicationId: string): Promise<LoanApplicationResponse | null> {
    try {
      const response = await this.httpClient.get<LoanApplicationResponse>(
        `/api/v1/application/${applicationId}`
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
   * Wait for application result
   */
  async waitForResult(
    applicationId: string,
    timeoutMs: number = 30000
  ): Promise<CreditScoringResult> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      const app = await this.getApplication(applicationId);

      if (!app) {
        throw new Error(`Application ${applicationId} not found`);
      }

      if (app.status === 'completed' && app.result) {
        return app.result;
      }

      if (app.status === 'failed') {
        throw new Error(app.error || 'Application processing failed');
      }

      await new Promise((resolve) => setTimeout(resolve, 500));
    }

    throw new Error(`Timeout waiting for application ${applicationId}`);
  }

  // ============ Model Operations ============

  /**
   * List available credit scoring models
   */
  async listModels(): Promise<CreditScoringModel[]> {
    const response = await this.httpClient.get<{ models: CreditScoringModel[] }>(
      '/api/v1/models'
    );
    return response.data.models;
  }

  /**
   * Get model details
   */
  async getModel(modelId: string): Promise<CreditScoringModel | null> {
    try {
      const response = await this.httpClient.get<CreditScoringModel>(
        `/api/v1/model/${modelId}`
      );
      return response.data;
    } catch (error: any) {
      if (error.response?.status === 404) {
        return null;
      }
      throw error;
    }
  }

  // ============ Demo Operations ============

  /**
   * List demo scenarios
   */
  async listScenarios(): Promise<DemoScenario[]> {
    const response = await this.httpClient.get<{ scenarios: DemoScenario[] }>(
      '/api/v1/demo/scenarios'
    );
    return response.data.scenarios;
  }

  /**
   * Get scenario by ID
   */
  async getScenario(scenarioId: string): Promise<DemoScenario | null> {
    const scenarios = await this.listScenarios();
    return scenarios.find((s) => s.id === scenarioId) || null;
  }

  /**
   * Run a demo scenario
   */
  async runScenario(
    scenarioId: string,
    withVerification: boolean = false
  ): Promise<CreditScoringResult> {
    const response = await this.httpClient.post<CreditScoringResult>(
      '/api/v1/demo/run',
      { scenarioId, withVerification }
    );
    return response.data;
  }

  /**
   * Run all demo scenarios
   */
  async runAllScenarios(
    withVerification: boolean = false
  ): Promise<CreditScoringResult[]> {
    const scenarios = await this.listScenarios();
    const results: CreditScoringResult[] = [];

    for (const scenario of scenarios) {
      const result = await this.runScenario(scenario.id, withVerification);
      results.push(result);
    }

    return results;
  }

  // ============ Metrics ============

  /**
   * Get pipeline metrics
   */
  async getMetrics(): Promise<PipelineMetrics> {
    const response = await this.httpClient.get<PipelineMetrics>(
      '/api/v1/metrics'
    );
    return response.data;
  }

  // ============ Utilities ============

  /**
   * Create sample credit features for testing
   */
  createSampleFeatures(profile: 'excellent' | 'good' | 'fair' | 'poor'): CreditFeatures {
    const profiles: Record<string, CreditFeatures> = {
      excellent: {
        paymentHistory: 0.99,
        latePayments30Days: 0,
        latePayments60Days: 0,
        latePayments90Days: 0,
        creditUtilization: 0.15,
        totalCreditLimit: 50000,
        totalCreditUsed: 7500,
        creditHistoryMonths: 180,
        oldestAccountMonths: 240,
        averageAccountAgeMonths: 120,
        numCreditCards: 4,
        numInstallmentLoans: 1,
        numMortgages: 1,
        numAutoLoans: 0,
        recentInquiries: 0,
        newAccountsLast12Months: 0,
        bankruptcyHistory: false,
        collectionsCount: 0,
        publicRecordsCount: 0,
        annualIncome: 150000,
        employmentLengthMonths: 120,
        debtToIncomeRatio: 0.25,
      },
      good: {
        paymentHistory: 0.95,
        latePayments30Days: 1,
        latePayments60Days: 0,
        latePayments90Days: 0,
        creditUtilization: 0.30,
        totalCreditLimit: 25000,
        totalCreditUsed: 7500,
        creditHistoryMonths: 84,
        oldestAccountMonths: 120,
        averageAccountAgeMonths: 60,
        numCreditCards: 3,
        numInstallmentLoans: 1,
        numMortgages: 0,
        numAutoLoans: 1,
        recentInquiries: 2,
        newAccountsLast12Months: 1,
        bankruptcyHistory: false,
        collectionsCount: 0,
        publicRecordsCount: 0,
        annualIncome: 85000,
        employmentLengthMonths: 48,
        debtToIncomeRatio: 0.35,
      },
      fair: {
        paymentHistory: 0.85,
        latePayments30Days: 3,
        latePayments60Days: 1,
        latePayments90Days: 0,
        creditUtilization: 0.55,
        totalCreditLimit: 15000,
        totalCreditUsed: 8250,
        creditHistoryMonths: 48,
        oldestAccountMonths: 60,
        averageAccountAgeMonths: 36,
        numCreditCards: 4,
        numInstallmentLoans: 2,
        numMortgages: 0,
        numAutoLoans: 1,
        recentInquiries: 4,
        newAccountsLast12Months: 2,
        bankruptcyHistory: false,
        collectionsCount: 0,
        publicRecordsCount: 0,
        annualIncome: 55000,
        employmentLengthMonths: 24,
        debtToIncomeRatio: 0.42,
      },
      poor: {
        paymentHistory: 0.70,
        latePayments30Days: 5,
        latePayments60Days: 3,
        latePayments90Days: 1,
        creditUtilization: 0.85,
        totalCreditLimit: 8000,
        totalCreditUsed: 6800,
        creditHistoryMonths: 24,
        oldestAccountMonths: 36,
        averageAccountAgeMonths: 18,
        numCreditCards: 3,
        numInstallmentLoans: 2,
        numMortgages: 0,
        numAutoLoans: 0,
        recentInquiries: 6,
        newAccountsLast12Months: 3,
        bankruptcyHistory: false,
        collectionsCount: 1,
        publicRecordsCount: 0,
        annualIncome: 35000,
        employmentLengthMonths: 12,
        debtToIncomeRatio: 0.55,
      },
    };

    return profiles[profile];
  }

  /**
   * Validate credit features
   */
  validateFeatures(features: CreditFeatures): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Payment history validation
    if (features.paymentHistory < 0 || features.paymentHistory > 1) {
      errors.push('Payment history must be between 0 and 1');
    }

    // Credit utilization validation
    if (features.creditUtilization < 0 || features.creditUtilization > 1) {
      errors.push('Credit utilization must be between 0 and 1');
    }

    // Credit history validation
    if (features.creditHistoryMonths < 0) {
      errors.push('Credit history months cannot be negative');
    }

    // Income validation
    if (features.annualIncome < 0) {
      errors.push('Annual income cannot be negative');
    }

    // DTI validation
    if (features.debtToIncomeRatio < 0 || features.debtToIncomeRatio > 1) {
      errors.push('Debt-to-income ratio must be between 0 and 1');
    }

    // Warnings
    if (features.creditUtilization > 0.7) {
      warnings.push('High credit utilization may negatively impact score');
    }

    if (features.recentInquiries > 5) {
      warnings.push('Many recent inquiries may indicate credit seeking behavior');
    }

    if (features.debtToIncomeRatio > 0.43) {
      warnings.push('DTI above 43% may disqualify for QM mortgages');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Calculate estimated score from features
   */
  estimateScore(features: CreditFeatures): ScoreEstimate {
    // This is a simplified client-side estimation
    // Real scoring happens on-chain with verification

    let score = 300; // Base score

    // Payment history (35%)
    score += features.paymentHistory * 175;
    score -= features.latePayments30Days * 10;
    score -= features.latePayments60Days * 25;
    score -= features.latePayments90Days * 50;

    // Credit utilization (30%)
    score += (1 - features.creditUtilization) * 150;

    // Credit history length (15%)
    const historyFactor = Math.min(features.creditHistoryMonths / 240, 1);
    score += historyFactor * 75;

    // Credit mix (10%)
    const hasMix =
      features.numCreditCards > 0 &&
      (features.numInstallmentLoans > 0 || features.numMortgages > 0);
    score += hasMix ? 50 : 25;

    // New credit (10%)
    score -= features.recentInquiries * 5;
    score -= features.newAccountsLast12Months * 10;

    // Negative factors
    if (features.bankruptcyHistory) score -= 100;
    score -= features.collectionsCount * 50;
    score -= features.publicRecordsCount * 30;

    // Clamp to valid range
    score = Math.max(300, Math.min(850, Math.round(score)));

    // Determine category
    let category: ScoreCategory;
    if (score >= 750) category = 'excellent';
    else if (score >= 700) category = 'good';
    else if (score >= 650) category = 'fair';
    else if (score >= 550) category = 'poor';
    else category = 'very_poor';

    // Estimate decision
    let estimatedDecision: LoanDecision;
    if (score >= 700) estimatedDecision = 'approved';
    else if (score >= 600) estimatedDecision = 'review';
    else estimatedDecision = 'denied';

    return {
      estimatedScore: score,
      category,
      estimatedDecision,
      confidence: 0.7, // Client-side estimates have lower confidence
      note: 'This is a client-side estimate. Actual scoring requires on-chain verification.',
    };
  }

  /**
   * Format score for display
   */
  formatScore(score: number): string {
    if (score >= 750) return `${score} (Excellent)`;
    if (score >= 700) return `${score} (Good)`;
    if (score >= 650) return `${score} (Fair)`;
    if (score >= 550) return `${score} (Poor)`;
    return `${score} (Very Poor)`;
  }

  /**
   * Get decision color for UI
   */
  getDecisionColor(decision: LoanDecision): string {
    switch (decision) {
      case 'approved':
        return '#22c55e'; // green
      case 'review':
        return '#eab308'; // yellow
      case 'denied':
        return '#ef4444'; // red
      default:
        return '#6b7280'; // gray
    }
  }
}

// Additional types

interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

interface ScoreEstimate {
  estimatedScore: number;
  category: ScoreCategory;
  estimatedDecision: LoanDecision;
  confidence: number;
  note: string;
}
