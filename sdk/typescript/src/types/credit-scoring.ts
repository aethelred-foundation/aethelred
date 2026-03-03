/**
 * Credit Scoring Types
 */

export type LoanDecision = 'approved' | 'denied' | 'review';

export type ScoreCategory = 'excellent' | 'good' | 'fair' | 'poor' | 'very_poor';

export type LoanType = 'personal' | 'mortgage' | 'auto' | 'business' | 'credit_card';

export type VerificationType = 'tee' | 'zkml' | 'hybrid' | 'none';

/**
 * Credit features input for scoring
 */
export interface CreditFeatures {
  // Payment History (35% weight)
  paymentHistory: number; // 0-1, percentage of on-time payments
  latePayments30Days: number;
  latePayments60Days: number;
  latePayments90Days: number;

  // Credit Utilization (30% weight)
  creditUtilization: number; // 0-1, current usage / limit
  totalCreditLimit: number;
  totalCreditUsed: number;

  // Credit History Length (15% weight)
  creditHistoryMonths: number;
  oldestAccountMonths: number;
  averageAccountAgeMonths: number;

  // Credit Mix (10% weight)
  numCreditCards: number;
  numInstallmentLoans: number;
  numMortgages: number;
  numAutoLoans: number;

  // New Credit (10% weight)
  recentInquiries: number; // Last 12 months
  newAccountsLast12Months: number;

  // Additional Risk Factors
  bankruptcyHistory: boolean;
  collectionsCount: number;
  publicRecordsCount: number;

  // Income & Employment
  annualIncome: number;
  employmentLengthMonths: number;
  debtToIncomeRatio: number;
}

/**
 * Risk factor in scoring result
 */
export interface RiskFactor {
  /** Factor code */
  code: string;

  /** Human-readable description */
  description: string;

  /** Impact on score (-100 to +100) */
  impact: number;

  /** Category of factor */
  category: string;
}

/**
 * Credit scoring result
 */
export interface CreditScoringResult {
  /** Application ID */
  applicationId: string;

  /** Credit score (300-850) */
  score: number;

  /** Score category */
  scoreCategory: ScoreCategory;

  /** Probability of default (0-1) */
  defaultProbability: number;

  /** Loan decision */
  decision: LoanDecision;

  /** Confidence level (0-1) */
  confidence: number;

  /** Recommended interest rate */
  recommendedRate?: number;

  /** Recommended credit limit */
  recommendedLimit?: number;

  /** Risk factors */
  riskFactors: RiskFactor[];

  /** Positive factors */
  positiveFactors: string[];

  /** Model used for scoring */
  modelId: string;

  /** Model version */
  modelVersion: string;

  /** Verification type used */
  verificationType: VerificationType;

  /** Processing time in ms */
  processingTimeMs: number;

  /** Timestamp */
  timestamp: string;

  /** Seal ID if verified */
  sealId?: string;
}

/**
 * Loan application request
 */
export interface LoanApplicationRequest {
  /** Applicant ID */
  applicantId: string;

  /** Loan type */
  loanType: LoanType;

  /** Requested amount */
  loanAmount: number;

  /** Loan term in months */
  loanTermMonths: number;

  /** Credit features */
  features: CreditFeatures;

  /** Model to use */
  modelId?: string;

  /** Whether to request verification */
  withVerification?: boolean;

  /** Custom metadata */
  metadata?: Record<string, string>;
}

/**
 * Loan application response
 */
export interface LoanApplicationResponse {
  /** Application ID */
  applicationId: string;

  /** Status */
  status: 'pending' | 'processing' | 'completed' | 'failed';

  /** Result if completed */
  result?: CreditScoringResult;

  /** Error if failed */
  error?: string;

  /** Created at */
  createdAt: string;

  /** Completed at */
  completedAt?: string;
}

/**
 * Batch scoring request
 */
export interface BatchScoringRequest {
  /** Applications to score */
  applications: LoanApplicationRequest[];

  /** Whether to run in parallel */
  parallel?: boolean;

  /** Whether to request verification for all */
  withVerification?: boolean;
}

/**
 * Batch scoring response
 */
export interface BatchScoringResponse {
  /** Batch ID */
  batchId: string;

  /** Total applications */
  total: number;

  /** Completed count */
  completed: number;

  /** Failed count */
  failed: number;

  /** Results */
  results: LoanApplicationResponse[];

  /** Processing time */
  processingTimeMs: number;
}

/**
 * Credit scoring model info
 */
export interface CreditScoringModel {
  /** Model ID */
  modelId: string;

  /** Model name */
  name: string;

  /** Model version */
  version: string;

  /** Description */
  description?: string;

  /** Model hash */
  modelHash: string;

  /** Status */
  status: 'active' | 'inactive' | 'deprecated';

  /** Input schema */
  inputSchema: {
    featureCount: number;
    requiredFeatures: string[];
  };

  /** Model metrics */
  metrics?: {
    aucRoc: number;
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
    ksStatistic: number;
  };

  /** Compliance info */
  compliance?: {
    frameworks: string[];
    lastAuditDate?: string;
  };

  /** Usage count */
  usageCount: number;

  /** Registered at */
  registeredAt: string;
}

/**
 * Demo scenario
 */
export interface DemoScenario {
  /** Scenario ID */
  id: string;

  /** Scenario name */
  name: string;

  /** Description */
  description: string;

  /** Category */
  category: string;

  /** Expected decision */
  expectedDecision: LoanDecision;

  /** Loan type */
  loanType: LoanType;

  /** Loan amount */
  loanAmount: number;

  /** Loan term */
  loanTermMonths: number;

  /** Pre-filled features */
  features: CreditFeatures;
}

/**
 * Pipeline metrics
 */
export interface PipelineMetrics {
  /** Total applications received */
  totalApplications: number;

  /** Processed applications */
  processedApplications: number;

  /** Approved count */
  approvedApplications: number;

  /** Denied count */
  deniedApplications: number;

  /** Manual review count */
  reviewApplications: number;

  /** Failed count */
  failedApplications: number;

  /** Average score */
  averageScore: number;

  /** Average processing time */
  averageProcessingTimeMs: number;

  /** Score distribution */
  scoreDistribution: {
    excellent: number;
    good: number;
    fair: number;
    poor: number;
    veryPoor: number;
  };
}
