/**
 * Aethelred SDK Builders
 *
 * Fluent builders for constructing complex requests and objects.
 */

import {
  CreditFeatures,
  LoanApplicationRequest,
  LoanType,
} from '../types/credit-scoring';

import {
  SubmitJobRequest,
  ProofType,
  JobPriority,
} from '../types/compute';

import {
  CreateSealRequest,
} from '../types/seal';

import { sha256Hex, hashJSON } from '../crypto';

// ============ Seal Builder ============

/**
 * Fluent builder for creating seal requests
 */
export class SealBuilder {
  private request: Partial<CreateSealRequest> = {};

  /**
   * Set model hash
   */
  model(hash: string): this;
  model(data: Buffer): this;
  model(hashOrData: string | Buffer): this {
    this.request.modelHash = typeof hashOrData === 'string'
      ? hashOrData
      : sha256Hex(hashOrData);
    return this;
  }

  /**
   * Set input hash
   */
  input(hash: string): this;
  input(data: unknown): this;
  input(hashOrData: string | unknown): this {
    this.request.inputHash = typeof hashOrData === 'string'
      ? hashOrData
      : hashJSON(hashOrData);
    return this;
  }

  /**
   * Set output hash
   */
  output(hash: string): this;
  output(data: unknown): this;
  output(hashOrData: string | unknown): this {
    this.request.outputHash = typeof hashOrData === 'string'
      ? hashOrData
      : hashJSON(hashOrData);
    return this;
  }

  /**
   * Set purpose
   */
  purpose(purpose: string): this {
    this.request.purpose = purpose;
    return this;
  }

  /**
   * Add metadata
   */
  metadata(key: string, value: string): this;
  metadata(data: Record<string, string>): this;
  metadata(keyOrData: string | Record<string, string>, value?: string): this {
    if (!this.request.metadata) {
      this.request.metadata = {};
    }

    if (typeof keyOrData === 'string' && value !== undefined) {
      this.request.metadata[keyOrData] = value;
    } else if (typeof keyOrData === 'object') {
      this.request.metadata = { ...this.request.metadata, ...keyOrData };
    }

    return this;
  }

  /**
   * Set regulatory framework
   */
  regulatory(framework: string, compliant: boolean = true): this {
    return this.metadata(`regulatory_${framework}`, compliant ? 'compliant' : 'pending');
  }

  /**
   * Build the request
   */
  build(): CreateSealRequest {
    if (!this.request.modelHash) {
      throw new Error('Model hash is required');
    }
    if (!this.request.inputHash) {
      throw new Error('Input hash is required');
    }
    if (!this.request.outputHash) {
      throw new Error('Output hash is required');
    }

    return this.request as CreateSealRequest;
  }

  /**
   * Create a new builder
   */
  static create(): SealBuilder {
    return new SealBuilder();
  }
}

// ============ Compute Job Builder ============

/**
 * Fluent builder for compute job requests
 */
export class ComputeJobBuilder {
  private request: Partial<SubmitJobRequest> = {
    proofType: 'hybrid',
    priority: 'normal',
  };

  /**
   * Set model hash
   */
  model(hash: string): this;
  model(data: Buffer): this;
  model(hashOrData: string | Buffer): this {
    this.request.modelHash = typeof hashOrData === 'string'
      ? hashOrData
      : sha256Hex(hashOrData);
    return this;
  }

  /**
   * Set input data
   */
  inputData(data: string): this {
    this.request.inputData = data;
    this.request.inputHash = sha256Hex(data);
    return this;
  }

  /**
   * Set input hash (if data is not provided directly)
   */
  inputHash(hash: string): this {
    this.request.inputHash = hash;
    return this;
  }

  /**
   * Set input from object
   */
  input(data: unknown): this {
    const json = JSON.stringify(data);
    this.request.inputData = json;
    this.request.inputHash = hashJSON(data);
    return this;
  }

  /**
   * Set purpose
   */
  purpose(purpose: string): this {
    this.request.purpose = purpose;
    return this;
  }

  /**
   * Set proof type
   */
  proofType(type: ProofType): this {
    this.request.proofType = type;
    return this;
  }

  /**
   * Use TEE only
   */
  teeOnly(): this {
    return this.proofType('tee');
  }

  /**
   * Use zkML only
   */
  zkmlOnly(): this {
    return this.proofType('zkml');
  }

  /**
   * Use hybrid (TEE + zkML)
   */
  hybrid(): this {
    return this.proofType('hybrid');
  }

  /**
   * Set priority
   */
  priority(priority: JobPriority): this {
    this.request.priority = priority;
    return this;
  }

  /**
   * Set low priority
   */
  low(): this {
    return this.priority('low');
  }

  /**
   * Set normal priority
   */
  normal(): this {
    return this.priority('normal');
  }

  /**
   * Set high priority
   */
  high(): this {
    return this.priority('high');
  }

  /**
   * Set critical priority
   */
  critical(): this {
    return this.priority('critical');
  }

  /**
   * Set max wait time
   */
  maxWait(seconds: number): this {
    this.request.maxWaitTime = seconds;
    return this;
  }

  /**
   * Set callback URL
   */
  callback(url: string): this {
    this.request.callbackUrl = url;
    return this;
  }

  /**
   * Add metadata
   */
  metadata(key: string, value: string): this;
  metadata(data: Record<string, string>): this;
  metadata(keyOrData: string | Record<string, string>, value?: string): this {
    if (!this.request.metadata) {
      this.request.metadata = {};
    }

    if (typeof keyOrData === 'string' && value !== undefined) {
      this.request.metadata[keyOrData] = value;
    } else if (typeof keyOrData === 'object') {
      this.request.metadata = { ...this.request.metadata, ...keyOrData };
    }

    return this;
  }

  /**
   * Build the request
   */
  build(): SubmitJobRequest {
    if (!this.request.modelHash) {
      throw new Error('Model hash is required');
    }
    if (!this.request.inputHash && !this.request.inputData) {
      throw new Error('Input hash or data is required');
    }
    if (!this.request.purpose) {
      throw new Error('Purpose is required');
    }

    return this.request as SubmitJobRequest;
  }

  /**
   * Create a new builder
   */
  static create(): ComputeJobBuilder {
    return new ComputeJobBuilder();
  }
}

// ============ Credit Features Builder ============

/**
 * Fluent builder for credit features
 */
export class CreditFeaturesBuilder {
  private features: Partial<CreditFeatures> = {
    // Default values
    paymentHistory: 0.95,
    latePayments30Days: 0,
    latePayments60Days: 0,
    latePayments90Days: 0,
    creditUtilization: 0.30,
    totalCreditLimit: 25000,
    totalCreditUsed: 7500,
    creditHistoryMonths: 60,
    oldestAccountMonths: 72,
    averageAccountAgeMonths: 48,
    numCreditCards: 2,
    numInstallmentLoans: 1,
    numMortgages: 0,
    numAutoLoans: 0,
    recentInquiries: 1,
    newAccountsLast12Months: 0,
    bankruptcyHistory: false,
    collectionsCount: 0,
    publicRecordsCount: 0,
    annualIncome: 75000,
    employmentLengthMonths: 36,
    debtToIncomeRatio: 0.35,
  };

  // ============ Payment History ============

  /**
   * Set payment history (0-1)
   */
  paymentHistory(value: number): this {
    this.features.paymentHistory = Math.max(0, Math.min(1, value));
    return this;
  }

  /**
   * Set perfect payment history
   */
  perfectPayments(): this {
    return this.paymentHistory(1.0)
      .latePayments(0, 0, 0);
  }

  /**
   * Set late payments
   */
  latePayments(days30: number, days60: number = 0, days90: number = 0): this {
    this.features.latePayments30Days = days30;
    this.features.latePayments60Days = days60;
    this.features.latePayments90Days = days90;
    return this;
  }

  // ============ Credit Utilization ============

  /**
   * Set credit utilization (0-1)
   */
  utilization(value: number): this {
    this.features.creditUtilization = Math.max(0, Math.min(1, value));
    return this;
  }

  /**
   * Set credit limits and usage
   */
  creditUsage(limit: number, used: number): this {
    this.features.totalCreditLimit = limit;
    this.features.totalCreditUsed = used;
    this.features.creditUtilization = limit > 0 ? used / limit : 0;
    return this;
  }

  /**
   * Set low utilization (under 30%)
   */
  lowUtilization(): this {
    return this.utilization(0.15);
  }

  /**
   * Set high utilization (over 70%)
   */
  highUtilization(): this {
    return this.utilization(0.85);
  }

  // ============ Credit History ============

  /**
   * Set credit history length in months
   */
  historyMonths(months: number): this {
    this.features.creditHistoryMonths = months;
    return this;
  }

  /**
   * Set credit history in years
   */
  historyYears(years: number): this {
    return this.historyMonths(years * 12);
  }

  /**
   * Set oldest account age
   */
  oldestAccount(months: number): this {
    this.features.oldestAccountMonths = months;
    return this;
  }

  /**
   * Set average account age
   */
  averageAge(months: number): this {
    this.features.averageAccountAgeMonths = months;
    return this;
  }

  /**
   * Set long credit history (15+ years)
   */
  longHistory(): this {
    return this.historyYears(15)
      .oldestAccount(20 * 12)
      .averageAge(10 * 12);
  }

  /**
   * Set short credit history (under 2 years)
   */
  shortHistory(): this {
    return this.historyYears(2)
      .oldestAccount(24)
      .averageAge(12);
  }

  // ============ Credit Mix ============

  /**
   * Set number of credit cards
   */
  creditCards(count: number): this {
    this.features.numCreditCards = count;
    return this;
  }

  /**
   * Set number of installment loans
   */
  installmentLoans(count: number): this {
    this.features.numInstallmentLoans = count;
    return this;
  }

  /**
   * Set number of mortgages
   */
  mortgages(count: number): this {
    this.features.numMortgages = count;
    return this;
  }

  /**
   * Set number of auto loans
   */
  autoLoans(count: number): this {
    this.features.numAutoLoans = count;
    return this;
  }

  /**
   * Set diverse credit mix
   */
  diverseMix(): this {
    return this.creditCards(3)
      .installmentLoans(1)
      .mortgages(1)
      .autoLoans(1);
  }

  /**
   * Set limited credit mix
   */
  limitedMix(): this {
    return this.creditCards(1)
      .installmentLoans(0)
      .mortgages(0)
      .autoLoans(0);
  }

  // ============ New Credit ============

  /**
   * Set recent inquiries
   */
  recentInquiries(count: number): this {
    this.features.recentInquiries = count;
    return this;
  }

  /**
   * Set new accounts in last 12 months
   */
  newAccounts(count: number): this {
    this.features.newAccountsLast12Months = count;
    return this;
  }

  /**
   * Set no recent credit activity
   */
  noRecentActivity(): this {
    return this.recentInquiries(0).newAccounts(0);
  }

  // ============ Negative Factors ============

  /**
   * Set bankruptcy history
   */
  bankruptcy(hasBankruptcy: boolean = true): this {
    this.features.bankruptcyHistory = hasBankruptcy;
    return this;
  }

  /**
   * Set collections count
   */
  collections(count: number): this {
    this.features.collectionsCount = count;
    return this;
  }

  /**
   * Set public records count
   */
  publicRecords(count: number): this {
    this.features.publicRecordsCount = count;
    return this;
  }

  /**
   * Set clean record (no negative factors)
   */
  cleanRecord(): this {
    return this.bankruptcy(false)
      .collections(0)
      .publicRecords(0);
  }

  // ============ Income & Employment ============

  /**
   * Set annual income
   */
  income(amount: number): this {
    this.features.annualIncome = amount;
    return this;
  }

  /**
   * Set employment length in months
   */
  employmentMonths(months: number): this {
    this.features.employmentLengthMonths = months;
    return this;
  }

  /**
   * Set employment length in years
   */
  employmentYears(years: number): this {
    return this.employmentMonths(years * 12);
  }

  /**
   * Set debt-to-income ratio (0-1)
   */
  dti(ratio: number): this {
    this.features.debtToIncomeRatio = Math.max(0, Math.min(1, ratio));
    return this;
  }

  /**
   * Set stable employment (5+ years)
   */
  stableEmployment(): this {
    return this.employmentYears(5);
  }

  // ============ Presets ============

  /**
   * Set excellent credit profile
   */
  excellent(): this {
    return this.perfectPayments()
      .lowUtilization()
      .longHistory()
      .diverseMix()
      .noRecentActivity()
      .cleanRecord()
      .income(150000)
      .stableEmployment()
      .dti(0.25);
  }

  /**
   * Set good credit profile
   */
  good(): this {
    return this.paymentHistory(0.95)
      .latePayments(1, 0, 0)
      .utilization(0.30)
      .historyYears(7)
      .creditCards(3)
      .installmentLoans(1)
      .recentInquiries(2)
      .newAccounts(1)
      .cleanRecord()
      .income(85000)
      .employmentYears(3)
      .dti(0.35);
  }

  /**
   * Set fair credit profile
   */
  fair(): this {
    return this.paymentHistory(0.85)
      .latePayments(3, 1, 0)
      .utilization(0.55)
      .historyYears(4)
      .creditCards(4)
      .installmentLoans(2)
      .recentInquiries(4)
      .newAccounts(2)
      .collections(0)
      .income(55000)
      .employmentYears(2)
      .dti(0.42);
  }

  /**
   * Set poor credit profile
   */
  poor(): this {
    return this.paymentHistory(0.70)
      .latePayments(5, 3, 1)
      .utilization(0.85)
      .historyYears(2)
      .creditCards(3)
      .installmentLoans(2)
      .recentInquiries(6)
      .newAccounts(3)
      .collections(1)
      .income(35000)
      .employmentYears(1)
      .dti(0.55);
  }

  /**
   * Build the features
   */
  build(): CreditFeatures {
    return this.features as CreditFeatures;
  }

  /**
   * Create a new builder
   */
  static create(): CreditFeaturesBuilder {
    return new CreditFeaturesBuilder();
  }
}

// ============ Loan Application Builder ============

/**
 * Fluent builder for loan applications
 */
export class LoanApplicationBuilder {
  private request: Partial<LoanApplicationRequest> = {};
  private featuresBuilder: CreditFeaturesBuilder = new CreditFeaturesBuilder();

  /**
   * Set applicant ID
   */
  applicant(id: string): this {
    this.request.applicantId = id;
    return this;
  }

  /**
   * Set loan type
   */
  loanType(type: LoanType): this {
    this.request.loanType = type;
    return this;
  }

  /**
   * Personal loan
   */
  personal(): this {
    return this.loanType('personal');
  }

  /**
   * Mortgage loan
   */
  mortgage(): this {
    return this.loanType('mortgage');
  }

  /**
   * Auto loan
   */
  auto(): this {
    return this.loanType('auto');
  }

  /**
   * Business loan
   */
  business(): this {
    return this.loanType('business');
  }

  /**
   * Credit card
   */
  creditCard(): this {
    return this.loanType('credit_card');
  }

  /**
   * Set loan amount
   */
  amount(amount: number): this {
    this.request.loanAmount = amount;
    return this;
  }

  /**
   * Set loan term in months
   */
  termMonths(months: number): this {
    this.request.loanTermMonths = months;
    return this;
  }

  /**
   * Set loan term in years
   */
  termYears(years: number): this {
    return this.termMonths(years * 12);
  }

  /**
   * Set model ID
   */
  model(modelId: string): this {
    this.request.modelId = modelId;
    return this;
  }

  /**
   * Enable verification
   */
  withVerification(enabled: boolean = true): this {
    this.request.withVerification = enabled;
    return this;
  }

  /**
   * Set credit features directly
   */
  features(features: CreditFeatures): this {
    this.request.features = features;
    return this;
  }

  /**
   * Configure features using builder
   */
  configureFeatures(configure: (builder: CreditFeaturesBuilder) => void): this {
    configure(this.featuresBuilder);
    return this;
  }

  /**
   * Use excellent credit profile
   */
  excellentCredit(): this {
    this.featuresBuilder.excellent();
    return this;
  }

  /**
   * Use good credit profile
   */
  goodCredit(): this {
    this.featuresBuilder.good();
    return this;
  }

  /**
   * Use fair credit profile
   */
  fairCredit(): this {
    this.featuresBuilder.fair();
    return this;
  }

  /**
   * Use poor credit profile
   */
  poorCredit(): this {
    this.featuresBuilder.poor();
    return this;
  }

  /**
   * Add metadata
   */
  metadata(key: string, value: string): this;
  metadata(data: Record<string, string>): this;
  metadata(keyOrData: string | Record<string, string>, value?: string): this {
    if (!this.request.metadata) {
      this.request.metadata = {};
    }

    if (typeof keyOrData === 'string' && value !== undefined) {
      this.request.metadata[keyOrData] = value;
    } else if (typeof keyOrData === 'object') {
      this.request.metadata = { ...this.request.metadata, ...keyOrData };
    }

    return this;
  }

  /**
   * Build the request
   */
  build(): LoanApplicationRequest {
    if (!this.request.applicantId) {
      this.request.applicantId = `app-${Date.now()}`;
    }
    if (!this.request.loanType) {
      throw new Error('Loan type is required');
    }
    if (!this.request.loanAmount) {
      throw new Error('Loan amount is required');
    }
    if (!this.request.loanTermMonths) {
      throw new Error('Loan term is required');
    }

    // Use configured features if not set directly
    if (!this.request.features) {
      this.request.features = this.featuresBuilder.build();
    }

    return this.request as LoanApplicationRequest;
  }

  /**
   * Create a new builder
   */
  static create(): LoanApplicationBuilder {
    return new LoanApplicationBuilder();
  }
}

// ============ Export ============

export const builders = {
  seal: () => SealBuilder.create(),
  job: () => ComputeJobBuilder.create(),
  features: () => CreditFeaturesBuilder.create(),
  loan: () => LoanApplicationBuilder.create(),
};
