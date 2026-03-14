import { PrismaClient, ComplianceStatus, PaymentStatus, Prisma } from "@prisma/client";
import { v4 as uuidv4 } from "uuid";
import crypto from "crypto";
import { logger } from "../lib/logger";
import { screeningDuration, compliancePassRate, flaggedPayments } from "../lib/metrics";
import { AuditService } from "./audit";

export interface ScreeningRequest {
  paymentId: string;
  priority: "normal" | "high" | "urgent";
}

export interface ScreeningResult {
  id: string;
  paymentId: string;
  sanctionsClear: boolean;
  amlRiskScore: number;
  travelRuleCompliant: boolean;
  status: ComplianceStatus;
  flagReason: string | null;
  screenedBy: string;
  screeningDuration: number;
}

export interface ComplianceMetrics {
  totalScreenings: number;
  passedScreenings: number;
  failedScreenings: number;
  averageRiskScore: number;
  averageScreeningDuration: number;
  passRate: number;
  flaggedCount: number;
  underReviewCount: number;
}

export interface SanctionsStatus {
  lastUpdated: Date | null;
  listsLoaded: string[];
  totalEntries: number;
  status: "fresh" | "stale" | "updating";
}

// Simulated sanctions last update
let sanctionsLastUpdated: Date | null = null;
let sanctionsUpdating = false;

export class ComplianceService {
  constructor(
    private prisma: PrismaClient,
    private auditService: AuditService,
  ) {}

  /**
   * Submit a payment for compliance screening via TEE compliance engine.
   */
  async submitForScreening(request: ScreeningRequest): Promise<ScreeningResult> {
    const startTime = Date.now();

    const payment = await this.prisma.payment.findUnique({
      where: { id: request.paymentId },
    });

    if (!payment) {
      throw new ComplianceError("PAYMENT_NOT_FOUND", "Payment not found", 404);
    }

    if (payment.status !== "PENDING") {
      throw new ComplianceError(
        "INVALID_STATE",
        `Payment is in ${payment.status} state, expected PENDING`,
        409,
      );
    }

    // Update payment status to SCREENING
    await this.prisma.payment.update({
      where: { id: payment.id },
      data: { status: "SCREENING" },
    });

    // Simulate TEE compliance engine screening
    const teeNodeAddress = await this.getActiveTEENode();
    const screeningResult = await this.performTEEScreening(payment, teeNodeAddress);
    const elapsed = Date.now() - startTime;

    // Store screening result
    const screening = await this.prisma.complianceScreening.create({
      data: {
        paymentId: payment.paymentId,
        sanctionsClear: screeningResult.sanctionsClear,
        amlRiskScore: screeningResult.amlRiskScore,
        travelRuleCompliant: screeningResult.travelRuleCompliant,
        status: screeningResult.status,
        flagReason: screeningResult.flagReason,
        investigationHash: screeningResult.investigationHash,
        screenedBy: teeNodeAddress,
        screeningDuration: elapsed,
      },
    });

    // Determine new payment status based on screening result
    let newStatus: PaymentStatus;
    if (screeningResult.status === "PASSED") {
      newStatus = "APPROVED";
    } else if (screeningResult.status === "FAILED") {
      newStatus = "REJECTED";
    } else {
      newStatus = "FLAGGED";
    }

    // Update payment
    await this.prisma.payment.update({
      where: { id: payment.id },
      data: {
        status: newStatus,
        riskScore: screeningResult.amlRiskScore,
        teeAttestation: `0x${crypto.randomBytes(32).toString("hex")}`,
        screenedAt: new Date(),
      },
    });

    // Record metrics
    const resultLabel = screeningResult.status === "PASSED" ? "passed" : "failed";
    screeningDuration.observe({ result: resultLabel }, elapsed / 1000);

    // Update pass rate gauge
    await this.updatePassRateMetric();

    // Audit entry
    const eventType =
      screeningResult.status === "PASSED"
        ? "COMPLIANCE_PASSED"
        : screeningResult.status === "FAILED"
          ? "COMPLIANCE_FAILED"
          : "COMPLIANCE_ESCALATED";

    await this.auditService.createAuditEntry({
      eventType: eventType as "COMPLIANCE_PASSED" | "COMPLIANCE_FAILED" | "COMPLIANCE_ESCALATED",
      actor: teeNodeAddress,
      description: `Compliance screening ${screeningResult.status} for payment ${payment.paymentId} (risk score: ${screeningResult.amlRiskScore})`,
      severity: screeningResult.status === "PASSED" ? "INFO" : "HIGH",
      metadata: {
        paymentId: payment.paymentId,
        amlRiskScore: screeningResult.amlRiskScore,
        sanctionsClear: screeningResult.sanctionsClear,
        screeningDuration: elapsed,
      },
    });

    logger.info("Compliance screening complete", {
      paymentId: payment.paymentId,
      status: screeningResult.status,
      riskScore: screeningResult.amlRiskScore,
      duration: elapsed,
    });

    return {
      id: screening.id,
      paymentId: payment.paymentId,
      sanctionsClear: screeningResult.sanctionsClear,
      amlRiskScore: screeningResult.amlRiskScore,
      travelRuleCompliant: screeningResult.travelRuleCompliant,
      status: screeningResult.status,
      flagReason: screeningResult.flagReason,
      screenedBy: teeNodeAddress,
      screeningDuration: elapsed,
    };
  }

  /**
   * Get screening result for a payment.
   */
  async getScreeningResult(paymentId: string) {
    const screenings = await this.prisma.complianceScreening.findMany({
      where: { paymentId },
      orderBy: { createdAt: "desc" },
    });

    if (screenings.length === 0) {
      throw new ComplianceError("SCREENING_NOT_FOUND", "No screening found for this payment", 404);
    }

    return screenings;
  }

  /**
   * Get compliance metrics.
   */
  async getComplianceMetrics(): Promise<ComplianceMetrics> {
    const [total, passed, failed, avgRisk, avgDuration, flaggedCount, underReview] =
      await Promise.all([
        this.prisma.complianceScreening.count(),
        this.prisma.complianceScreening.count({ where: { status: "PASSED" } }),
        this.prisma.complianceScreening.count({ where: { status: "FAILED" } }),
        this.prisma.complianceScreening.aggregate({ _avg: { amlRiskScore: true } }),
        this.prisma.complianceScreening.aggregate({ _avg: { screeningDuration: true } }),
        this.prisma.payment.count({ where: { status: "FLAGGED" } }),
        this.prisma.complianceScreening.count({ where: { status: "UNDER_REVIEW" } }),
      ]);

    const passRate = total > 0 ? passed / total : 0;

    return {
      totalScreenings: total,
      passedScreenings: passed,
      failedScreenings: failed,
      averageRiskScore: avgRisk._avg.amlRiskScore || 0,
      averageScreeningDuration: avgDuration._avg.screeningDuration || 0,
      passRate,
      flaggedCount,
      underReviewCount: underReview,
    };
  }

  /**
   * Trigger a sanctions list refresh.
   */
  async updateSanctionsList(): Promise<{ status: string; message: string }> {
    if (sanctionsUpdating) {
      return { status: "in_progress", message: "Sanctions list update already in progress" };
    }

    sanctionsUpdating = true;

    // Simulate async sanctions list update
    setTimeout(() => {
      sanctionsLastUpdated = new Date();
      sanctionsUpdating = false;
      logger.info("Sanctions list updated");
    }, 2000);

    await this.auditService.createAuditEntry({
      eventType: "SANCTIONS_UPDATED",
      actor: "system",
      description: "Sanctions list refresh triggered",
      severity: "INFO",
    });

    return { status: "started", message: "Sanctions list update initiated" };
  }

  /**
   * Get sanctions list freshness status.
   */
  getSanctionsStatus(): SanctionsStatus {
    const lists = ["OFAC-SDN", "EU-CONSOLIDATED", "UN-SANCTIONS", "UK-HMT"];
    const staleThreshold = 24 * 60 * 60 * 1000; // 24 hours

    let status: "fresh" | "stale" | "updating" = "stale";
    if (sanctionsUpdating) {
      status = "updating";
    } else if (sanctionsLastUpdated && Date.now() - sanctionsLastUpdated.getTime() < staleThreshold) {
      status = "fresh";
    }

    return {
      lastUpdated: sanctionsLastUpdated,
      listsLoaded: lists,
      totalEntries: 12847, // Simulated
      status,
    };
  }

  /**
   * Get flagged payments awaiting review.
   */
  async getFlaggedPayments(page: number = 1, limit: number = 20) {
    const [data, total] = await Promise.all([
      this.prisma.payment.findMany({
        where: { status: "FLAGGED" },
        include: { screenings: true },
        orderBy: { initiatedAt: "desc" },
        skip: (page - 1) * limit,
        take: limit,
      }),
      this.prisma.payment.count({ where: { status: "FLAGGED" } }),
    ]);

    flaggedPayments.set(total);

    return {
      data,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
    };
  }

  /**
   * Review a flagged payment and submit a decision.
   */
  async reviewFlaggedPayment(
    paymentId: string,
    decision: "approve" | "reject" | "escalate",
    reason: string,
    reviewerAddress: string,
  ) {
    const payment = await this.prisma.payment.findUnique({
      where: { id: paymentId },
    });

    if (!payment) {
      throw new ComplianceError("PAYMENT_NOT_FOUND", "Payment not found", 404);
    }

    if (payment.status !== "FLAGGED") {
      throw new ComplianceError(
        "INVALID_STATE",
        `Payment is in ${payment.status} state, expected FLAGGED`,
        409,
      );
    }

    let newPaymentStatus: PaymentStatus;
    let complianceStatus: ComplianceStatus;

    switch (decision) {
      case "approve":
        newPaymentStatus = "APPROVED";
        complianceStatus = "PASSED";
        break;
      case "reject":
        newPaymentStatus = "REJECTED";
        complianceStatus = "FAILED";
        break;
      case "escalate":
        newPaymentStatus = "FLAGGED";
        complianceStatus = "ESCALATED";
        break;
    }

    // Update payment status
    await this.prisma.payment.update({
      where: { id: payment.id },
      data: { status: newPaymentStatus },
    });

    // Update latest screening
    const latestScreening = await this.prisma.complianceScreening.findFirst({
      where: { paymentId: payment.paymentId },
      orderBy: { createdAt: "desc" },
    });

    if (latestScreening) {
      await this.prisma.complianceScreening.update({
        where: { id: latestScreening.id },
        data: {
          status: complianceStatus,
          flagReason: reason,
          investigationHash: `0x${crypto.createHash("sha256").update(`${paymentId}:${decision}:${reason}:${Date.now()}`).digest("hex")}`,
        },
      });
    }

    await this.auditService.createAuditEntry({
      eventType: decision === "approve" ? "COMPLIANCE_PASSED" : decision === "reject" ? "COMPLIANCE_FAILED" : "COMPLIANCE_ESCALATED",
      actor: reviewerAddress,
      description: `Flagged payment ${payment.paymentId} reviewed: ${decision} — ${reason}`,
      severity: decision === "escalate" ? "HIGH" : "MEDIUM",
      metadata: { paymentId: payment.paymentId, decision, reason },
    });

    logger.info("Flagged payment reviewed", {
      paymentId: payment.paymentId,
      decision,
      reviewer: reviewerAddress,
    });

    return {
      paymentId: payment.paymentId,
      decision,
      newStatus: newPaymentStatus,
      reviewedBy: reviewerAddress,
      reviewedAt: new Date(),
    };
  }

  // ─── Private Helpers ────────────────────────────────────────────────────────

  private async getActiveTEENode(): Promise<string> {
    const node = await this.prisma.tEENode.findFirst({
      where: { status: "ACTIVE", attestationValid: true },
      orderBy: { lastHeartbeat: "desc" },
    });

    return node?.address || "0x0000000000000000000000000000000000000001";
  }

  private async performTEEScreening(
    payment: { sender: string; recipient: string; amount: Prisma.Decimal; currency: string },
    _teeNode: string,
  ): Promise<{
    sanctionsClear: boolean;
    amlRiskScore: number;
    travelRuleCompliant: boolean;
    status: ComplianceStatus;
    flagReason: string | null;
    investigationHash: string | null;
  }> {
    // Simulate TEE compliance engine processing
    // In production, this would call the actual TEE enclave via remote attestation
    const amount = parseFloat(payment.amount.toString());
    const riskScore = Math.floor(Math.random() * 100);
    const sanctionsClear = riskScore < 85;
    const travelRuleCompliant = amount < 1000 || riskScore < 70;

    let status: ComplianceStatus;
    let flagReason: string | null = null;

    if (!sanctionsClear) {
      status = "FAILED";
      flagReason = "Sanctions match detected";
    } else if (riskScore > 70) {
      status = "UNDER_REVIEW";
      flagReason = `High risk score: ${riskScore}`;
    } else if (!travelRuleCompliant) {
      status = "UNDER_REVIEW";
      flagReason = "Travel rule compliance verification required";
    } else {
      status = "PASSED";
    }

    const investigationHash = flagReason
      ? `0x${crypto.createHash("sha256").update(`${payment.sender}:${riskScore}:${Date.now()}`).digest("hex")}`
      : null;

    return {
      sanctionsClear,
      amlRiskScore: riskScore,
      travelRuleCompliant,
      status,
      flagReason,
      investigationHash,
    };
  }

  private async updatePassRateMetric(): Promise<void> {
    const [total, passed] = await Promise.all([
      this.prisma.complianceScreening.count(),
      this.prisma.complianceScreening.count({ where: { status: "PASSED" } }),
    ]);

    if (total > 0) {
      compliancePassRate.set(passed / total);
    }
  }
}

// ─── Error Class ────────────────────────────────────────────────────────────

export class ComplianceError extends Error {
  constructor(
    public code: string,
    message: string,
    public statusCode: number = 400,
  ) {
    super(message);
    this.name = "ComplianceError";
  }
}
