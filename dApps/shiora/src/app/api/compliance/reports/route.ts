// ============================================================
// Shiora on Aethelred — Compliance Reports API
// GET /api/compliance/reports — Generated compliance reports
// POST /api/compliance/reports — Create a draft compliance report
// ============================================================

import { NextRequest } from 'next/server';
import { successResponse, errorResponse, HTTP } from '@/lib/api/responses';
import { runMiddleware } from '@/lib/api/middleware';
import { seededHex, seededInt, seededPick } from '@/lib/utils';

import type { ComplianceFrameworkId, ComplianceReport, GenerateReportForm } from '@/types';

const SEED = 2440;

const FRAMEWORK_IDS: ComplianceFrameworkId[] = ['hipaa', 'gdpr', 'soc2', 'hitrust', 'fda_21cfr11'];

const FRAMEWORK_NAMES: Record<ComplianceFrameworkId, string> = {
  hipaa: 'HIPAA',
  gdpr: 'GDPR',
  soc2: 'SOC 2',
  hitrust: 'HITRUST',
  fda_21cfr11: 'FDA 21 CFR 11',
};

function buildReportTitle(frameworkId: ComplianceFrameworkId) {
  return `${FRAMEWORK_NAMES[frameworkId]} Compliance Report`;
}

function defaultPeriod() {
  const end = Date.now();
  return { start: end - 90 * 86_400_000, end };
}

function generateReports(): ComplianceReport[] {
  return Array.from({ length: 5 }, (_, i) => {
    const frameworkId = FRAMEWORK_IDS[i % FRAMEWORK_IDS.length];
    const generatedAt = Date.now() - (i + 1) * 14 * 86_400_000;
    const findings = seededInt(SEED + i * 10, 2, 14);
    const criticalGaps = seededInt(SEED + i * 11, 0, 3);
    const overallScore = seededInt(SEED + i * 12, 81, 98);

    return {
      id: `report-${seededHex(SEED + i * 13, 10)}`,
      frameworkId,
      title: buildReportTitle(frameworkId),
      generatedAt,
      period: {
        start: generatedAt - 90 * 86_400_000,
        end: generatedAt,
      },
      overallScore,
      findings,
      criticalGaps,
      status: seededPick(SEED + i * 14, ['final', 'final', 'draft', 'archived'] as const),
    };
  });
}

export async function GET(request: NextRequest) {
  const blocked = runMiddleware(request);
  if (blocked) return blocked;

  try {
    return successResponse(generateReports());
  } catch {
    return errorResponse('INTERNAL_ERROR', 'Failed to fetch compliance reports', HTTP.INTERNAL);
  }
}

export async function POST(request: NextRequest) {
  const blocked = runMiddleware(request);
  if (blocked) return blocked;

  let form: GenerateReportForm = {};
  try {
    form = (await request.json()) as GenerateReportForm;
  } catch {
    return errorResponse('INVALID_JSON', 'Request body must be valid JSON', HTTP.BAD_REQUEST);
  }

  const frameworkId =
    form.frameworkId && FRAMEWORK_IDS.includes(form.frameworkId) ? form.frameworkId : 'hipaa';

  const period = form.period ?? defaultPeriod();

  try {
    const report: ComplianceReport = {
      id: `report-${seededHex(SEED + 999, 10)}`,
      frameworkId,
      title: buildReportTitle(frameworkId),
      generatedAt: Date.now(),
      period,
      overallScore: seededInt(SEED + 1000, 88, 96),
      findings: seededInt(SEED + 1001, 1, 8),
      criticalGaps: seededInt(SEED + 1002, 0, 2),
      status: 'draft',
    };

    return successResponse(report, HTTP.CREATED);
  } catch {
    return errorResponse('INTERNAL_ERROR', 'Failed to create compliance report', HTTP.INTERNAL);
  }
}
