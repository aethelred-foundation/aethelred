// ============================================================
// Shiora on Aethelred — Genomics Reports API
// GET /api/genomics/reports — Generated genomic reports
// POST /api/genomics/reports — Queue a new genomic report
// ============================================================

import { NextRequest } from 'next/server';
import { successResponse, errorResponse, HTTP } from '@/lib/api/responses';
import { runMiddleware } from '@/lib/api/middleware';
import { seededHex, seededInt, seededPick, generateAttestation } from '@/lib/utils';

import type { GenomicReport } from '@/types';

const SEED = 2660;

const REPORT_CATEGORIES = [
  'General',
  'Pharmacogenomics',
  'Polygenic Risk',
  'Biomarkers',
  'Clinical Summary',
] as const;

function reportSummary(category: string) {
  return `${category} analysis with TEE-verified genomic findings, prioritized care actions, and clinician-ready notes.`;
}

function generateReports(): GenomicReport[] {
  return Array.from({ length: 5 }, (_, i) => {
    const category = REPORT_CATEGORIES[i % REPORT_CATEGORIES.length];
    const generatedAt = Date.now() - (i + 1) * 9 * 86_400_000;

    return {
      id: `gen-report-${seededHex(SEED + i * 10, 10)}`,
      title: `${category} Genomic Report`,
      category,
      generatedAt,
      summary: reportSummary(category),
      findings: seededInt(SEED + i * 11, 3, 14),
      actionableItems: seededInt(SEED + i * 12, 1, 6),
      teeVerified: true,
      attestation: generateAttestation(SEED + i * 13),
      status: seededPick(SEED + i * 14, ['ready', 'ready', 'reviewed', 'shared'] as const),
    };
  });
}

export async function GET(request: NextRequest) {
  const blocked = runMiddleware(request);
  if (blocked) return blocked;

  try {
    return successResponse(generateReports());
  } catch {
    return errorResponse('INTERNAL_ERROR', 'Failed to fetch genomic reports', HTTP.INTERNAL);
  }
}

export async function POST(request: NextRequest) {
  const blocked = runMiddleware(request);
  if (blocked) return blocked;

  let body: { category?: string } = {};
  try {
    body = (await request.json()) as { category?: string };
  } catch {
    return errorResponse('INVALID_BODY', 'Request body must be valid JSON', HTTP.BAD_REQUEST);
  }

  const category = body.category?.trim() || 'General';

  try {
    const report: GenomicReport = {
      id: `gen-report-${seededHex(SEED + 999, 10)}`,
      title: `${category} Genomic Report`,
      category,
      generatedAt: Date.now(),
      summary: reportSummary(category),
      findings: seededInt(SEED + 1000, 2, 10),
      actionableItems: seededInt(SEED + 1001, 1, 5),
      teeVerified: true,
      attestation: generateAttestation(SEED + 1002),
      status: 'generating',
    };

    return successResponse(report, HTTP.CREATED);
  } catch {
    return errorResponse('INTERNAL_ERROR', 'Failed to create genomic report', HTTP.INTERNAL);
  }
}
