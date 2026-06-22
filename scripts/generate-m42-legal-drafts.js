#!/usr/bin/env node
/**
 * Generate the M42 LOI and MOU legal-draft Word documents.
 *
 * Sources of truth: docs/operations/m42-loi-draft.md and m42-mou-draft.md.
 * Output: M42/Aethelred_M42_LOI_Draft_v1_0.docx and
 *         M42/Aethelred_M42_MOU_Draft_v1_0.docx
 *
 * Word (not PDF) because these drafts go to counsel for redlining.
 * Run with: NODE_PATH="$(npm root -g)" node scripts/generate-m42-legal-drafts.js
 */

const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  AlignmentType, BorderStyle, WidthType, ShadingType, Header, Footer,
  PageNumber, PageBreak, TabStopType, TabStopPosition,
} = require("docx");

const BASE = path.resolve(__dirname, "..");
const OUT_DIR = path.join(BASE, "M42");

const RED = "9F0A24";
const GRAY = "6B7280";
const DARK = "111827";
const RULE = "CCCCCC";
const HEAD_FILL = "F3F4F6";

// A4 with 1" margins -> content width 9026 DXA.
const CONTENT_W = 9026;

const cellBorder = { style: BorderStyle.SINGLE, size: 1, color: RULE };
// OOXML schema order: top, left, bottom, right (docx-js serializes insertion order).
const cellBorders = { top: cellBorder, left: cellBorder, bottom: cellBorder, right: cellBorder };
const cellMargins = { top: 80, bottom: 80, left: 120, right: 120 };

function body(text, opts = {}) {
  return new Paragraph({
    spacing: { after: 160, line: 300 },
    alignment: AlignmentType.JUSTIFIED,
    children: [new TextRun({ text, size: 21, color: DARK, ...opts })],
  });
}

function clause(text) {
  return body(text);
}

function sectionHeading(text) {
  return new Paragraph({
    spacing: { before: 280, after: 140 },
    children: [new TextRun({ text, bold: true, size: 23, color: DARK })],
  });
}

function noticeBox(lines) {
  // A single-cell table rather than bordered paragraphs: docx-js serializes
  // w:pBdr children in a schema-invalid order when bottom + left/right mix,
  // while w:tcBorders serialize correctly.
  const border = { style: BorderStyle.SINGLE, size: 6, color: RED };
  return [
    new Table({
      width: { size: CONTENT_W, type: WidthType.DXA },
      columnWidths: [CONTENT_W],
      rows: [new TableRow({
        children: [new TableCell({
          borders: { top: border, left: border, bottom: border, right: border },
          width: { size: CONTENT_W, type: WidthType.DXA },
          margins: { top: 120, bottom: 120, left: 160, right: 160 },
          children: lines.map((line, i) => new Paragraph({
            spacing: { after: i === lines.length - 1 ? 0 : 60 },
            children: [new TextRun({ text: line, bold: i === 0, size: 18, color: RED })],
          })),
        })],
      })],
    }),
    new Paragraph({ spacing: { after: 120 }, children: [] }),
  ];
}

function partyBlock(label, lines) {
  const out = [
    new Paragraph({
      spacing: { before: 120, after: 40 },
      children: [new TextRun({ text: label, bold: true, size: 21, color: DARK })],
    }),
  ];
  for (const line of lines) {
    out.push(new Paragraph({
      spacing: { after: 40 },
      children: [new TextRun({ text: line, size: 21, color: DARK })],
    }));
  }
  return out;
}

function signatureBlocks() {
  const blocks = [];
  for (const party of ["For M42:", "For Aethelred:"]) {
    blocks.push(new Paragraph({
      spacing: { before: 480, after: 60 },
      children: [new TextRun({ text: party, bold: true, size: 21, color: DARK })],
    }));
    for (const field of ["Signature:", "Name:", "Title:", "Date:"]) {
      blocks.push(new Paragraph({
        spacing: { after: 120 },
        tabStops: [{ type: TabStopType.LEFT, position: 1800 }, { type: TabStopType.RIGHT, position: 7200 }],
        children: [
          new TextRun({ text: field, size: 21, color: DARK }),
          new TextRun({ text: "\t" }),
          new TextRun({ text: "_______________________________________", size: 21, color: GRAY }),
        ],
      }));
    }
  }
  return blocks;
}

function decisionTable(rows) {
  const widths = [600, 2400, 3000, 3026];
  const headerCells = ["#", "Decision", "Options", "Recommendation"].map((text, i) =>
    new TableCell({
      borders: cellBorders,
      width: { size: widths[i], type: WidthType.DXA },
      shading: { fill: HEAD_FILL, type: ShadingType.CLEAR },
      margins: cellMargins,
      children: [new Paragraph({ children: [new TextRun({ text, bold: true, size: 19, color: DARK })] })],
    })
  );
  const bodyRows = rows.map((row) =>
    new TableRow({
      children: row.map((text, i) =>
        new TableCell({
          borders: cellBorders,
          width: { size: widths[i], type: WidthType.DXA },
          margins: cellMargins,
          children: [new Paragraph({ children: [new TextRun({ text, size: 19, color: DARK })] })],
        })
      ),
    })
  );
  return new Table({
    width: { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: widths,
    rows: [new TableRow({ tableHeader: true, children: headerCells }), ...bodyRows],
  });
}

function internalPage(rows) {
  return [
    new Paragraph({ children: [new PageBreak()] }),
    ...noticeBox([
      "INTERNAL — AETHELRED ONLY — REMOVE THIS PAGE BEFORE SENDING TO M42",
      "Open decision points to resolve with counsel before the draft is shared externally.",
    ]),
    decisionTable(rows),
  ];
}

function buildDoc({ title, headerLabel, children }) {
  return new Document({
    creator: "Ramesh Tamilselvan",
    title,
    styles: { default: { document: { run: { font: "Arial", size: 21 } } } },
    sections: [{
      properties: {
        page: {
          size: { width: 11906, height: 16838 }, // A4
          margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
        },
      },
      headers: {
        default: new Header({
          children: [new Paragraph({
            tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
            border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: RED, space: 2 } },
            children: [
              new TextRun({ text: headerLabel, bold: true, size: 14, color: RED }),
              new TextRun({ text: "\tDRAFT FOR LEGAL REVIEW · V1.0 · JUNE 2026", size: 14, color: GRAY }),
            ],
          })],
        }),
      },
      footers: {
        default: new Footer({
          children: [new Paragraph({
            tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
            border: { top: { style: BorderStyle.SINGLE, size: 4, color: RULE, space: 2 } },
            children: [
              new TextRun({ text: "Confidential · Working draft · No legal effect", size: 14, color: GRAY }),
              new TextRun({ text: "\t", size: 14 }),
              new TextRun({ children: ["Page ", PageNumber.CURRENT, " of ", PageNumber.TOTAL_PAGES], size: 14, color: GRAY }),
            ],
          })],
        }),
      },
      children,
    }],
  });
}

// ---------------------------------------------------------------------------
// LOI
// ---------------------------------------------------------------------------

const loiChildren = [
  ...noticeBox([
    "DRAFT FOR LEGAL REVIEW — NOT A LEGAL INSTRUMENT",
    "Working draft prepared by Aethelred for discussion. Not reviewed by counsel for either party; creates no obligations. Bracketed fields are open decision points.",
  ]),
  new Paragraph({
    spacing: { before: 120, after: 240 },
    alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "LETTER OF INTENT", bold: true, size: 32, color: DARK })],
  }),
  new Paragraph({
    spacing: { after: 240 },
    alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "M42 × Aethelred — Next-Phase Deployment", size: 23, color: GRAY })],
  }),
  ...partyBlock("Between:", [
    "[M42 legal entity name], a company incorporated in [Abu Dhabi, UAE] (“M42”)",
  ]),
  ...partyBlock("And:", [
    "[Aethelred Labs Ltd, an entity in formation under the Abu Dhabi Global Market (“ADGM”)] (“Aethelred”), represented pending registration by Ramesh Tamilselvan, Founder.",
  ]),
  ...partyBlock("Date:", ["[____], 2026"]),

  sectionHeading("1. Purpose"),
  clause("This Letter of Intent (“LOI”) records the parties’ mutual, non-binding intent to negotiate a next-phase deployment of Aethelred’s sovereign verified AI compute and evidence layer for M42 workloads, following the completion of the four-week paid evaluation pilot (the “Pilot”) described in the Sovereign Verified AI Compute business case dated June 2026."),

  sectionHeading("2. Background"),
  clause("2.1. M42 engaged Aethelred for a $200,000 paid Pilot on the synthetic Med42-compatible evaluation workload m42-med42-synthetic-eval, executed in a dedicated sandbox with no access to M42 production systems and no live patient data."),
  clause("2.2. The Pilot acceptance bar was: (a) 100% hybrid TEE + zkML + Digital Seal evidence coverage for accepted cases; (b) zero accepted single-evidence fallback cases; (c) zero live PHI introduced; (d) six of six negative controls rejected; (e) a completed value-bank scorecard reviewed with the M42 sponsor; (f) a go/no-go recommendation with owners, risks, and next-phase budget logic."),
  clause("2.3. The Pilot results were presented to the M42 executive value board on [date], with the outcome recorded in the executive readout and value scorecard delivered to M42."),

  sectionHeading("3. Intended Next Phase"),
  clause("Subject to definitive agreements, the parties intend to negotiate a next-phase engagement comprising one or more of the following, as selected by M42 at the executive value board:"),
  clause("[   ]  Option A — Expanded Med42 evaluation: a larger Med42 evaluation workload under the same evidence contract, with an expanded case volume and M42-approved model checkpoint digests."),
  clause("[   ]  Option B — De-identified retrospective clinical AI: introduction of M42-approved, de-identified retrospective data under a written scope change and M42 governance approval, per the Pilot’s data-boundary protocol."),
  clause("[   ]  Option C — Genomics workload: a retrospective genomic variant interpretation or pipeline workload under the sovereign evidence contract."),
  clause("Indicative next-phase commercial range: [$____ to $____] over [__] months, to be defined in a statement of work."),

  sectionHeading("4. Intended Terms of the Next Phase"),
  clause("4.1. Evidence contract. Accepted production-track jobs require hybrid TEE attestation, zkML proof evidence, validator signature, and a Digital Seal, consistent with the Pilot’s evidence schema. Fallback evidence modes are not accepted deliverables."),
  clause("4.2. Data sovereignty. All workload data remains within [UAE / Abu Dhabi]-approved boundaries. Jurisdiction, data class, consent scope, and retention are fixed in workload policy metadata before execution."),
  clause("4.3. No production dependency. Until definitive agreements state otherwise, no M42 production system shall depend on Aethelred infrastructure."),
  clause("4.4. Infrastructure reuse. The sandbox topology, monitoring, archive, gate register, and evidence tooling delivered during the Pilot remain available to M42 for the next phase."),

  sectionHeading("5. Exclusivity and Announcement"),
  clause("5.1. [Optional — DECISION POINT: include or strike] For [90] days from signature, Aethelred will not initiate a competing healthcare-AI assurance pilot with another [UAE-based] healthcare provider, and M42 will negotiate the next phase exclusively with Aethelred for the workloads named in Section 3."),
  clause("5.2. Neither party will make any public announcement, use the other’s name or marks, or characterize the relationship publicly without prior written approval of the other party."),

  sectionHeading("6. Strategic Discussions"),
  clause("The parties acknowledge that M42’s corporate development function and Aethelred are separately engaged in discussions regarding a potential strategic investment in Aethelred. Those discussions are independent of this LOI, are not a condition of this LOI or of any next-phase engagement, and are governed by their own documentation."),

  sectionHeading("7. Non-Binding Effect"),
  clause("Except for Sections 5.2 (announcements), 8 (confidentiality), and 9 (costs), this LOI is non-binding and creates no obligation on either party to negotiate, execute, or perform any agreement. Any binding commitment requires definitive written agreements executed after Aethelred’s ADGM entity registration is complete and after each party’s internal approvals and legal review."),

  sectionHeading("8. Confidentiality"),
  clause("The parties will keep the contents of this LOI, the Pilot artifacts, and all evidence bundles confidential under the [existing NDA dated ____ / confidentiality terms to be agreed], except for disclosures required to advisers and regulators."),

  sectionHeading("9. Costs"),
  clause("Each party bears its own costs in connection with this LOI and any subsequent negotiation."),

  sectionHeading("10. Governing Framework"),
  clause("This LOI is to be read under the laws of [the Abu Dhabi Global Market]. Any definitive agreements will state their own governing law and dispute resolution terms."),

  ...signatureBlocks(),

  ...internalPage([
    ["1", "Next-phase commercial range in §3", "Leave blank for board / pre-fill an anchor", "Pre-fill an anchor range; anchoring at the board is stronger than an open blank"],
    ["2", "Exclusivity §5.1", "Include mutual 90-day / strike entirely", "Include — mutual exclusivity is cheap for Aethelred today and signals seriousness"],
    ["3", "Which §3 options to present pre-checked", "A, B, C", "Present all three unchecked; let the board choose — choice architecture beats prescription"],
    ["4", "LOI vs MOU", "This LOI / the MOU draft", "LOI if the value board lands decisively; MOU if M42 wants partnership framing without a commercial number"],
  ]),
];

// ---------------------------------------------------------------------------
// MOU
// ---------------------------------------------------------------------------

const mouChildren = [
  ...noticeBox([
    "DRAFT FOR LEGAL REVIEW — NOT A LEGAL INSTRUMENT",
    "Working draft prepared by Aethelred for discussion. Not reviewed by counsel for either party; creates no obligations. Bracketed fields are open decision points. Use this instrument instead of the LOI when M42 prefers a strategic-partnership frame without a next-phase commercial range.",
  ]),
  new Paragraph({
    spacing: { before: 120, after: 240 },
    alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "MEMORANDUM OF UNDERSTANDING", bold: true, size: 32, color: DARK })],
  }),
  new Paragraph({
    spacing: { after: 240 },
    alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "M42 × Aethelred — Strategic Collaboration", size: 23, color: GRAY })],
  }),
  ...partyBlock("Between:", ["[M42 legal entity name] (“M42”)"]),
  ...partyBlock("And:", ["[Aethelred Labs Ltd, in formation under ADGM] (“Aethelred”)"]),
  ...partyBlock("Date:", ["[____], 2026"]),

  sectionHeading("1. Purpose"),
  clause("This Memorandum of Understanding (“MOU”) records the parties’ shared intent to collaborate on sovereign, verifiable AI compute infrastructure for regulated healthcare workloads, following the four-week paid evaluation pilot completed on [date]."),

  sectionHeading("2. Shared Objectives"),
  clause("2.1. Establish independently verifiable evidence — TEE attestation, zkML proof, and Digital Seal — as the assurance standard for M42’s regulated AI workloads sold to sovereign and enterprise buyers."),
  clause("2.2. Keep sensitive health and genomic data within approved jurisdictional boundaries while making results verifiable across borders."),
  clause("2.3. Position the UAE as the reference deployment for sovereign verified AI compute in healthcare."),

  sectionHeading("3. Areas of Collaboration"),
  clause("The parties intend to explore, without obligation:"),
  clause("a. Next-phase workloads. Expanded Med42 evaluation, de-identified retrospective clinical AI, or genomics workloads under the pilot’s evidence contract, each subject to its own statement of work."),
  clause("b. Joint working group. A standing technical working group ([quarterly / monthly]) covering evidence schema evolution, regulatory alignment (UAE data protection, NIST AI RMF, ISO/IEC 42001), and workload prioritization."),
  clause("c. Validator participation. Evaluation of M42 operating validator capacity on its approved infrastructure under Aethelred’s Proof of Useful Work design, subject to the independence conditions described in the business case (no single party controls consensus; rewards structured under the ADGM virtual-asset framework with tax and accounting review)."),
  clause("d. Reference and co-marketing. Subject to Section 6, jointly approved case studies or reference materials describing the pilot methodology and evidence model."),

  sectionHeading("4. Strategic Investment Acknowledgment"),
  clause("The parties acknowledge that discussions regarding a potential strategic investment by [M42 / its corporate development affiliate] in Aethelred may proceed in parallel. Such discussions are independent of this MOU, are not a condition of any collaboration described here, and will be governed by their own documentation and approvals."),

  sectionHeading("5. Status and Non-Binding Effect"),
  clause("5.1. This MOU is a statement of intent. Except for Sections 6 (announcements and confidentiality) and 7 (costs), it is non-binding and creates no legal obligation, partnership, agency, or joint venture."),
  clause("5.2. Any binding engagement requires definitive agreements executed after Aethelred’s ADGM entity registration completes and after each party’s internal approvals and legal review."),
  clause("5.3. No M42 production system shall depend on Aethelred infrastructure under this MOU."),

  sectionHeading("6. Announcements and Confidentiality"),
  clause("6.1. Neither party will make public announcements about this MOU or the collaboration, or use the other’s name or marks, without prior written approval."),
  clause("6.2. Pilot artifacts, evidence bundles, and the contents of this MOU remain confidential under [existing NDA dated ____ / terms to be agreed]."),

  sectionHeading("7. Costs"),
  clause("Each party bears its own costs."),

  sectionHeading("8. Term and Review"),
  clause("This MOU takes effect on signature and continues for [12] months unless extended in writing or superseded by definitive agreements. The parties will review progress at the joint working group every [quarter]."),

  sectionHeading("9. Governing Framework"),
  clause("This MOU is to be read under the laws of [the Abu Dhabi Global Market]."),

  ...signatureBlocks(),

  ...internalPage([
    ["1", "LOI or MOU at the Week 4 board", "LOI (commercial) / MOU (strategic)", "Bring both; lead with LOI if the value scorecard lands at or above target, fall back to MOU"],
    ["2", "Validator clause §3c", "Include / defer to investment docs", "Include — it plants the equity-aligned role in the commercial track too"],
    ["3", "Working group cadence", "Monthly / quarterly", "Monthly for the first quarter, then quarterly; early cadence builds the dependency"],
    ["4", "Term length §8", "6 / 12 / 18 months", "12 months — long enough to span testnet launch, short enough to force renewal contact"],
  ]),
];

// ---------------------------------------------------------------------------

async function main() {
  const docs = [
    {
      out: path.join(OUT_DIR, "Aethelred_M42_LOI_Draft_v1_0.docx"),
      doc: buildDoc({
        title: "Letter of Intent (Draft) — M42 × Aethelred Next-Phase Deployment",
        headerLabel: "AETHELRED × M42 · LETTER OF INTENT",
        children: loiChildren,
      }),
    },
    {
      out: path.join(OUT_DIR, "Aethelred_M42_MOU_Draft_v1_0.docx"),
      doc: buildDoc({
        title: "Memorandum of Understanding (Draft) — M42 × Aethelred Strategic Collaboration",
        headerLabel: "AETHELRED × M42 · MEMORANDUM OF UNDERSTANDING",
        children: mouChildren,
      }),
    },
  ];
  for (const { out, doc } of docs) {
    const buffer = await Packer.toBuffer(doc);
    fs.writeFileSync(out, buffer);
    console.log(`Wrote ${out}`);
  }
}

main().catch((err) => { console.error(err); process.exit(1); });
