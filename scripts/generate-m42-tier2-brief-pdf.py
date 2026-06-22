#!/usr/bin/env python3
"""Render the one-page M42 Tier-2 cross-border brief as a branded PDF.

Source of truth: docs/workload-packs/m42/tier2-cross-border-brief.md.
Output: M42/Aethelred_M42_Tier2_Cross_Border_Brief_v1_0.pdf

Single page, A4, matching the v5 deck visual language (red/dark Aethelred).
"""

from __future__ import annotations

from pathlib import Path

from fpdf import FPDF


BASE = Path(__file__).resolve().parents[1]
LOGO = BASE / "frontend" / "website" / "org-v2" / "aethelred-logo.png"
OUT = BASE / "M42" / "Aethelred_M42_Tier2_Cross_Border_Brief_v1_0.pdf"

CR = (159, 10, 36)
DK = (17, 24, 39)
BD = (31, 41, 55)
MT = (107, 114, 128)
LT = (156, 163, 175)
RL = (229, 231, 235)
NB = (254, 242, 242)
TH = (243, 244, 246)
TS = (249, 250, 251)

CONTENT_W = 174.0  # A4 (210) minus 18mm margins each side


def clean(text: str) -> str:
    for old, new in {"—": "-", "–": "-", "’": "'", "‘": "'", "“": '"', "”": '"', "•": "-", "×": "x", " ": " "}.items():
        text = text.replace(old, new)
    return text.encode("latin-1", errors="replace").decode("latin-1")


ROWS = [
    [
        "De-identification & data-egress attestation",
        "Malaffi, BioBank, genome data",
        "De-identified data licensing to foreign pharma and research consortia; TELUS-style international data collaborations",
        "PHI removed (recall >= 98%), zero residual PHI in the released set, k-anonymity >= 5 - before any record leaves the boundary",
    ],
    [
        "Malaffi population-health & RWE",
        "ADHDS / Malaffi HIE - 3.5M records, 3,000+ facilities",
        "Regulatory-grade real-world evidence sold to biopharma; Malaffi/Sahatna HIE licensed to other governments",
        "The cohort query ran on approved data, in-boundary, with a stated differential-privacy budget and 100% small-cell suppression - no record exposed",
    ],
    [
        "Biobank GWAS & polygenic risk scores",
        "Emirati Genome Programme - 700K genomes",
        "Biopharma target-discovery and PRS licensing on the sovereign cohort",
        "Association power >= 80%, FDR <= 5%, genomic inflation controlled (lambda <= 1.10) - the cohort never left Abu Dhabi",
    ],
    [
        "Digital pathology AI",
        "National Reference Laboratory",
        "Cross-border diagnostic reads and second-opinion services",
        "Slide AUROC >= 0.90, sensitivity >= 0.95, with the model and circuit hash bound to each slide read the receiving clinician can audit",
    ],
    [
        "Clinical-trial matching & synthetic control arms",
        "IROS",
        "Multi-site international trials and pharma trial partnerships",
        "Eligibility matched at high sensitivity with a balanced synthetic control arm (covariate SMD <= 0.10) a regulator can accept in lieu of randomization",
    ],
    [
        "Med42 training / fine-tuning provenance",
        "Med42 + Core42 / Cerebras",
        "Licensing Med42 into other jurisdictions; defending its IP",
        "Which approved, consented data trained the checkpoint - zero unapproved data included, complete lineage, bound to the checkpoint hash",
    ],
]
HEADERS = ["Workload", "M42 asset", "Cross-border deal it unlocks", "What the Digital Seal proves"]
WIDTHS = [30.0, 33.0, 49.0, 62.0]


class Brief(FPDF):
    def __init__(self) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self.set_auto_page_break(False)
        self.set_margins(18, 14, 18)

    def measure_lines(self, cell_w: float, text: str, font_size: float, bold: bool, line_h: float) -> int:
        """Count wrapped lines using fpdf2's own breaker so heights never clip.

        cell_w must be the exact width passed to multi_cell at render time, so the
        dry run wraps over the identical text area.
        """
        self.set_font("Helvetica", "B" if bold else "", font_size)
        try:
            lines = self.multi_cell(cell_w, line_h, clean(text), dry_run=True, output="LINES", align="L")
        except TypeError:
            lines = self.multi_cell(cell_w, line_h, clean(text), split_only=True, align="L")
        return max(1, len(lines))

    def header_band(self) -> None:
        self.set_draw_color(*CR)
        self.set_line_width(1.1)
        self.line(18, 13, self.w - 18, 13)
        if LOGO.exists():
            self.image(str(LOGO), 18, 16, 13)
        self.set_xy(34, 16)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*CR)
        self.cell(0, 4, "AETHELRED x M42  ·  CONFIDENTIAL BRIEF  ·  JUNE 2026")
        self.set_xy(34, 20)
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(*CR)
        self.cell(0, 7, "Sovereign Data, Verified for Export")
        self.set_xy(34, 28)
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*BD)
        self.cell(0, 4, "Tier-2 workloads and the cross-border deals they unlock")
        self.set_y(36)

    def intro(self) -> None:
        self.set_x(18)
        self.set_font("Helvetica", "", 8.2)
        self.set_text_color(*BD)
        self.multi_cell(
            CONTENT_W, 4.0,
            clean(
                "M42's models are valuable, but its data, diagnostics, trials, and Med42 governance assets are "
                "the larger prize - and each can be sold or licensed internationally only when a foreign buyer, "
                "regulator, or partner can verify the result without seeing the underlying records. That "
                "verification is the product. Each Tier-2 workload produces a Digital Seal that supplies exactly "
                "the proof the counterparty requires, turning a stalled conversation into a clearable deal."
            ),
            align="L",
        )
        self.ln(1.5)

    def table(self) -> None:
        # Header row.
        head_h = max(self.measure_lines(WIDTHS[i] - 2.8, HEADERS[i], 7, True, 3.4) for i in range(4)) * 3.4 + 2.4
        x0, y0 = 18, self.get_y()
        for i, header in enumerate(HEADERS):
            x = x0 + sum(WIDTHS[:i])
            self.set_fill_color(*CR)
            self.set_draw_color(*RL)
            self.rect(x, y0, WIDTHS[i], head_h, "F")
            self.set_xy(x + 1.4, y0 + 1.2)
            self.set_text_color(255, 255, 255)
            self.multi_cell(WIDTHS[i] - 2.8, 3.4, clean(header), align="L")
        self.set_xy(x0, y0 + head_h)

        # Body rows.
        for ri, row in enumerate(ROWS):
            font_size = 7.0
            line_h = 3.5
            row_h = max(self.measure_lines(WIDTHS[i] - 2.8, row[i], font_size, i == 0, line_h) for i in range(4)) * line_h + 3.4
            y = self.get_y()
            fill = TS if ri % 2 else (255, 255, 255)
            for i, cell in enumerate(row):
                x = x0 + sum(WIDTHS[:i])
                self.set_fill_color(*fill)
                self.set_draw_color(*RL)
                self.rect(x, y, WIDTHS[i], row_h, "DF")
                self.set_xy(x + 1.4, y + 1.6)
                self.set_font("Helvetica", "B" if i == 0 else "", font_size)
                self.set_text_color(*DK if i == 0 else BD)
                self.multi_cell(WIDTHS[i] - 2.8, line_h, clean(cell), align="L")
            self.set_xy(x0, y + row_h)
        self.ln(2)

    def callout(self, label: str, text: str) -> None:
        self.set_x(18)
        lines = self.measure_lines(CONTENT_W - 6, f"{label} {text}", 7.6, False, 3.5)
        height = lines * 3.5 + 3.4
        x, y = 18, self.get_y()
        self.set_fill_color(*NB)
        self.set_draw_color(*CR)
        self.set_line_width(0.5)
        self.rect(x, y, CONTENT_W, height, "F")
        self.line(x, y, x, y + height)
        self.set_xy(x + 3, y + 1.6)
        self.set_text_color(*CR)
        self.set_font("Helvetica", "B", 7.6)
        label_w = self.get_string_width(clean(label)) + 1
        self.cell(label_w, 3.5, clean(label))
        self.set_font("Helvetica", "", 7.6)
        self.set_text_color(*BD)
        self.multi_cell(CONTENT_W - 6 - label_w, 3.5, clean(text), align="L")
        self.set_y(y + height + 2)

    def render(self) -> None:
        self.add_page()
        self.header_band()
        self.intro()
        self.table()
        self.callout(
            "The through-line.",
            " De-identification attestation is the master key: no data asset clears a foreign residency or "
            "consent review until M42 can prove safe egress. The other five each convert a specific M42 asset "
            "into recurring, cross-border revenue by replacing \"trust M42's word\" with \"verify the Seal.\"",
        )
        self.callout(
            "Boundary.",
            " Pilot evidence is synthetic and pre-testnet; the metrics above are drill results computed on "
            "synthetic ground truth, not clinical, scientific, or production claims. Live deals follow the paid "
            "pilot, ADGM entity registration, and M42 governance approval.",
        )
        # Footer rule.
        self.set_draw_color(*RL)
        self.set_line_width(0.2)
        self.line(18, self.h - 12, self.w - 18, self.h - 12)
        self.set_xy(18, self.h - 11)
        self.set_font("Helvetica", "", 6.5)
        self.set_text_color(*LT)
        self.cell(CONTENT_W / 2, 4, "Aethelred  ·  Sovereign Verified AI Compute")
        self.set_xy(18 + CONTENT_W / 2, self.h - 11)
        self.cell(CONTENT_W / 2, 4, "Prepared by Ramesh Tamilselvan  ·  Abu Dhabi", align="R")


def main() -> None:
    pdf = Brief()
    pdf.set_title("Aethelred x M42 - Tier-2 Cross-Border Brief")
    pdf.set_author("Ramesh Tamilselvan")
    pdf.render()
    pdf.output(str(OUT))
    print(f"Wrote {OUT} ({pdf.page_no()} page)")


if __name__ == "__main__":
    main()
