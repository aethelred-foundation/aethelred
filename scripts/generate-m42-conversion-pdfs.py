#!/usr/bin/env python3
"""
Generate the M42 conversion-track PDFs from their markdown sources:

- Differentiation dossier (M42 technical/security reviewers)
- Pre-seed investment memo (M42 corporate development channel)

The LOI and MOU drafts are deliberately excluded: they are legal drafts
delivered as Word documents for redlining, not as PDFs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from fpdf import FPDF


BASE = Path(__file__).resolve().parents[1]
LOGO = BASE / "frontend" / "website" / "org-v2" / "aethelred-logo.png"

CR = (159, 10, 36)
DK = (17, 24, 39)
BD = (31, 41, 55)
MT = (107, 114, 128)
LT = (156, 163, 175)
RL = (229, 231, 235)
NB = (254, 242, 242)
TH = (243, 244, 246)
TS = (249, 250, 251)

# Body lines carrying repo status metadata; the cover carries this instead.
# The audience note is carried by the contents-page intro.
SKIP_PREFIXES = ("Status date:", "Document status:", "Audience note:")


@dataclass
class DocSpec:
    src: Path
    out: Path
    header_left: str
    header_right: str
    footer_label: str
    eyebrow: str
    title: str
    subtitle: str
    meta: list[tuple[str, str]]
    cover_notice: str
    contents_intro: str
    pdf_title: str
    skip_sections: list[str] = field(default_factory=list)


def clean(text: str) -> str:
    replacements = {
        "—": "-",
        "–": "-",
        "‘": "'",
        "’": "'",
        "“": '"',
        "”": '"',
        "•": "-",
        "×": "x",
        " ": " ",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"\1", text)
    text = re.sub(r"`(.*?)`", r"\1", text)
    text = re.sub(r"\[(.*?)\]\((.*?)\)", r"\1 (\2)", text)
    return text.encode("latin-1", errors="replace").decode("latin-1").strip()


def is_table_sep(line: str) -> bool:
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    return bool(cells) and all(c and set(c) <= set("-:") for c in cells)


def parse_md_table(lines: list[str], start: int):
    table_lines: list[str] = []
    i = start
    while i < len(lines) and lines[i].strip().startswith("|"):
        table_lines.append(lines[i].rstrip())
        i += 1
    if len(table_lines) < 2 or not is_table_sep(table_lines[1]):
        return None, start
    headers = [clean(c) for c in table_lines[0].strip().strip("|").split("|")]
    rows = []
    for raw in table_lines[2:]:
        row = [clean(c) for c in raw.strip().strip("|").split("|")]
        while len(row) < len(headers):
            row.append("")
        rows.append(row[: len(headers)])
    return (headers, rows), i


class ConversionPDF(FPDF):
    def __init__(self, spec: DocSpec):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.spec = spec
        self.set_auto_page_break(True, 24)
        self.set_left_margin(20)
        self.set_right_margin(20)
        self.set_top_margin(26)

    def header(self):
        if self.page_no() <= 2:
            return
        self.set_y(9)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*CR)
        self.cell(0, 5, self.spec.header_left)
        self.set_text_color(*LT)
        self.cell(0, 5, self.spec.header_right, align="R")
        self.set_draw_color(*CR)
        self.set_line_width(0.35)
        self.line(20, 18, self.w - 20, 18)
        self.set_y(26)

    def footer(self):
        if self.page_no() <= 1:
            return
        self.set_y(-17)
        self.set_draw_color(*RL)
        self.set_line_width(0.2)
        self.line(20, self.get_y(), self.w - 20, self.get_y())
        self.ln(3)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*LT)
        self.cell(0, 5, self.spec.footer_label)
        self.set_x(20)
        self.cell(0, 5, f"Page {self.page_no()}", align="R")

    def cover(self):
        self.add_page()
        self.set_fill_color(255, 248, 248)
        self.rect(0, 0, self.w, self.h, "F")
        self.set_draw_color(*CR)
        self.set_line_width(1.3)
        self.line(22, 24, self.w - 22, 24)

        if LOGO.exists():
            self.image(str(LOGO), (self.w - 28) / 2, 42, 28)

        self.set_y(80)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*CR)
        self.cell(0, 7, self.spec.eyebrow, align="C")
        self.ln(7)
        self.set_font("Helvetica", "B", 25)
        self.set_text_color(*CR)
        self.multi_cell(0, 11, self.spec.title, align="C")
        self.ln(4)
        self.set_font("Helvetica", "", 11)
        self.set_text_color(*BD)
        self.multi_cell(0, 6, clean(self.spec.subtitle), align="C")
        self.ln(14)

        self.set_x(36)
        self.set_fill_color(255, 255, 255)
        self.set_draw_color(*RL)
        box_h = len(self.spec.meta) * 8 + 10
        self.rect(36, self.get_y(), self.w - 72, box_h, "DF")
        y = self.get_y() + 6
        for label, value in self.spec.meta:
            self.set_xy(44, y)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*MT)
            self.cell(34, 6, label)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*BD)
            self.cell(0, 6, value)
            y += 8

        self.set_y(self.h - 34)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*CR)
        self.cell(0, 5, self.spec.cover_notice, align="C")
        self.set_line_width(1.3)
        self.line(22, self.h - 24, self.w - 22, self.h - 24)

    def contents(self, sections: list[str]):
        self.add_page()
        self.h2("Contents", track=False)
        self.p(self.spec.contents_intro)
        self.ln(2)
        for idx, section in enumerate(sections, start=1):
            if self.get_y() > self.h - 32:
                self.add_page()
            self.set_x(20)
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(*CR)
            self.cell(8, 6, f"{idx:02d}")
            self.set_font("Helvetica", "", 9)
            self.set_text_color(*BD)
            self.multi_cell(self.w - 48, 6, section, align="L")

    def h2(self, text: str, track: bool = True):
        if self.get_y() > self.h - 50:
            self.add_page()
        self.ln(3)
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*CR)
        self.multi_cell(0, 8, clean(text), align="L")
        self.set_draw_color(*RL)
        self.set_line_width(0.25)
        self.line(20, self.get_y() + 1, self.w - 20, self.get_y() + 1)
        self.ln(4)

    def h3(self, text: str):
        if self.get_y() > self.h - 38:
            self.add_page()
        self.ln(2)
        self.set_font("Helvetica", "B", 10.5)
        self.set_text_color(*DK)
        self.multi_cell(0, 6, clean(text), align="L")
        self.ln(1)

    def p(self, text: str):
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "", 9.2)
        self.set_text_color(*BD)
        self.multi_cell(0, 5.3, clean(text), align="L")
        self.ln(1.6)

    def bullet(self, text: str):
        self.set_x(25)
        self.set_font("Helvetica", "B", 9.2)
        self.set_text_color(*CR)
        self.cell(4, 5.2, "-")
        self.set_font("Helvetica", "", 9.2)
        self.set_text_color(*BD)
        self.multi_cell(0, 5.2, clean(text), align="L")
        self.ln(0.6)

    def number(self, num: str, text: str):
        self.set_x(24)
        self.set_font("Helvetica", "B", 9.2)
        self.set_text_color(*CR)
        self.cell(8, 5.2, f"{num}.")
        self.set_font("Helvetica", "", 9.2)
        self.set_text_color(*BD)
        self.multi_cell(0, 5.2, clean(text), align="L")
        self.ln(0.6)

    def notice(self, text: str):
        self.ln(3)
        x = self.get_x()
        y = self.get_y()
        width = self.w - 40
        self.set_font("Helvetica", "", 8.4)
        lines = self._line_count(width - 12, text)
        height = lines * 4.6 + 8
        if y + height > self.h - 24:
            self.add_page()
            y = self.get_y()
        self.set_fill_color(*NB)
        self.set_draw_color(*CR)
        self.set_line_width(0.55)
        self.rect(x, y, width, height, "F")
        self.line(x, y, x, y + height)
        self.set_xy(x + 7, y + 4)
        self.set_text_color(*CR)
        self.multi_cell(width - 12, 4.6, clean(text), align="L")
        self.set_y(y + height + 3)

    def _line_count(self, width: float, text: str, font_size: float = 8.0) -> int:
        self.set_font("Helvetica", "", font_size)
        # multi_cell wraps inside width - 2*c_margin, not the full cell width.
        width -= 2 * getattr(self, "c_margin", 1.0)
        # Mirror fpdf2's breaker: it splits on spaces and after hyphens, and
        # falls back to character wrapping for tokens wider than the cell.
        words: list[str] = []
        for token in clean(str(text)).split():
            parts = re.split(r"(?<=-)", token)
            words.extend(p for p in parts if p)
        if not words:
            return 1
        lines = 1
        current = ""
        for word in words:
            joiner = "" if current.endswith("-") else " "
            test = f"{current}{joiner}{word}" if current else word
            if self.get_string_width(test) <= width:
                current = test
                continue
            word_w = self.get_string_width(word)
            if word_w > width:
                lines += max(1, int(word_w // width) + 1)
                current = ""
            else:
                lines += 1
                current = word
        return lines

    def table(self, headers: list[str], rows: list[list[str]]):
        if not rows:
            return
        self.ln(2)
        n = len(headers)
        avail = self.w - 40

        max_lens = []
        for i in range(n):
            max_len = len(headers[i])
            for row in rows:
                if i < len(row):
                    max_len = max(max_len, min(len(row[i]), 65))
            max_lens.append(max(max_len, 10))

        total = sum(max_lens)
        widths = [avail * value / total for value in max_lens]
        min_width = 24 if n <= 4 else 18
        for i, width in enumerate(widths):
            if width < min_width:
                widths[i] = min_width
        scale = avail / sum(widths)
        widths = [width * scale for width in widths]

        font_size = 7.2 if n >= 4 else 7.8
        header_h = max(self._line_count(widths[i] - 3, headers[i], font_size) for i in range(n)) * 4 + 4
        if self.get_y() + header_h > self.h - 24:
            self.add_page()
        self._table_header(headers, widths, header_h, font_size)

        self.set_font("Helvetica", "", font_size)
        self.set_text_color(*BD)
        for ri, row in enumerate(rows):
            row_h = max(
                self._line_count(widths[i] - 3, row[i] if i < len(row) else "", font_size)
                for i in range(n)
            ) * 4 + 4
            if self.get_y() + row_h > self.h - 24:
                self.add_page()
                self._table_header(headers, widths, header_h, font_size)
            x0 = self.get_x()
            y0 = self.get_y()
            fill = ri % 2 == 1
            for i in range(n):
                x = x0 + sum(widths[:i])
                self.set_fill_color(*(TS if fill else (255, 255, 255)))
                self.set_draw_color(*RL)
                self.rect(x, y0, widths[i], row_h, "DF")
                self.set_xy(x + 1.5, y0 + 2)
                self.multi_cell(widths[i] - 3, 4, clean(row[i] if i < len(row) else ""), align="L")
            self.set_xy(x0, y0 + row_h)
        self.ln(3)

    def _table_header(self, headers: list[str], widths: list[float], height: float, font_size: float):
        x0 = self.get_x()
        y0 = self.get_y()
        self.set_font("Helvetica", "B", font_size)
        self.set_text_color(*DK)
        for i, header in enumerate(headers):
            x = x0 + sum(widths[:i])
            self.set_fill_color(*TH)
            self.set_draw_color(*RL)
            self.rect(x, y0, widths[i], height, "DF")
            self.set_xy(x + 1.5, y0 + 2)
            self.multi_cell(widths[i] - 3, 4, clean(header), align="L")
        self.set_xy(x0, y0 + height)


def filter_lines(lines: list[str], skip_sections: list[str]) -> list[str]:
    """Drop status-metadata lines, horizontal rules, and named ## sections."""
    out: list[str] = []
    skipping = False
    for raw in lines:
        line = raw.strip()
        if line.startswith("## "):
            skipping = clean(line[3:]) in skip_sections
        if skipping:
            continue
        if line == "---":
            continue
        if any(line.startswith(prefix) for prefix in SKIP_PREFIXES):
            continue
        out.append(raw)
    return out


def collect_sections(lines: list[str]) -> list[str]:
    # Strip any leading "N. " so the contents page does not double-number.
    return [
        re.sub(r"^\d+\.\s+", "", clean(line[3:].strip()))
        for line in lines
        if line.startswith("## ")
    ]


def render_markdown(pdf: ConversionPDF, lines: list[str]):
    i = 0
    skip_title = True
    while i < len(lines):
        raw = lines[i].rstrip()
        line = raw.strip()

        if skip_title and line.startswith("# "):
            i += 1
            continue
        skip_title = False

        if not line:
            i += 1
            continue

        if line.startswith("> "):
            parts = [line[2:]]
            i += 1
            while i < len(lines) and lines[i].strip().startswith("> "):
                parts.append(lines[i].strip()[2:])
                i += 1
            pdf.notice(" ".join(parts))
            continue

        if line.startswith("## "):
            pdf.h2(line[3:])
            i += 1
            continue

        if line.startswith("### "):
            pdf.h3(line[4:])
            i += 1
            continue

        if line.startswith("|"):
            table, next_i = parse_md_table(lines, i)
            if table:
                pdf.table(table[0], table[1])
                i = next_i
                continue

        numbered = re.match(r"^(\d+)\.\s+(.+)", line)
        if numbered:
            pdf.number(numbered.group(1), numbered.group(2))
            i += 1
            continue

        if line.startswith("- "):
            pdf.bullet(line[2:])
            i += 1
            continue

        paragraph = [line]
        i += 1
        while i < len(lines):
            nxt = lines[i].rstrip()
            stripped = nxt.strip()
            if (
                not stripped
                or stripped.startswith("#")
                or stripped.startswith("> ")
                or stripped.startswith("|")
                or stripped.startswith("- ")
                or stripped == "---"
                or re.match(r"^\d+\.\s+", stripped)
            ):
                break
            paragraph.append(stripped)
            i += 1
        pdf.p(" ".join(paragraph))


SPECS = [
    DocSpec(
        src=BASE / "docs" / "workload-packs" / "m42" / "differentiation-dossier.md",
        out=BASE / "M42" / "Aethelred_M42_Differentiation_Dossier_v1_0.pdf",
        header_left="AETHELRED · M42 DIFFERENTIATION DOSSIER",
        header_right="V1.0 · JUNE 2026",
        footer_label="Aethelred · M42 Differentiation Dossier",
        eyebrow="DIFFERENTIATION DOSSIER · M42 REVIEW · JUNE 2026",
        title="Aethelred x M42\nDifferentiation Dossier",
        subtitle=(
            "How Aethelred differs from general-purpose Layer 1 networks, privacy chains, "
            "zkML projects, compute markets, and hyperscaler confidential computing - with "
            "every claim mapped to an artifact M42 inspects in its own pilot."
        ),
        meta=[
            ("Prepared for", "M42 technical and security reviewers"),
            ("Prepared by", "Ramesh Tamilselvan, Founder, Aethelred"),
            ("Purpose", "Evidence-anchored differentiation review"),
            ("Delivery moment", "After the Week 2 evidence room walkthrough"),
        ],
        cover_notice="CONFIDENTIAL · M42 REVIEW MATERIAL · CLAIMS BOUNDED TO INSPECTABLE ARTIFACTS",
        contents_intro=(
            "This dossier compares Aethelred against each category an M42 reviewer will "
            "raise in an internal debate. The standard for inclusion is that every claim "
            "maps to a pilot artifact or public repository check M42 can verify directly."
        ),
        pdf_title="Aethelred x M42 Differentiation Dossier",
    ),
    DocSpec(
        src=BASE / "docs" / "operations" / "m42-preseed-investment-memo.md",
        out=BASE / "M42" / "Aethelred_M42_Pre_Seed_Investment_Memo_v1_0.pdf",
        header_left="AETHELRED · PRE-SEED INVESTMENT MEMO",
        header_right="V1.0 · JUNE 2026 · CORP-DEV CHANNEL ONLY",
        footer_label="Aethelred · Pre-Seed Investment Memo · Confidential Discussion Draft",
        eyebrow="STRATEGIC INVESTMENT MEMO · M42 CORPORATE DEVELOPMENT · JUNE 2026",
        title="Aethelred Pre-Seed\nInvestment Memo",
        subtitle=(
            "A $2,000,000 pre-seed proposal prepared for M42 corporate development, "
            "de-risked by the four-week sovereign verified AI compute pilot and "
            "structured to keep the evidence layer independent."
        ),
        meta=[
            ("Prepared for", "M42 corporate development / ventures"),
            ("Prepared by", "Ramesh Tamilselvan, Founder, Aethelred"),
            ("Instrument", "Post-money SAFE plus strategic side letter (proposed)"),
            ("Status", "Pre-registration project; ADGM registration planned"),
        ],
        cover_notice="CONFIDENTIAL DISCUSSION DRAFT · NOT AN OFFER OF SECURITIES",
        contents_intro=(
            "This memo travels only through the corporate development channel. It is "
            "deliberately separate from the $200,000 pilot, which stands on its own "
            "commercial terms and is not conditioned on any investment."
        ),
        pdf_title="Aethelred Pre-Seed Investment Memo - Prepared for M42 Corporate Development",
    ),
]


def build(spec: DocSpec):
    lines = filter_lines(spec.src.read_text(encoding="utf-8").splitlines(), spec.skip_sections)
    sections = collect_sections(lines)
    pdf = ConversionPDF(spec)
    pdf.set_title(spec.pdf_title)
    pdf.set_author("Ramesh Tamilselvan")
    pdf.cover()
    pdf.contents(sections)
    render_markdown(pdf, lines)
    pdf.output(str(spec.out))
    print(f"Wrote {spec.out}")


def main():
    for spec in SPECS:
        build(spec)


if __name__ == "__main__":
    main()
