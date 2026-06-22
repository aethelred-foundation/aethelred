#!/usr/bin/env python3
"""
Generate the M42 sovereign verified AI compute business-case PDF.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from fpdf import FPDF


BASE = Path(__file__).resolve().parents[1]
SRC = BASE / "use cases" / "Companies" / "Aethelred_M42_Sovereign_Verified_AI_Compute_Business_Case_v1.0.md"
OUT = BASE / "use cases" / "Companies" / "Aethelred_M42_Sovereign_Verified_AI_Compute_Business_Case_v1.0.pdf"
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


def clean(text: str) -> str:
    replacements = {
        "\u2014": "-",
        "\u2013": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2022": "-",
        "\u00a0": " ",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
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


class ProposalPDF(FPDF):
    def __init__(self, title: str):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.title_text = title
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
        self.cell(0, 5, "AETHELRED · M42 BUSINESS CASE")
        self.set_text_color(*LT)
        self.cell(0, 5, "V1.0 · JUNE 2026", align="R")
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
        self.cell(0, 5, "Aethelred · Sovereign Verified AI Compute Business Case")
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
        self.cell(0, 7, "BUSINESS CASE · M42 · JUNE 2026", align="C")
        self.ln(7)
        self.set_font("Helvetica", "B", 25)
        self.set_text_color(*CR)
        self.multi_cell(0, 11, "Aethelred x M42\nSovereign Verified AI Compute", align="C")
        self.ln(4)
        self.set_font("Helvetica", "", 11)
        self.set_text_color(*BD)
        self.multi_cell(
            0,
            6,
            "Reducing M42's AI and genomics compute cost while creating a new "
            "B2B/B2G managed-service revenue line.",
            align="C",
        )
        self.ln(14)

        self.set_x(40)
        self.set_fill_color(255, 255, 255)
        self.set_draw_color(*RL)
        self.rect(40, self.get_y(), self.w - 80, 42, "DF")
        y = self.get_y() + 6
        meta = [
            ("Prepared for", "M42 executive and technical review"),
            ("Prepared by", "Ramesh Tamilselvan, Founder, Aethelred project"),
            ("Purpose", "Technical-commercial pilot scoping"),
            ("Status", "Pre-registration project; ADGM labs/foundation planned"),
        ]
        for label, value in meta:
            self.set_xy(48, y)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*MT)
            self.cell(32, 6, label)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*BD)
            self.cell(0, 6, value)
            y += 8

        self.set_y(self.h - 34)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*CR)
        self.cell(0, 5, "CONFIDENTIAL SCOPING PROPOSAL · NOT A PARTNERSHIP ANNOUNCEMENT", align="C")
        self.set_line_width(1.3)
        self.line(22, self.h - 24, self.w - 22, self.h - 24)

    def contents(self, sections: list[str]):
        self.add_page()
        self.h2("Contents", track=False)
        self.p(
            "This proposal presents a technical and commercial path for M42 to evaluate "
            "lower-cost sovereign AI compute, auditable AI evidence, and a managed-service "
            "offering for regulated healthcare, government, and life-sciences customers."
        )
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
        self.notice(
            "This proposal is framed solely for M42 and its own healthcare, AI, "
            "genomics, and client-service context."
        )

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
        self.set_font("Helvetica", "", 9.2)
        self.set_text_color(*BD)
        self.multi_cell(0, 5.3, clean(text), align="L")
        self.ln(1.6)

    def bullet(self, text: str):
        link_match = re.fullmatch(r"\[(.+?)\]\((https?://.+?)\)", text.strip())
        self.set_x(25)
        self.set_font("Helvetica", "B", 9.2)
        self.set_text_color(*CR)
        self.cell(4, 5.2, "-")
        if link_match:
            self.set_font("Helvetica", "U", 9.2)
            self.set_text_color(0, 88, 180)
            self.multi_cell(0, 5.2, clean(link_match.group(1)), align="L", link=link_match.group(2))
        else:
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
        words = clean(str(text)).split()
        if not words:
            return 1
        lines = 1
        current = ""
        for word in words:
            test = f"{current} {word}".strip()
            if self.get_string_width(test) <= width:
                current = test
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


def collect_sections(lines: list[str]) -> list[str]:
    return [clean(line[3:].strip()) for line in lines if line.startswith("## ")]


def render_markdown(pdf: ProposalPDF, lines: list[str]):
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

        if line.startswith("**") and ":" in line:
            # Metadata appears on cover; keep the body focused.
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
                or re.match(r"^\d+\.\s+", stripped)
            ):
                break
            paragraph.append(stripped)
            i += 1
        pdf.p(" ".join(paragraph))


def main():
    lines = SRC.read_text(encoding="utf-8").splitlines()
    sections = collect_sections(lines)
    pdf = ProposalPDF("Aethelred x M42 Sovereign Verified AI Compute Business Case")
    pdf.set_title("Aethelred x M42 Sovereign Verified AI Compute Business Case")
    pdf.set_author("Ramesh Tamilselvan")
    pdf.cover()
    pdf.contents(sections)
    render_markdown(pdf, lines)
    pdf.output(str(OUT))
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
