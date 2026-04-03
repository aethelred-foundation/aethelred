#!/usr/bin/env python3
"""
Generate publication-grade PDFs with tables, metrics, and figures.
Follows international whitepaper / tokenomics document standards.
"""

from fpdf import FPDF
import os
import re
import shutil

# ── Brand palette ────────────────────────────────────────────────────────────
CR  = (159, 10, 36)     # crimson
DK  = (17, 24, 39)      # dark
BD  = (31, 41, 55)      # body
MT  = (107, 114, 128)   # muted
LT  = (156, 163, 175)   # light
RL  = (229, 231, 235)   # rule
NB  = (254, 242, 242)   # notice bg
NF  = (153, 27, 27)     # notice fg
TH  = (243, 244, 246)   # table header bg
TS  = (249, 250, 251)   # table stripe bg
DOC_VERSION = '1.1'
DOC_DATE = 'April 2026'


class DocPDF(FPDF):

    def __init__(self, logo, title):
        super().__init__()
        self.logo = logo
        self.title_text = title
        self.toc = []
        self.set_auto_page_break(True, 28)
        self.set_top_margin(30)
        self.set_left_margin(22)
        self.set_right_margin(22)

    def header(self):
        if self.page_no() <= 2:
            return
        if os.path.exists(self.logo):
            self.image(self.logo, 22, 10, 7)
        self.set_y(10)
        self.set_x(32)
        self.set_font('Helvetica', '', 7)
        self.set_text_color(*LT)
        self.cell(0, 7, self.title_text.upper())
        self.set_y(10)
        self.set_font('Helvetica', 'B', 7)
        self.set_text_color(*CR)
        self.cell(0, 7, 'PUBLIC CANONICAL DRAFT', align='R')
        self.set_draw_color(*CR)
        self.set_line_width(0.3)
        self.line(22, 19, self.w - 22, 19)
        self.set_y(30)

    def footer(self):
        if self.page_no() <= 1:
            return
        self.set_y(-20)
        self.set_draw_color(*RL)
        self.set_line_width(0.2)
        self.line(22, self.get_y(), self.w - 22, self.get_y())
        self.ln(3)
        self.set_font('Helvetica', '', 7)
        self.set_text_color(*LT)
        self.cell(0, 5, '(c) 2026 Aethelred  |  Public Canonical Draft')
        self.set_x(22)
        self.cell(0, 5, str(self.page_no() - 1), align='R')

    # ── Cover ────────────────────────────────────────────────────────────────
    def cover(self, title, subtitle):
        self.add_page()
        self.set_draw_color(*CR)
        self.set_line_width(2)
        self.line(22, 22, self.w - 22, 22)
        if os.path.exists(self.logo):
            self.image(self.logo, (self.w - 36) / 2, 45, 36)
        self.set_y(92)
        self.set_font('Helvetica', 'B', 26)
        self.set_text_color(*CR)
        self.multi_cell(0, 11, title.upper(), align='C')
        self.ln(4)
        self.set_draw_color(*CR)
        self.set_line_width(0.5)
        self.line(55, self.get_y(), self.w - 55, self.get_y())
        self.ln(8)
        self.set_font('Helvetica', '', 12)
        self.set_text_color(*MT)
        self.multi_cell(0, 7, subtitle, align='C')
        self.ln(20)
        meta = [('Version', DOC_VERSION), ('Date', DOC_DATE),
                ('Prepared by', 'Aethelred'),
                ('Classification', 'Public Canonical Draft'),
                ('Disclosure', 'Governed -- publish only when approved')]
        cw = 55
        vw = self.w - 44 - cw
        for k, v in meta:
            self.set_x((self.w - cw - vw) / 2)
            self.set_font('Helvetica', 'B', 9); self.set_text_color(*MT)
            self.cell(cw, 7, k)
            self.set_font('Helvetica', '', 9); self.set_text_color(*BD)
            self.cell(vw, 7, v); self.ln(7)
        self.ln(12)
        bw = 82; bx = (self.w - bw) / 2
        self.set_draw_color(*CR); self.set_line_width(0.6)
        self.rect(bx, self.get_y(), bw, 10)
        self.set_x(bx); self.set_font('Helvetica', 'B', 8); self.set_text_color(*CR)
        self.cell(bw, 10, 'PUBLIC CANONICAL DRAFT', align='C')
        self.set_draw_color(*CR); self.set_line_width(2)
        self.line(22, self.h - 22, self.w - 22, self.h - 22)

    # ── TOC ──────────────────────────────────────────────────────────────────
    def build_toc(self):
        self.add_page()
        self.set_font('Helvetica', 'B', 18); self.set_text_color(*DK)
        self.cell(0, 12, 'TABLE OF CONTENTS'); self.ln(10)
        self.set_draw_color(*CR); self.set_line_width(0.5)
        self.line(22, self.get_y(), self.w - 22, self.get_y()); self.ln(8)
        for lv, t, p in self.toc:
            if lv == 2:
                self.set_font('Helvetica', 'B', 10); self.set_text_color(*DK); ind = 0
            else:
                self.set_font('Helvetica', '', 9); self.set_text_color(*MT); ind = 8
            self.set_x(22 + ind)
            self.cell(self.w - 44 - ind - 10, 6, t)
            self.cell(0, 6, str(p), align='R'); self.ln(6)
            if lv == 2: self.ln(1)

    # ── Content blocks ───────────────────────────────────────────────────────
    def h2(self, t):
        self.toc.append((2, t, self.page_no() - 1))
        self.ln(5); self.set_font('Helvetica', 'B', 14); self.set_text_color(*CR)
        self.multi_cell(0, 8, t)
        self.set_draw_color(*RL); self.set_line_width(0.3)
        self.line(22, self.get_y() + 1, self.w - 22, self.get_y() + 1); self.ln(5)

    def h3(self, t):
        self.toc.append((3, t, self.page_no() - 1))
        self.ln(3); self.set_font('Helvetica', 'B', 11); self.set_text_color(*DK)
        self.multi_cell(0, 6, t); self.ln(2)

    def p(self, t):
        self.set_font('Helvetica', '', 10); self.set_text_color(*BD)
        self.multi_cell(0, 5.5, t); self.ln(2.5)

    def bullet(self, t):
        self.set_font('Helvetica', '', 10); self.set_text_color(*BD)
        x = self.get_x(); self.set_x(x + 8)
        self.set_font('Helvetica', 'B', 10); self.set_text_color(*CR)
        self.cell(5, 5.5, '-')
        self.set_font('Helvetica', '', 10); self.set_text_color(*BD)
        self.multi_cell(0, 5.5, t.strip()); self.ln(1)

    def num(self, n, t):
        self.set_text_color(*BD); x = self.get_x(); self.set_x(x + 8)
        self.set_font('Helvetica', 'B', 10); self.set_text_color(*CR)
        self.cell(8, 5.5, f'{n}.')
        self.set_font('Helvetica', '', 10); self.set_text_color(*BD)
        self.multi_cell(0, 5.5, t.strip()); self.ln(1)

    def notice(self, t):
        self.ln(3)
        self.set_fill_color(*NB); self.set_draw_color(*CR); self.set_line_width(0.6)
        x, y = self.get_x(), self.get_y()
        self.set_font('Helvetica', '', 9); self.set_text_color(*NF)
        self.set_x(x + 8)
        self.multi_cell(self.w - 44 - 14, 5, t)
        ey = self.get_y()
        self.rect(x, y - 2, self.w - 44, ey - y + 6, 'F')
        self.line(x, y - 2, x, ey + 4)
        self.set_y(y); self.set_x(x + 8)
        self.multi_cell(self.w - 44 - 14, 5, t); self.ln(4)

    def hr(self):
        self.ln(3); self.set_draw_color(*RL); self.set_line_width(0.2)
        self.line(22, self.get_y(), self.w - 22, self.get_y()); self.ln(3)

    # ── Metrics row ──────────────────────────────────────────────────────────
    def metrics_row(self, items):
        """Render a row of key metric boxes. items = [(label, value), ...]"""
        self.ln(4)
        n = len(items)
        gap = 4
        bw = (self.w - 44 - gap * (n - 1)) / n
        bh = 22
        x0 = 22
        y0 = self.get_y()

        if y0 + bh + 10 > self.h - 28:
            self.add_page()
            y0 = self.get_y()

        for i, (label, value) in enumerate(items):
            x = x0 + i * (bw + gap)
            # Box background
            self.set_fill_color(*TH)
            self.rect(x, y0, bw, bh, 'F')
            # Left accent
            self.set_draw_color(*CR); self.set_line_width(1.5)
            self.line(x, y0, x, y0 + bh)
            # Value
            self.set_xy(x + 5, y0 + 3)
            self.set_font('Helvetica', 'B', 14); self.set_text_color(*CR)
            self.cell(bw - 10, 8, value)
            # Label
            self.set_xy(x + 5, y0 + 12)
            self.set_font('Helvetica', '', 7); self.set_text_color(*MT)
            self.cell(bw - 10, 6, label)

        self.set_y(y0 + bh + 5)

    # ── Table ────────────────────────────────────────────────────────────────
    def _line_count(self, width, text):
        text = str(text).replace('\n', ' ')
        words = text.split()
        if not words:
            return 1
        limit = max(width - 4, 10)
        lines = 1
        current = ''
        for word in words:
            test = f'{current} {word}'.strip()
            if self.get_string_width(test) <= limit:
                current = test
            else:
                lines += 1
                current = word
        return lines

    def table(self, headers, rows, col_widths=None):
        """Render a professional table with wrapped cells."""
        self.ln(3)
        n = len(headers)
        avail = self.w - 44
        if col_widths:
            ws = col_widths
        else:
            lens = []
            for ci in range(n):
                max_len = len(str(headers[ci]))
                for row in rows:
                    if ci < len(row):
                        max_len = max(max_len, len(str(row[ci])))
                lens.append(max(max_len, 12))
            total = sum(lens)
            ws = [(avail * l) / total for l in lens]

        # Header
        head_h = max(self._line_count(ws[i], headers[i]) for i in range(n)) * 4.2 + 4
        if self.get_y() + head_h + 12 > self.h - 28:
            self.add_page()
        self.set_fill_color(*TH)
        self.set_draw_color(*RL); self.set_line_width(0.3)
        self.set_font('Helvetica', 'B', 8); self.set_text_color(*DK)
        x0 = self.get_x()
        y0 = self.get_y()
        for i, h in enumerate(headers):
            x = x0 + sum(ws[:i])
            self.rect(x, y0, ws[i], head_h, 'FD')
            self.set_xy(x + 1.5, y0 + 1.5)
            self.multi_cell(ws[i] - 3, 4.2, str(h), border=0)
        self.set_xy(x0, y0 + head_h)

        # Rows
        self.set_font('Helvetica', '', 8); self.set_text_color(*BD)
        for ri, row in enumerate(rows):
            row_h = max(self._line_count(ws[i], row[i] if i < len(row) else '')
                        for i in range(n)) * 4.2 + 3
            if self.get_y() + row_h > self.h - 28:
                self.add_page()
                # repeat header on page break
                self.set_fill_color(*TH)
                self.set_draw_color(*RL); self.set_line_width(0.3)
                self.set_font('Helvetica', 'B', 8); self.set_text_color(*DK)
                x0 = self.get_x()
                y0 = self.get_y()
                for i, h in enumerate(headers):
                    x = x0 + sum(ws[:i])
                    self.rect(x, y0, ws[i], head_h, 'FD')
                    self.set_xy(x + 1.5, y0 + 1.5)
                    self.multi_cell(ws[i] - 3, 4.2, str(h), border=0)
                self.set_xy(x0, y0 + head_h)
                self.set_font('Helvetica', '', 8); self.set_text_color(*BD)
            if ri % 2 == 1:
                self.set_fill_color(*TS)
                fill = True
            else:
                fill = False
            x0 = self.get_x()
            y0 = self.get_y()
            for i in range(n):
                cell = str(row[i]) if i < len(row) else ''
                x = x0 + sum(ws[:i])
                if fill:
                    self.set_fill_color(*TS)
                    self.rect(x, y0, ws[i], row_h, 'FD')
                else:
                    self.rect(x, y0, ws[i], row_h)
                self.set_xy(x + 1.5, y0 + 1.5)
                self.multi_cell(ws[i] - 3, 4.2, cell, border=0)
            self.set_xy(x0, y0 + row_h)
        self.ln(3)

    # ── Flow diagram (text-based) ────────────────────────────────────────────
    def flow_diagram(self, title, steps):
        """Render a simple flow diagram with numbered steps and arrows."""
        self.ln(3)
        self.set_font('Helvetica', 'B', 9); self.set_text_color(*DK)
        self.cell(0, 6, title); self.ln(6)

        bw = self.w - 60
        bh = 10
        x0 = 30

        for i, step in enumerate(steps):
            y = self.get_y()
            if y + bh + 8 > self.h - 28:
                self.add_page()
                y = self.get_y()
            # Step box
            self.set_fill_color(*TH); self.set_draw_color(*CR); self.set_line_width(0.4)
            self.rect(x0, y, bw, bh, 'DF')
            self.set_xy(x0 + 3, y + 2)
            self.set_font('Helvetica', 'B', 8); self.set_text_color(*CR)
            self.cell(8, 6, f'{i+1}.')
            self.set_font('Helvetica', '', 8); self.set_text_color(*BD)
            self.cell(bw - 14, 6, step)
            self.set_y(y + bh)
            # Arrow between steps
            if i < len(steps) - 1:
                mid = x0 + bw / 2
                self.set_draw_color(*CR); self.set_line_width(0.4)
                self.line(mid, self.get_y(), mid, self.get_y() + 5)
                # arrowhead
                ay = self.get_y() + 5
                self.line(mid - 2, ay - 2, mid, ay)
                self.line(mid + 2, ay - 2, mid, ay)
                self.set_y(ay + 2)
        self.ln(4)


# ── Text cleaning ────────────────────────────────────────────────────────────
def clean(text):
    text = re.sub(r'\*\*(.*?)\*\*', r'\1', text)
    text = re.sub(r'\*(.*?)\*', r'\1', text)
    text = re.sub(r'`(.*?)`', r'\1', text)
    for o, n in [('&mdash;','--'),('&amp;','&'),('\u2014','--'),('\u2013','-'),
                 ('\u2018',"'"),('\u2019',"'"),('\u201c','"'),('\u201d','"'),
                 ('\u2022','-'),('\u00a9','(c)')]:
        text = text.replace(o, n)
    return text.encode('latin-1', errors='replace').decode('latin-1').strip()


def mirror_download(base, src_path):
    targets = [
        os.path.join(base, 'frontend', 'website', 'io', 'downloads'),
        os.path.join(base, 'frontend', 'website', 'io'),
        os.path.join(base, 'frontend', 'website', 'io', 'hostinger-public_html', 'downloads'),
        os.path.join(base, 'frontend', 'website', 'io', 'hostinger-public_html'),
    ]
    for target_dir in targets:
        os.makedirs(target_dir, exist_ok=True)
        dst_path = os.path.join(target_dir, os.path.basename(src_path))
        if os.path.abspath(src_path) == os.path.abspath(dst_path):
            continue
        shutil.copy2(src_path, dst_path)


def is_table_sep(line):
    cells = [c.strip() for c in line.strip().strip('|').split('|')]
    return bool(cells) and all(c and set(c) <= set('-:') for c in cells)


def parse_md_table(lines, start):
    table_lines = []
    i = start
    while i < len(lines):
        ln = lines[i].rstrip()
        if not ln.strip().startswith('|'):
            break
        table_lines.append(ln)
        i += 1
    if len(table_lines) < 2 or not is_table_sep(table_lines[1]):
        return None, start
    headers = [clean(c) for c in table_lines[0].strip().strip('|').split('|')]
    rows = []
    for raw in table_lines[2:]:
        row = [clean(c) for c in raw.strip().strip('|').split('|')]
        if any(cell for cell in row):
            while len(row) < len(headers):
                row.append('')
            rows.append(row[:len(headers)])
    return (headers, rows), i


# ── Markdown parser ──────────────────────────────────────────────────────────
def render_md(pdf, path):
    with open(path) as f:
        lines = f.readlines()
    i = 0; skip = True; bq = []; nc = 0
    while i < len(lines):
        ln = lines[i].rstrip()
        if skip:
            if ln.startswith('## Important Notice'):
                skip = False; pdf.add_page(); pdf.h2('Important Notice')
            i += 1; continue
        if ln.strip() == '---':
            pdf.hr(); i += 1; continue
        if ln.startswith('## '):
            pdf.h2(clean(ln[3:])); nc = 0; i += 1; continue
        if ln.startswith('### '):
            pdf.h3(clean(ln[4:])); i += 1; continue
        if ln.strip().startswith('|'):
            table, nxt = parse_md_table(lines, i)
            if table:
                pdf.table(table[0], table[1]); i = nxt; continue
        if ln.startswith('> '):
            bq.append(clean(ln[2:])); i += 1
            while i < len(lines) and lines[i].rstrip().startswith('> '):
                bq.append(clean(lines[i].rstrip()[2:])); i += 1
            pdf.notice(' '.join(bq)); bq = []; continue
        m = re.match(r'^(\d+)\.\s+(.+)', ln)
        if m:
            nc += 1; pdf.num(nc, clean(m.group(2))); i += 1; continue
        if ln.startswith('- '):
            pdf.bullet(clean(ln[2:])); i += 1; continue
        if not ln.strip():
            i += 1; nc = 0; continue
        para = [ln]; i += 1
        while i < len(lines):
            nl = lines[i].rstrip()
            if not nl.strip() or nl.startswith('#') or nl.startswith('-') or \
               nl.startswith('>') or nl.strip() == '---' or re.match(r'^\d+\.\s', nl):
                break
            para.append(nl); i += 1
        t = clean(' '.join(para))
        if t: pdf.p(t)


# ── Whitepaper generation ────────────────────────────────────────────────────
def gen_whitepaper(base, dl, logo):
    pdf = DocPDF(logo, 'Aethelred Whitepaper')
    pdf.cover('Aethelred Whitepaper', 'The Sovereign Layer 1 for Verifiable AI')

    # Render markdown content (first pass for TOC)
    render_md(pdf, os.path.join(base, 'docs', 'WHITEPAPER.md'))

    # Insert enrichment: tables, metrics, figures at appropriate points
    # We rebuild with TOC + enrichments in pass 2
    toc = pdf.toc[:]

    pdf2 = DocPDF(logo, 'Aethelred Whitepaper')
    pdf2.toc = toc
    pdf2.cover('Aethelred Whitepaper', 'The Sovereign Layer 1 for Verifiable AI')
    pdf2.build_toc()

    # -- Important Notice (re-rendered from MD) then enrichments woven in --
    with open(os.path.join(base, 'docs', 'WHITEPAPER.md')) as f:
        lines = f.readlines()

    i = 0; skip = True; bq = []; nc = 0
    while i < len(lines):
        ln = lines[i].rstrip()
        if skip:
            if ln.startswith('## Important Notice'):
                skip = False; pdf2.add_page(); pdf2.h2('Important Notice')
            i += 1; continue

        if ln.strip() == '---': pdf2.hr(); i += 1; continue
        if ln.startswith('## '):
            sec = clean(ln[3:])
            pdf2.h2(sec); nc = 0; i += 1

            # ── Inject enrichments after specific sections ────────────────
            if sec.startswith('1.'):  # Why Aethelred Exists
                pass  # pure text section
            elif 'Network Overview' in sec:
                pdf2.p('The protocol stack is organized into five interacting layers:')
                pdf2.table(
                    ['Layer', 'Function', 'Key Components'],
                    [['Consensus', 'Deterministic settlement', 'CometBFT, PoUW, ABCI++'],
                     ['Execution', 'Verified AI computation', 'TEE backends, zkML proofs'],
                     ['Evidence', 'Portable proof artifacts', 'Digital Seals, attestations'],
                     ['Developer', 'Integration surfaces', 'SDKs (Go, Rust, Python, TS)'],
                     ['Governance', 'Disclosure + control', 'Claims register, legal controls']],
                    [40, 50, 76]
                )
            elif 'Consensus and Verified' in sec:
                pdf2.flow_diagram('Verified Compute Flow', [
                    'AI job submitted to protocol',
                    'VRF-based scheduler assigns to validator',
                    'Execution in approved TEE environment',
                    'Proof artifact generated (zkML or attestation)',
                    'Evidence checked against protocol rules',
                    'Result sealed and settled on-chain',
                ])
            elif 'Verification Model' in sec:
                pdf2.table(
                    ['Backend', 'Type', 'Status'],
                    [['Intel SGX', 'TEE', 'Supported'],
                     ['AMD SEV-SNP', 'TEE', 'Supported'],
                     ['AWS Nitro Enclaves', 'TEE', 'Supported'],
                     ['Azure Confidential VMs', 'TEE', 'Supported'],
                     ['Google CoCo', 'TEE', 'Supported'],
                     ['Groth16', 'ZK Proof', 'Supported'],
                     ['PLONK', 'ZK Proof', 'Supported'],
                     ['Halo2', 'ZK Proof', 'Supported'],
                     ['STARK', 'ZK Proof', 'Supported'],
                     ['EZKL', 'zkML', 'Supported']],
                    [55, 40, 71]
                )
            elif 'Post-Quantum' in sec:
                pdf2.metrics_row([
                    ('Signature', 'ML-DSA-65'),
                    ('Key Encapsulation', 'ML-KEM-768'),
                    ('Hash', 'SHA-3'),
                ])
            elif 'Token Model' in sec:
                pdf2.metrics_row([
                    ('Total Supply', '10B AETHEL'),
                    ('Inflation', '0%'),
                    ('Supply Cap', 'Hard Capped'),
                ])
                pdf2.table(
                    ['Utility Role', 'Description'],
                    [['Staking', 'Validator participation and security bonding'],
                     ['Fee Settlement', 'Native unit for protocol fee accounting'],
                     ['Governance', 'Protocol-level voting and proposal submission'],
                     ['Compute Settlement', 'Payment for verified AI job execution'],
                     ['Burn', 'Fee-based supply reduction mechanism'],
                     ['Slashing', 'Economic accountability for misbehavior']],
                    [45, 121]
                )
            elif 'Developer Platform' in sec:
                pdf2.table(
                    ['SDK', 'Language', 'Primary Use'],
                    [['aethelred-go', 'Go', 'Node operations, consensus integration'],
                     ['aethelred-rs', 'Rust', 'High-performance verification, TEE'],
                     ['aethelred-py', 'Python', 'ML workflows, data science'],
                     ['aethelred-ts', 'TypeScript', 'Web integration, dApp frontends']],
                    [40, 35, 91]
                )
            continue

        if ln.startswith('### '): pdf2.h3(clean(ln[4:])); i += 1; continue
        if ln.strip().startswith('|'):
            table, nxt = parse_md_table(lines, i)
            if table:
                pdf2.table(table[0], table[1]); i = nxt; continue
        if ln.startswith('> '):
            bq.append(clean(ln[2:])); i += 1
            while i < len(lines) and lines[i].rstrip().startswith('> '):
                bq.append(clean(lines[i].rstrip()[2:])); i += 1
            pdf2.notice(' '.join(bq)); bq = []; continue
        m = re.match(r'^(\d+)\.\s+(.+)', ln)
        if m: nc += 1; pdf2.num(nc, clean(m.group(2))); i += 1; continue
        if ln.startswith('- '): pdf2.bullet(clean(ln[2:])); i += 1; continue
        if not ln.strip(): i += 1; nc = 0; continue
        para = [ln]; i += 1
        while i < len(lines):
            nl = lines[i].rstrip()
            if not nl.strip() or nl.startswith('#') or nl.startswith('-') or \
               nl.startswith('>') or nl.strip() == '---' or re.match(r'^\d+\.\s', nl):
                break
            para.append(nl); i += 1
        t = clean(' '.join(para))
        if t: pdf2.p(t)

    # Disclaimer
    pdf2.add_page(); pdf2.h2('Disclaimer')
    pdf2.p('This document is provided for informational purposes only. It does not '
           'constitute legal advice, financial advice, an offer to sell, a solicitation '
           'to buy, or a commitment to launch, list, or distribute tokens on any '
           'particular date or at any particular price.')
    pdf2.ln(4)
    pdf2.p('ADGM DLT Foundation registration is in preparation. No regulatory approval '
           'has been obtained.')
    pdf2.ln(4)
    pdf2.p('Any regulated activity requiring a Financial Services Permission will only '
           'be conducted by an appropriately authorised entity.')

    out = os.path.join(dl, 'aethelred-whitepaper.pdf')
    pdf2.output(out)
    mirror_download(base, out)
    print(f'Whitepaper: {out} ({os.path.getsize(out)//1024} KB, {pdf2.page_no()} pages)')


# ── Tokenomics generation ────────────────────────────────────────────────────
def gen_tokenomics(base, dl, logo):
    pdf = DocPDF(logo, 'AETHEL Tokenomics Paper')
    pdf.cover('AETHEL Tokenomics Paper', 'Token Economics, Utility Design, and Disclosure Controls')

    render_md(pdf, os.path.join(base, 'docs', 'TOKENOMICS.md'))
    toc = pdf.toc[:]

    pdf2 = DocPDF(logo, 'AETHEL Tokenomics Paper')
    pdf2.toc = toc
    pdf2.cover('AETHEL Tokenomics Paper', 'Token Economics, Utility Design, and Disclosure Controls')
    pdf2.build_toc()

    with open(os.path.join(base, 'docs', 'TOKENOMICS.md')) as f:
        lines = f.readlines()

    i = 0; skip = True; bq = []; nc = 0
    while i < len(lines):
        ln = lines[i].rstrip()
        if skip:
            if ln.startswith('## Important Notice'):
                skip = False; pdf2.add_page(); pdf2.h2('Important Notice')
            i += 1; continue

        if ln.strip() == '---': pdf2.hr(); i += 1; continue
        if ln.startswith('## '):
            sec = clean(ln[3:])
            pdf2.h2(sec); nc = 0; i += 1

            # ── Inject enrichments ────────────────────────────────────────
            if 'Current Public Disclosure' in sec:
                pdf2.table(
                    ['Category', 'Status', 'Notes'],
                    [['Total supply', 'Disclosed', '10,000,000,000 AETHEL'],
                     ['Post-genesis inflation', 'Disclosed', '0%'],
                     ['Utility roles', 'Disclosed', 'Staking, fees, governance, compute, burn'],
                     ['Launch float', 'Withheld', 'Pending canonical release'],
                     ['Token price', 'Withheld', 'Pending canonical release'],
                     ['Valuation', 'Withheld', 'Pending canonical release'],
                     ['Counterparty names', 'Withheld', 'Pending executed status'],
                     ['Performance metrics', 'Withheld', 'Pending benchmark verification']],
                    [42, 28, 96]
                )
            elif 'Token Nature' in sec:
                pdf2.metrics_row([
                    ('Token', 'AETHEL'),
                    ('Type', 'Native Utility'),
                    ('Supply', '10B Fixed'),
                    ('Inflation', '0%'),
                ])
            elif 'Fixed Supply' in sec:
                pdf2.table(
                    ['Parameter', 'Value'],
                    [['Total supply', '10,000,000,000 AETHEL'],
                     ['Genesis mint model', 'Fixed supply minted at genesis'],
                     ['Post-genesis inflation', 'Zero'],
                     ['Hard supply cap', '10,000,000,000 AETHEL'],
                     ['Cosmos denomination', 'uaethel (6 decimals)'],
                     ['EVM denomination', '18 decimals (compatibility)']],
                    [60, 106]
                )
            elif 'Utility Flows' in sec:
                pdf2.table(
                    ['Utility', 'Function', 'Economic Role'],
                    [['Staking', 'Validator admission + security', 'Bonded collateral'],
                     ['Slashing', 'Fraud/downtime penalties', 'Economic accountability'],
                     ['Fee Settlement', 'Protocol fee payment', 'Network usage pricing'],
                     ['Governance', 'Voting + proposals', 'Protocol control'],
                     ['Compute Settlement', 'Verified AI job payment', 'Primary demand driver'],
                     ['Burn', 'Fee-based supply reduction', 'Deflationary pressure']],
                    [38, 55, 73]
                )
                pdf2.flow_diagram('Token Utility Flow', [
                    'User submits AI inference job',
                    'AETHEL fee charged (base + priority)',
                    'Fee split: validators / burn / treasury (design targets)',
                    'Validator earns staking rewards',
                    'Burned portion permanently reduces supply',
                ])
            elif 'Burn and Deflation' in sec:
                pdf2.metrics_row([
                    ('Burn Model', 'Fee x Congestion'),
                    ('Baseline', 'Fixed Supply'),
                    ('Direction', 'Deflationary'),
                ])
            elif 'Governance and Change' in sec:
                pdf2.table(
                    ['Control Layer', 'Mechanism'],
                    [['Code-level', 'Supply constraints, hard cap enforcement'],
                     ['Disclosure', 'Claims register, counterparty state management'],
                     ['Legal', 'Regulatory status tracking, legal artifact control'],
                     ['Website', 'Drift checks, canonical source verification'],
                     ['Approval', 'Formal gates for public release']],
                    [42, 124]
                )
            elif 'Regulatory and Operating' in sec:
                pdf2.table(
                    ['Permitted Statement', 'Not Permitted Without Evidence'],
                    [['Follows governed disclosure controls', 'Registered with ADGM'],
                     ['Legal materials in preparation', 'Approved by ADGM'],
                     ['Protocol utility token design', 'Securities offering'],
                     ['Distinguishes utility from FSP', 'Completed regulatory filing']],
                    [83, 83]
                )
            elif 'Risk Factors' in sec:
                pdf2.table(
                    ['Risk Category', 'Description'],
                    [['Launch timing', 'Schedule may change pending approvals'],
                     ['Float disclosure', 'May remain withheld until approval complete'],
                     ['Counterparties', 'May not reach executed status on timeline'],
                     ['Technical', 'Benchmark, release, or testnet timing may shift'],
                     ['Regulatory', 'Interpretation may evolve across jurisdictions'],
                     ['Adoption', 'Usage may differ from projections'],
                     ['Token utility', 'Depends on actual network adoption']],
                    [42, 124]
                )
            continue

        if ln.startswith('### '): pdf2.h3(clean(ln[4:])); i += 1; continue
        if ln.strip().startswith('|'):
            table, nxt = parse_md_table(lines, i)
            if table:
                pdf2.table(table[0], table[1]); i = nxt; continue
        if ln.startswith('> '):
            bq.append(clean(ln[2:])); i += 1
            while i < len(lines) and lines[i].rstrip().startswith('> '):
                bq.append(clean(lines[i].rstrip()[2:])); i += 1
            pdf2.notice(' '.join(bq)); bq = []; continue
        m = re.match(r'^(\d+)\.\s+(.+)', ln)
        if m: nc += 1; pdf2.num(nc, clean(m.group(2))); i += 1; continue
        if ln.startswith('- '): pdf2.bullet(clean(ln[2:])); i += 1; continue
        if not ln.strip(): i += 1; nc = 0; continue
        para = [ln]; i += 1
        while i < len(lines):
            nl = lines[i].rstrip()
            if not nl.strip() or nl.startswith('#') or nl.startswith('-') or \
               nl.startswith('>') or nl.strip() == '---' or re.match(r'^\d+\.\s', nl):
                break
            para.append(nl); i += 1
        t = clean(' '.join(para))
        if t: pdf2.p(t)

    # Disclaimer
    pdf2.add_page(); pdf2.h2('Disclaimer')
    pdf2.p('This paper is provided for informational purposes only. It does not '
           'constitute legal advice, financial advice, an offer to sell, a solicitation '
           'to buy, or a commitment to launch, list, or distribute tokens on any '
           'particular date or at any particular price.')
    pdf2.ln(4)
    pdf2.p('ADGM DLT Foundation registration is in preparation. No regulatory approval '
           'has been obtained.')
    pdf2.ln(4)
    pdf2.p('Any regulated activity requiring a Financial Services Permission will only '
           'be conducted by an appropriately authorised entity.')

    out = os.path.join(dl, 'aethelred-tokenomics-paper.pdf')
    pdf2.output(out)
    mirror_download(base, out)
    print(f'Tokenomics: {out} ({os.path.getsize(out)//1024} KB, {pdf2.page_no()} pages)')


# ── Main ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dl = os.path.join(base, 'frontend', 'website', 'io', 'downloads')
    os.makedirs(dl, exist_ok=True)
    logo = os.path.join(base, 'frontend', 'website', 'io', 'aethelred-mark.png')

    gen_tokenomics(base, dl, logo)
    gen_whitepaper(base, dl, logo)
