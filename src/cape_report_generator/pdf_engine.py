"""
CAPEv2 Professional PDF Report Engine (Commercial Grade)
Generates exhaustive, publication-grade executive malware analysis PDF reports
with interactive clickable Table of Contents, native PDF bookmarks outline,
clean first-page executive summary, and complete untruncated technical appendices.
"""

import os
import json
import datetime
from typing import Optional, List, Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable, Flowable
)
from reportlab.pdfgen import canvas

try:
    from .parser import CapeReportData, defang, format_bytes
except ImportError:
    from parser import CapeReportData, defang, format_bytes


# ─── Color Palette (Executive Neutral Cybersecurity Theme) ─────────────────────
NAVY_PRIMARY = colors.HexColor("#0F172A")       # Slate 900
NAVY_SECONDARY = colors.HexColor("#1E293B")     # Slate 800
NAVY_LIGHT = colors.HexColor("#334155")         # Slate 700
ACCENT_BLUE = colors.HexColor("#2563EB")        # Blue 600
ACCENT_CYAN = colors.HexColor("#0284C7")        # Sky 600

RED_CRITICAL = colors.HexColor("#DC2626")       # Red 600
RED_BG = colors.HexColor("#FEF2F2")             # Red 50
AMBER_WARNING = colors.HexColor("#D97706")      # Amber 600
AMBER_BG = colors.HexColor("#FFFBEB")           # Amber 50
GREEN_CLEAN = colors.HexColor("#059669")        # Emerald 600
GREEN_BG = colors.HexColor("#ECFDF5")           # Emerald 50

BG_LIGHT = colors.HexColor("#F8FAFC")           # Slate 50
BORDER_LIGHT = colors.HexColor("#E2E8F0")       # Slate 200
TEXT_MAIN = colors.HexColor("#0F172A")
TEXT_MUTED = colors.HexColor("#64748B")         # Slate 500


class Bookmark(Flowable):
    """Generates internal PDF named destination and native bookmark outline."""
    def __init__(self, key: str, title: str = "", level: int = 0):
        super().__init__()
        self.key = key
        self.title = title
        self.level = level

    def wrap(self, availWidth, availHeight):
        return 0, 0

    def draw(self):
        self.canv.bookmarkPage(self.key)
        if self.title:
            self.canv.addOutlineEntry(self.title, self.key, self.level, closed=False)


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and print 'Page X of Y' 
    plus professional running headers and footers on all pages.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(TEXT_MUTED)

        # Header (pages 2+)
        if self._pageNumber > 1:
            header_title = getattr(self, "report_header_str", "CAPEv2 MALWARE ANALYSIS REPORT")
            self.drawString(54, 755, header_title)
            self.drawRightString(612 - 54, 755, getattr(self, "report_id_str", ""))
            self.setStrokeColor(BORDER_LIGHT)
            self.setLineWidth(0.5)
            self.line(54, 747, 612 - 54, 747)

        # Footer (all pages)
        self.setStrokeColor(BORDER_LIGHT)
        self.setLineWidth(0.5)
        self.line(54, 42, 612 - 54, 42)

        self.setFont("Helvetica", 8)
        self.setFillColor(TEXT_MUTED)
        footer_left = getattr(self, "footer_classification_str", "")
        self.drawString(54, 30, footer_left)
        self.drawRightString(612 - 54, 30, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


class CapePdfReport:
    """Enterprise-grade PDF Report Generator for CAPEv2 Sandbox Reports."""

    def __init__(self, data: CapeReportData, output_path: str, options: Optional[Dict[str, Any]] = None):
        self.data = data
        self.output_path = output_path
        self.options = options or {}

        # User-customizable fields (No hardcoded vendor names)
        self.analyst_name = self.options.get("analyst", "").strip()
        self.org_name = self.options.get("organization", "").strip()
        self.report_title = self.options.get("report_title", "").strip() or "CAPEv2 Sandbox Malware Analysis Report"
        self.classification = self.options.get("classification", "").strip()

        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Define fine-tuned typography styles for report elements."""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            fontName='Helvetica-Bold',
            fontSize=21,
            leading=25,
            textColor=NAVY_PRIMARY,
            spaceAfter=3
        ))
        self.styles.add(ParagraphStyle(
            name='ReportSubtitle',
            fontName='Helvetica',
            fontSize=10,
            leading=13,
            textColor=TEXT_MUTED,
            spaceAfter=10
        ))
        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=17,
            textColor=NAVY_PRIMARY,
            spaceBefore=12,
            spaceAfter=6,
            keepWithNext=True
        ))
        self.styles.add(ParagraphStyle(
            name='SubSectionHeading',
            fontName='Helvetica-Bold',
            fontSize=10.5,
            leading=14,
            textColor=ACCENT_BLUE,
            spaceBefore=10,
            spaceAfter=4,
            keepWithNext=True
        ))
        self.styles.add(ParagraphStyle(
            name='TableBody',
            fontName='Helvetica',
            fontSize=8,
            leading=10.5,
            textColor=TEXT_MAIN
        ))
        self.styles.add(ParagraphStyle(
            name='TableBodyBold',
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=10.5,
            textColor=TEXT_MAIN
        ))
        self.styles.add(ParagraphStyle(
            name='TableMono',
            fontName='Courier',
            fontSize=7.5,
            leading=9.5,
            textColor=NAVY_SECONDARY
        ))
        self.styles.add(ParagraphStyle(
            name='TableMonoRed',
            fontName='Courier-Bold',
            fontSize=7.5,
            leading=9.5,
            textColor=RED_CRITICAL
        ))
        self.styles.add(ParagraphStyle(
            name='VerdictBadge',
            fontName='Helvetica-Bold',
            fontSize=16,
            leading=18,
            textColor=colors.white,
            alignment=1
        ))
        self.styles.add(ParagraphStyle(
            name='IndexLink',
            fontName='Helvetica',
            fontSize=9,
            leading=15,
            textColor=ACCENT_BLUE
        ))

    def _esc(self, text: Any) -> str:
        """Escape XML entities for ReportLab Paragraphs."""
        if text is None:
            return ""
        s = str(text)
        s = s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        return s

    def build_pdf(self) -> str:
        """Assemble all sections and render the PDF document."""
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )

        story = []

        # ═══════════════════════════════════════════════════════════════════════
        # PAGE 1: EXECUTIVE SUMMARY & CLICKABLE TABLE OF CONTENTS
        # ═══════════════════════════════════════════════════════════════════════
        story.extend(self._build_header_block())
        story.append(Spacer(1, 10))

        story.append(self._build_verdict_banner())
        story.append(Spacer(1, 12))

        story.append(self._build_executive_overview_card())
        story.append(Spacer(1, 12))

        story.append(self._build_clickable_toc())
        story.append(PageBreak())  # Page 1 dedicated strictly to Executive Overview

        # ═══════════════════════════════════════════════════════════════════════
        # SECTION 1: TARGET SAMPLE IDENTIFICATION & COMPLETE HASHES
        # ═══════════════════════════════════════════════════════════════════════
        story.append(Bookmark("sec_target", "1. Target Sample Identification & Hashes"))
        story.append(self._build_section_heading("1. Target Sample Identification & Cryptographic Hashes", "sec_target"))
        story.extend(self._build_complete_hashes_block())
        story.append(Spacer(1, 14))

        # ═══════════════════════════════════════════════════════════════════════
        # SECTION 2: CAPE PAYLOAD & CONFIGURATION EXTRACTIONS (COMPLETE)
        # ═══════════════════════════════════════════════════════════════════════
        story.append(Bookmark("sec_cape", "2. CAPE Payload & Configuration Extractions"))
        story.append(self._build_section_heading("2. CAPE Advanced Payload & Configuration Extraction", "sec_cape"))
        story.extend(self._build_complete_cape_block())
        story.append(Spacer(1, 14))

        # ═══════════════════════════════════════════════════════════════════════
        # SECTION 3: MITRE ATT&CK MATRIX & DYNAMIC SIGNATURES (COMPLETE)
        # ═══════════════════════════════════════════════════════════════════════
        story.append(Bookmark("sec_mitre", "3. MITRE ATT&CK Matrix & Signatures"))
        story.append(self._build_section_heading("3. MITRE ATT&CK® Matrix & Dynamic Behavioral Signatures", "sec_mitre"))
        story.extend(self._build_complete_mitre_signatures_block())
        story.append(Spacer(1, 14))

        # ═══════════════════════════════════════════════════════════════════════
        # SECTION 4: PROCESS EXECUTION HIERARCHY & MONITORED PROCESSES
        # ═══════════════════════════════════════════════════════════════════════
        story.append(Bookmark("sec_processes", "4. Process Execution Hierarchy"))
        story.append(self._build_section_heading("4. Process Execution Hierarchy & Monitored Processes", "sec_processes"))
        story.extend(self._build_complete_processes_block())
        story.append(Spacer(1, 14))

        # ═══════════════════════════════════════════════════════════════════════
        # SECTION 5: NETWORK COMMUNICATIONS & COMPLETE IOC TABLE
        # ═══════════════════════════════════════════════════════════════════════
        story.append(Bookmark("sec_network", "5. Network Communications & IOCs"))
        story.append(self._build_section_heading("5. Network Communications & Indicators of Compromise (IOCs)", "sec_network"))
        story.extend(self._build_complete_network_block())
        story.append(Spacer(1, 14))

        # ═══════════════════════════════════════════════════════════════════════
        # SECTION 6: FILE SYSTEM & REGISTRY MODIFICATIONS (COMPLETE)
        # ═══════════════════════════════════════════════════════════════════════
        story.append(Bookmark("sec_behavior", "6. File System & Registry Modifications"))
        story.append(self._build_section_heading("6. File System & Registry Behavioral Modifications", "sec_behavior"))
        story.extend(self._build_complete_behavior_block())
        story.append(Spacer(1, 14))

        # ═══════════════════════════════════════════════════════════════════════
        # SECTION 7: DROPPED FILES & EXTRACTED ARTIFACTS (COMPLETE)
        # ═══════════════════════════════════════════════════════════════════════
        story.append(Bookmark("sec_dropped", "7. Dropped Files & Extracted Artifacts"))
        story.append(self._build_section_heading("7. Dropped Files & Extracted Artifacts", "sec_dropped"))
        story.extend(self._build_complete_dropped_block())
        story.append(Spacer(1, 14))

        # ═══════════════════════════════════════════════════════════════════════
        # SECTION 8: SANDBOX TELEMETRY & PROCESSING STATISTICS
        # ═══════════════════════════════════════════════════════════════════════
        story.append(Bookmark("sec_telemetry", "8. Sandbox Telemetry & Statistics"))
        story.append(self._build_section_heading("8. Sandbox Telemetry & Execution Statistics", "sec_telemetry"))
        story.extend(self._build_telemetry_block())
        story.append(Spacer(1, 14))

        # ═══════════════════════════════════════════════════════════════════════
        # SECTION 9: DISCLAIMER & LEGAL NOTICE
        # ═══════════════════════════════════════════════════════════════════════
        story.append(Bookmark("sec_disclaimer", "9. Disclaimer & Legal Notice"))
        story.append(self._build_section_heading("9. Disclaimer & Analytical Methodology", "sec_disclaimer"))
        story.append(self._build_disclaimer_block())

        # Render document with custom canvas
        def canvas_maker(*args, **kwargs):
            c = NumberedCanvas(*args, **kwargs)
            c.report_header_str = self.report_title.upper()
            c.report_id_str = f"Task #{self.data.id} | {self.data.filename[:28]}"
            footer_parts = []
            if self.classification:
                footer_parts.append(self.classification)
            if self.org_name:
                footer_parts.append(self.org_name)
            c.footer_classification_str = " | ".join(footer_parts) if footer_parts else "CAPEv2 Sandbox Threat Intelligence"
            return c

        doc.build(story, canvasmaker=canvas_maker)
        return self.output_path

    # ─── PAGE 1 BUILDERS ──────────────────────────────────────────────────────

    def _build_header_block(self) -> List[Any]:
        items = []

        # Top row: optional classification or date
        date_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        if self.classification:
            left_p = Paragraph(f"<b>{self._esc(self.classification)}</b>", ParagraphStyle(
                name='HdrClass', fontName='Helvetica-Bold', fontSize=8.5, textColor=NAVY_PRIMARY
            ))
            right_p = Paragraph(f"Report Generated: <b>{date_str}</b>", ParagraphStyle(
                name='HdrDate', fontName='Helvetica', fontSize=8, textColor=TEXT_MUTED, alignment=2
            ))
            tbl = Table([[left_p, right_p]], colWidths=[250, 254])
            tbl.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            items.append(tbl)
        else:
            right_p = Paragraph(f"Report Generated: <b>{date_str}</b>", ParagraphStyle(
                name='HdrDate', fontName='Helvetica', fontSize=8, textColor=TEXT_MUTED, alignment=2
            ))
            tbl = Table([[right_p]], colWidths=[504])
            tbl.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            items.append(tbl)

        items.append(Paragraph(self._esc(self.report_title), self.styles['ReportTitle']))

        sub_parts = ["Automated Dynamic Sandbox Detonation & Threat Analysis"]
        if self.org_name:
            sub_parts.append(f"Organization: <b>{self._esc(self.org_name)}</b>")
        if self.analyst_name:
            sub_parts.append(f"Analyst: <b>{self._esc(self.analyst_name)}</b>")

        items.append(Paragraph(" | ".join(sub_parts), self.styles['ReportSubtitle']))
        items.append(HRFlowable(width="100%", thickness=1.5, color=NAVY_PRIMARY, spaceAfter=4))
        return items

    def _build_verdict_banner(self) -> Table:
        v = self.data.verdict
        score = self.data.malscore

        if v == "MALICIOUS":
            banner_bg = RED_CRITICAL
            score_desc = "MALICIOUS ACTIVITY DETECTED"
        elif v == "SUSPICIOUS":
            banner_bg = AMBER_WARNING
            score_desc = "SUSPICIOUS BEHAVIOR DETECTED"
        elif v == "LOW RISK":
            banner_bg = colors.HexColor("#EAB308")
            score_desc = "LOW RISK / HEURISTIC FINDINGS"
        else:
            banner_bg = GREEN_CLEAN
            score_desc = "NO THREATS DETECTED"

        fam_str = f" | Malware Family: <b>{self._esc(', '.join(self.data.families))}</b>" if self.data.families else ""
        verdict_html = f"<b>{v}</b> (Threat Score: <b>{score:.1f}/10.0</b>)<br/><font size=9>{score_desc}{fam_str}</font>"

        p = Paragraph(verdict_html, self.styles['VerdictBadge'])
        tbl = Table([[p]], colWidths=[504])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), banner_bg),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 9),
        ]))
        return tbl

    def _build_executive_overview_card(self) -> Table:
        d = self.data
        data = [
            [
                Paragraph("<b>Analysis Task ID:</b>", self.styles['TableBodyBold']),
                Paragraph(f"#{self._esc(d.id)}", self.styles['TableBody']),
                Paragraph("<b>Target Filename:</b>", self.styles['TableBodyBold']),
                Paragraph(f"<b>{self._esc(d.filename)}</b>", self.styles['TableBody']),
            ],
            [
                Paragraph("<b>Analysis Package:</b>", self.styles['TableBodyBold']),
                Paragraph(f"<code>{self._esc(d.package)}</code>", self.styles['TableBody']),
                Paragraph("<b>File Size:</b>", self.styles['TableBodyBold']),
                Paragraph(f"{d.file_size_fmt} ({d.file_size:,} bytes)", self.styles['TableBody']),
            ],
            [
                Paragraph("<b>Execution Duration:</b>", self.styles['TableBodyBold']),
                Paragraph(f"{d.duration} seconds", self.styles['TableBody']),
                Paragraph("<b>Sandbox Environment:</b>", self.styles['TableBodyBold']),
                Paragraph(f"{self._esc(d.machine_name)} ({self._esc(d.machine_os)})", self.styles['TableBody']),
            ],
            [
                Paragraph("<b>Started At:</b>", self.styles['TableBodyBold']),
                Paragraph(self._esc(d.started), self.styles['TableBody']),
                Paragraph("<b>Completed At:</b>", self.styles['TableBodyBold']),
                Paragraph(self._esc(d.ended), self.styles['TableBody']),
            ],
            [
                Paragraph("<b>Primary SHA-256:</b>", self.styles['TableBodyBold']),
                Paragraph(f"<code>{d.sha256}</code>", self.styles['TableMono']),
                Paragraph("<b>Investigator / Analyst:</b>", self.styles['TableBodyBold']),
                Paragraph(self._esc(self.analyst_name) if self.analyst_name else "Automated Analysis", self.styles['TableBody']),
            ],
        ]

        tbl = Table(data, colWidths=[110, 142, 110, 142])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), BG_LIGHT),
            ('BACKGROUND', (2, 0), (2, -1), BG_LIGHT),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 3.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        return tbl

    def _build_clickable_toc(self) -> Table:
        """Interactive, Clickable Table of Contents with jump links."""
        p_title = Paragraph("<b>TABLE OF CONTENTS (CLICKABLE INDEX)</b>", ParagraphStyle(
            name='IndexTitle', fontName='Helvetica-Bold', fontSize=9, textColor=NAVY_PRIMARY
        ))

        idx_col1 = Paragraph("""
<b>1.</b> <a href="#sec_target" color="#2563EB"><u>Target Sample Identification &amp; Cryptographic Hashes</u></a><br/>
<b>2.</b> <a href="#sec_cape" color="#2563EB"><u>CAPE Advanced Payload &amp; Configuration Extraction</u></a><br/>
<b>3.</b> <a href="#sec_mitre" color="#2563EB"><u>MITRE ATT&amp;CK® Matrix &amp; Behavioral Signatures</u></a><br/>
<b>4.</b> <a href="#sec_processes" color="#2563EB"><u>Process Execution Hierarchy &amp; Monitored Processes</u></a><br/>
<b>5.</b> <a href="#sec_network" color="#2563EB"><u>Network Communications &amp; Indicators of Compromise (IOCs)</u></a>
""", self.styles['IndexLink'])

        idx_col2 = Paragraph("""
<b>6.</b> <a href="#sec_behavior" color="#2563EB"><u>File System &amp; Registry Behavioral Modifications</u></a><br/>
<b>7.</b> <a href="#sec_dropped" color="#2563EB"><u>Dropped Files &amp; Extracted Artifacts</u></a><br/>
<b>8.</b> <a href="#sec_telemetry" color="#2563EB"><u>Sandbox Telemetry &amp; Execution Statistics</u></a><br/>
<b>9.</b> <a href="#sec_disclaimer" color="#2563EB"><u>Disclaimer &amp; Analytical Methodology</u></a>
""", self.styles['IndexLink'])

        data = [
            [p_title, ""],
            [idx_col1, idx_col2]
        ]
        tbl = Table(data, colWidths=[252, 252])
        tbl.setStyle(TableStyle([
            ('SPAN', (0, 0), (1, 0)),
            ('BACKGROUND', (0, 0), (-1, 0), BORDER_LIGHT),
            ('BACKGROUND', (0, 1), (-1, -1), BG_LIGHT),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]))
        return tbl

    def _build_section_heading(self, title: str, anchor_name: str = "") -> Paragraph:
        safe_title = title.replace('&', '&amp;') if '&amp;' not in title else title
        anchor_tag = f'<a name="{anchor_name}"/>' if anchor_name else ''
        return Paragraph(f'{anchor_tag}<b>{safe_title}</b>', self.styles['SectionHeading'])

    # ─── SECTION 1: TARGET SAMPLE IDENTIFICATION & HASHES ─────────────────────

    def _build_complete_hashes_block(self) -> List[Any]:
        items = []
        d = self.data
        data = [
            [Paragraph("<b>File Format:</b>", self.styles['TableBodyBold']), Paragraph(self._esc(d.file_type), self.styles['TableBody'])],
            [Paragraph("<b>MIME Type:</b>", self.styles['TableBodyBold']), Paragraph(self._esc(d.mime) or "application/octet-stream", self.styles['TableBody'])],
            [Paragraph("<b>Original Path:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{self._esc(d.file_path or d.filename)}</code>", self.styles['TableMono'])],
            [Paragraph("<b>MD5:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{d.md5}</code>", self.styles['TableMono'])],
            [Paragraph("<b>SHA-1:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{d.sha1}</code>", self.styles['TableMono'])],
            [Paragraph("<b>SHA-256:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{d.sha256}</code>", self.styles['TableMono'])],
            [Paragraph("<b>SHA-512:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{d.sha512}</code>", self.styles['TableMono'])],
            [Paragraph("<b>SSDEEP:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{d.ssdeep}</code>", self.styles['TableMono'])],
            [Paragraph("<b>TLSH:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{d.tlsh}</code>", self.styles['TableMono'])],
            [Paragraph("<b>CRC32:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{d.crc32}</code>", self.styles['TableMono'])],
            [Paragraph("<b>RH_HASH:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{d.rh_hash}</code>", self.styles['TableMono'])],
            [Paragraph("<b>SHA3-384:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{d.sha3_384}</code>", self.styles['TableMono'])],
        ]

        if d.guest_paths:
            data.append([Paragraph("<b>Guest Placement:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{self._esc(', '.join(d.guest_paths))}</code>", self.styles['TableMono'])])

        if d.clamav:
            data.append([Paragraph("<b>ClamAV Verdict:</b>", self.styles['TableBodyBold']), Paragraph(f"<b>{self._esc(d.clamav)}</b>", self.styles['TableBody'])])

        tbl = Table(data, colWidths=[110, 394])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), BG_LIGHT),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        items.append(tbl)

        # YARA Matches
        if d.yara_matches:
            items.append(Spacer(1, 6))
            items.append(Paragraph(f"<b>Matching YARA Rules ({len(d.yara_matches)} Total)</b>", self.styles['SubSectionHeading']))
            yara_rows = [
                [Paragraph("<b>Rule Name</b>", self.styles['TableBodyBold']), Paragraph("<b>Description / Meta</b>", self.styles['TableBodyBold'])]
            ]
            for y in d.yara_matches:
                if isinstance(y, dict):
                    r_name = y.get("name", "Unnamed Rule")
                    meta = y.get("meta", {}) or {}
                    desc = meta.get("description") or meta.get("author") or str(meta)
                    yara_rows.append([
                        Paragraph(f"<b>{self._esc(r_name)}</b>", self.styles['TableBody']),
                        Paragraph(self._esc(desc), self.styles['TableBody']),
                    ])
            y_tbl = Table(yara_rows, colWidths=[160, 344])
            y_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            items.append(y_tbl)

        return items

    # ─── SECTION 2: CAPE EXTRACTIONS (ALL CONFIGS & ALL PAYLOADS) ─────────────

    def _build_complete_cape_block(self) -> List[Any]:
        items = []

        if not self.data.configs and not self.data.payloads and not self.data.procdump:
            items.append(Paragraph("<i>No decrypted configurations or injected payloads were identified for this execution trace.</i>", self.styles['TableBody']))
            return items

        # A) All Extracted Malware Configurations
        if self.data.configs:
            items.append(Paragraph(f"<b>Decrypted Malware Configurations ({len(self.data.configs)} Total)</b>", self.styles['SubSectionHeading']))
            for cfg in self.data.configs:
                if not isinstance(cfg, dict):
                    continue
                for family, details in cfg.items():
                    if family.startswith("_"):
                        continue
                    rows = [
                        [Paragraph("<b>Malware Family:</b>", self.styles['TableBodyBold']), Paragraph(f"<b>{self._esc(family)}</b>", self.styles['TableBodyBold'])],
                    ]
                    if isinstance(details, dict):
                        for k, v in details.items():
                            val_str = ", ".join(map(str, v)) if isinstance(v, list) else str(v)
                            if any(proto in val_str for proto in ['http', 'ftp', '://']):
                                val_str = defang(val_str)
                            is_sensitive = any(w in k.lower() for w in ['password', 'c2', 'username', 'key', 'persistence'])
                            rows.append([
                                Paragraph(f"<b>{self._esc(k)}:</b>", self.styles['TableBodyBold']),
                                Paragraph(f"<code>{self._esc(val_str)}</code>", self.styles['TableMonoRed'] if is_sensitive else self.styles['TableMono'])
                            ])

                    cfg_tbl = Table(rows, colWidths=[150, 354])
                    cfg_tbl.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), RED_BG),
                        ('BACKGROUND', (0, 1), (0, -1), BG_LIGHT),
                        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
                        ('LEFTPADDING', (0, 0), (-1, -1), 6),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ]))
                    items.append(cfg_tbl)
                    items.append(Spacer(1, 8))

        # B) ALL Extracted Payloads / Injected Shellcodes
        if self.data.payloads:
            items.append(Paragraph(f"<b>Extracted / Injected Payloads ({len(self.data.payloads)} Total — All Included)</b>", self.styles['SubSectionHeading']))
            p_rows = [
                [
                    Paragraph("<b>Type / Classification</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Size</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>SHA-256 Hash</b>", self.styles['TableBodyBold']),
                ]
            ]
            for p in self.data.payloads:  # ALL payloads, no cut
                ctype = p.get("cape_type") or "Payload"
                psize = format_bytes(p.get("size", 0))
                psha = p.get("sha256", "N/A")
                p_rows.append([
                    Paragraph(self._esc(ctype), self.styles['TableBody']),
                    Paragraph(psize, self.styles['TableBody']),
                    Paragraph(f"<code>{psha}</code>", self.styles['TableMono']),
                ])

            p_tbl = Table(p_rows, colWidths=[160, 60, 284])
            p_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
                ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ]))
            items.append(p_tbl)
            items.append(Spacer(1, 8))

        # C) Process Dumps
        if self.data.procdump:
            items.append(Paragraph(f"<b>Process Dumps ({len(self.data.procdump)} Total)</b>", self.styles['SubSectionHeading']))
            pd_rows = [
                [
                    Paragraph("<b>PID</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Process Name</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Size</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>SHA-256</b>", self.styles['TableBodyBold']),
                ]
            ]
            for pd in self.data.procdump:
                pd_rows.append([
                    Paragraph(str(pd.get("pid", "?")), self.styles['TableBody']),
                    Paragraph(self._esc(pd.get("process_name") or "dump"), self.styles['TableBody']),
                    Paragraph(format_bytes(pd.get("size", 0)), self.styles['TableBody']),
                    Paragraph(f"<code>{pd.get('sha256', 'N/A')}</code>", self.styles['TableMono']),
                ])
            pd_tbl = Table(pd_rows, colWidths=[50, 110, 60, 284])
            pd_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            items.append(pd_tbl)

        return items

    # ─── SECTION 3: MITRE ATT&CK & SIGNATURES (ALL OF THEM) ───────────────────

    def _build_complete_mitre_signatures_block(self) -> List[Any]:
        items = []

        if not self.data.ttps and not self.data.signatures:
            items.append(Paragraph("<i>No heuristic signatures or MITRE ATT&amp;CK techniques were triggered during analysis.</i>", self.styles['TableBody']))
            return items

        # A) All MITRE ATT&CK Techniques
        if self.data.ttps:
            items.append(Paragraph(f"<b>MITRE ATT&amp;CK® Techniques Observed ({len(self.data.ttps)} Total — All Included)</b>", self.styles['SubSectionHeading']))
            ttp_rows = [
                [
                    Paragraph("<b>Technique ID</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Tactic</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Technique Name / Signature</b>", self.styles['TableBodyBold']),
                ]
            ]
            for t in self.data.ttps:
                ttp_id = t.get("ttp") or "N/A"
                sig = t.get("signature") or "Detected behavioral pattern"
                tactic = "Execution" if "1059" in ttp_id else ("Command &amp; Control" if "1071" in ttp_id else "Defense Evasion")
                ttp_rows.append([
                    Paragraph(f"<code>{ttp_id}</code>", self.styles['TableMonoRed']),
                    Paragraph(tactic, self.styles['TableBody']),
                    Paragraph(self._esc(sig), self.styles['TableBody']),
                ])

            ttp_tbl = Table(ttp_rows, colWidths=[90, 110, 304])
            ttp_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            items.append(ttp_tbl)
            items.append(Spacer(1, 8))

        # B) All Triggered Dynamic Signatures
        if self.data.signatures:
            items.append(Paragraph(f"<b>Triggered Dynamic Behavioral Signatures ({len(self.data.signatures)} Total — All Included)</b>", self.styles['SubSectionHeading']))
            sig_rows = [
                [
                    Paragraph("<b>Severity</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Signature Name</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Description</b>", self.styles['TableBodyBold']),
                ]
            ]
            for s in self.data.signatures:
                sev = s.get("severity", 1)
                sev_label = "HIGH" if sev >= 3 else ("MEDIUM" if sev == 2 else "LOW")
                sev_color = RED_CRITICAL if sev >= 3 else (AMBER_WARNING if sev == 2 else NAVY_LIGHT)
                sig_rows.append([
                    Paragraph(f"<b><font color='{sev_color.hexval()}'>{sev_label} ({sev})</font></b>", self.styles['TableBody']),
                    Paragraph(f"<b>{self._esc(s.get('name', 'N/A'))}</b>", self.styles['TableBodyBold']),
                    Paragraph(self._esc(s.get("description", "")), self.styles['TableBody']),
                ])

            sig_tbl = Table(sig_rows, colWidths=[70, 160, 274])
            sig_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            items.append(sig_tbl)

        return items

    # ─── SECTION 4: PROCESSES & HIERARCHY (ALL PROCESSES) ─────────────────────

    def _build_complete_processes_block(self) -> List[Any]:
        items = []

        if not self.data.process_list:
            items.append(Paragraph("<i>No process execution traces were recorded.</i>", self.styles['TableBody']))
            return items

        items.append(Paragraph(f"<b>Monitored Processes ({len(self.data.process_list)} Total — All Included)</b>", self.styles['SubSectionHeading']))
        rows = [
            [
                Paragraph("<b>PID &larr; PPID</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Process Name</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Command Line &amp; Image Path</b>", self.styles['TableBodyBold']),
            ]
        ]

        for p in self.data.process_list:
            pid = p.get("pid", "?")
            ppid = p.get("ppid", "?")
            name = p.get("name", "Unknown")
            cmd = p.get("command_line") or p.get("path") or "No command line arguments captured"

            rows.append([
                Paragraph(f"<code>{pid} &larr; {ppid}</code>", self.styles['TableMono']),
                Paragraph(f"<b>{self._esc(name)}</b>", self.styles['TableBodyBold']),
                Paragraph(f"<code>{self._esc(cmd)}</code>", self.styles['TableMono']),
            ])

        tbl = Table(rows, colWidths=[80, 114, 310])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        items.append(tbl)
        return items

    # ─── SECTION 5: NETWORK COMMUNICATIONS & IOCs (COMPLETE) ──────────────────

    def _build_complete_network_block(self) -> List[Any]:
        items = []

        # Defanged Network IOCs
        if self.data.network_iocs:
            items.append(Paragraph(f"<b>Defanged Network Indicators of Compromise ({len(self.data.network_iocs)} Total)</b>", self.styles['SubSectionHeading']))
            ioc_rows = [
                [
                    Paragraph("<b>Indicator Type</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Defanged Value (Safe for SIEM / EDR Ingestion)</b>", self.styles['TableBodyBold']),
                ]
            ]
            for ioc in self.data.network_iocs:
                ioc_rows.append([
                    Paragraph(f"<b>{self._esc(ioc['type'])}</b>", self.styles['TableBody']),
                    Paragraph(f"<code>{self._esc(ioc['defanged'])}</code>", self.styles['TableMonoRed']),
                ])

            ioc_tbl = Table(ioc_rows, colWidths=[160, 344])
            ioc_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), RED_CRITICAL),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 3.5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
            ]))
            items.append(ioc_tbl)
            items.append(Spacer(1, 8))

        # DNS Queries
        if self.data.dns_requests:
            items.append(Paragraph(f"<b>DNS Queries &amp; Resolutions ({len(self.data.dns_requests)} Total)</b>", self.styles['SubSectionHeading']))
            dns_rows = [
                [
                    Paragraph("<b>Query / Domain</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Type</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Resolved Answers / IPs</b>", self.styles['TableBodyBold']),
                ]
            ]
            for d in self.data.dns_requests:
                req = d.get("request") or d.get("domain") or "N/A"
                qtype = d.get("type") or "A"
                ans = d.get("answers", [])
                ans_str = ", ".join([a.get("data", "") for a in ans if isinstance(a, dict)]) or "No answer"
                dns_rows.append([
                    Paragraph(f"<code>{defang(req)}</code>", self.styles['TableMono']),
                    Paragraph(str(qtype), self.styles['TableBody']),
                    Paragraph(f"<code>{defang(ans_str)}</code>", self.styles['TableMono']),
                ])
            dns_tbl = Table(dns_rows, colWidths=[200, 50, 254])
            dns_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            items.append(dns_tbl)
            items.append(Spacer(1, 8))

        # HTTP Requests
        if self.data.http_requests:
            items.append(Paragraph(f"<b>HTTP Requests ({len(self.data.http_requests)} Total)</b>", self.styles['SubSectionHeading']))
            http_rows = [
                [
                    Paragraph("<b>Method</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Host &amp; URI</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Status</b>", self.styles['TableBodyBold']),
                ]
            ]
            for h in self.data.http_requests:
                m = h.get("method", "GET")
                uri = h.get("uri") or h.get("path", "/")
                host = h.get("host", "")
                status = str(h.get("response", ""))
                http_rows.append([
                    Paragraph(f"<b>{m}</b>", self.styles['TableBody']),
                    Paragraph(f"<code>{defang(host + uri)}</code>", self.styles['TableMono']),
                    Paragraph(status, self.styles['TableBody']),
                ])
            http_tbl = Table(http_rows, colWidths=[60, 384, 60])
            http_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            items.append(http_tbl)
            items.append(Spacer(1, 8))

        # TCP Connections
        if self.data.tcp_connections:
            items.append(Paragraph(f"<b>TCP Network Flows ({len(self.data.tcp_connections)} Total)</b>", self.styles['SubSectionHeading']))
            tcp_rows = [
                [
                    Paragraph("<b>Source</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Destination IP:Port</b>", self.styles['TableBodyBold']),
                ]
            ]
            for t in self.data.tcp_connections:
                src = f"{t.get('src')}:{t.get('sport')}"
                dst = f"{t.get('dst')}:{t.get('dport')}"
                tcp_rows.append([
                    Paragraph(f"<code>{src}</code>", self.styles['TableMono']),
                    Paragraph(f"<code>{defang(dst)}</code>", self.styles['TableMono']),
                ])
            tcp_tbl = Table(tcp_rows, colWidths=[200, 304])
            tcp_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            items.append(tcp_tbl)

        if not self.data.network_iocs and not self.data.dns_requests and not self.data.http_requests and not self.data.tcp_connections:
            items.append(Paragraph("<i>No network egress or communication activity was recorded during execution.</i>", self.styles['TableBody']))

        return items

    # ─── SECTION 6: BEHAVIORAL MODIFICATIONS (ALL OF THEM) ────────────────────

    def _build_complete_behavior_block(self) -> List[Any]:
        items = []
        d = self.data

        # Metrics Card
        summary_data = [
            [
                Paragraph("<b>Files Written:</b>", self.styles['TableBodyBold']),
                Paragraph(str(len(d.files_written)), self.styles['TableBody']),
                Paragraph("<b>Registry Keys Written:</b>", self.styles['TableBodyBold']),
                Paragraph(str(len(d.keys_written)), self.styles['TableBody']),
            ],
            [
                Paragraph("<b>Files Deleted:</b>", self.styles['TableBodyBold']),
                Paragraph(str(len(d.files_deleted)), self.styles['TableBody']),
                Paragraph("<b>Mutexes Created:</b>", self.styles['TableBodyBold']),
                Paragraph(str(len(d.mutexes)), self.styles['TableBody']),
            ],
            [
                Paragraph("<b>Commands Executed:</b>", self.styles['TableBodyBold']),
                Paragraph(str(len(d.executed_commands)), self.styles['TableBody']),
                Paragraph("<b>Services Started:</b>", self.styles['TableBodyBold']),
                Paragraph(str(len(d.started_services)), self.styles['TableBody']),
            ],
        ]
        sum_tbl = Table(summary_data, colWidths=[130, 122, 130, 122])
        sum_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), BG_LIGHT),
            ('BACKGROUND', (2, 0), (2, -1), BG_LIGHT),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('TOPPADDING', (0, 0), (-1, -1), 3.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ]))
        items.append(sum_tbl)
        items.append(Spacer(1, 8))

        # Executed Commands
        if d.executed_commands:
            items.append(Paragraph(f"<b>Commands Executed ({len(d.executed_commands)} Total)</b>", self.styles['SubSectionHeading']))
            cmd_rows = [[Paragraph("<b>Command Line</b>", self.styles['TableBodyBold'])]]
            for cmd in d.executed_commands:
                cmd_rows.append([Paragraph(f"<code>{self._esc(cmd)}</code>", self.styles['TableMono'])])
            cmd_tbl = Table(cmd_rows, colWidths=[504])
            cmd_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            items.append(cmd_tbl)
            items.append(Spacer(1, 8))

        # Persistence & Security Bypass Registry Keys
        if d.persistence_keys or d.security_bypass_keys:
            items.append(Paragraph("<b>Highlighted Registry Modifications (Persistence &amp; Defense Evasion)</b>", self.styles['SubSectionHeading']))
            reg_rows = [[Paragraph("<b>Category</b>", self.styles['TableBodyBold']), Paragraph("<b>Registry Key Modified</b>", self.styles['TableBodyBold'])]]
            for k in d.persistence_keys:
                reg_rows.append([Paragraph("<b><font color='#DC2626'>Persistence</font></b>", self.styles['TableBody']), Paragraph(f"<code>{self._esc(k)}</code>", self.styles['TableMonoRed'])])
            for k in d.security_bypass_keys:
                reg_rows.append([Paragraph("<b><font color='#D97706'>Defense Evasion</font></b>", self.styles['TableBody']), Paragraph(f"<code>{self._esc(k)}</code>", self.styles['TableMono'])])
            reg_tbl = Table(reg_rows, colWidths=[120, 384])
            reg_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            items.append(reg_tbl)
            items.append(Spacer(1, 8))

        # Files Written (All of them)
        if d.files_written:
            items.append(Paragraph(f"<b>Files Written / Modified ({len(d.files_written)} Total — All Included)</b>", self.styles['SubSectionHeading']))
            fw_rows = [[Paragraph("<b>File Path</b>", self.styles['TableBodyBold'])]]
            for fw in d.files_written:
                fw_rows.append([Paragraph(f"<code>{self._esc(fw)}</code>", self.styles['TableMono'])])
            fw_tbl = Table(fw_rows, colWidths=[504])
            fw_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 2.5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
            ]))
            items.append(fw_tbl)
            items.append(Spacer(1, 8))

        # Mutexes Created
        if d.mutexes:
            items.append(Paragraph(f"<b>Mutexes Created ({len(d.mutexes)} Total)</b>", self.styles['SubSectionHeading']))
            m_rows = [[Paragraph("<b>Mutex Name</b>", self.styles['TableBodyBold'])]]
            for m in d.mutexes:
                m_rows.append([Paragraph(f"<code>{self._esc(m)}</code>", self.styles['TableMono'])])
            m_tbl = Table(m_rows, colWidths=[504])
            m_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 2.5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
            ]))
            items.append(m_tbl)

        return items

    # ─── SECTION 7: DROPPED FILES (ALL OF THEM) ───────────────────────────────

    def _build_complete_dropped_block(self) -> List[Any]:
        items = []
        if not self.data.dropped:
            items.append(Paragraph("<i>No dropped files were captured during sandbox detonation.</i>", self.styles['TableBody']))
            return items

        items.append(Paragraph(f"<b>Dropped Files ({len(self.data.dropped)} Total — All Included)</b>", self.styles['SubSectionHeading']))
        rows = [
            [
                Paragraph("<b>File Name</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Size</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Type Description</b>", self.styles['TableBodyBold']),
            ]
        ]
        for f in self.data.dropped:
            name = f.get("name")
            if isinstance(name, list):
                name = name[0] if name else "Unknown"
            size = format_bytes(f.get("size", 0))
            ftype = f.get("type", "Unknown")

            rows.append([
                Paragraph(f"<b>{self._esc(name)}</b>", self.styles['TableBody']),
                Paragraph(size, self.styles['TableBody']),
                Paragraph(self._esc(ftype), self.styles['TableBody']),
            ])

        tbl = Table(rows, colWidths=[150, 60, 294])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        items.append(tbl)
        return items

    # ─── SECTION 8: SANDBOX TELEMETRY & PROCESSING STATISTICS ─────────────────

    def _build_telemetry_block(self) -> List[Any]:
        items = []
        d = self.data

        rows = [
            [Paragraph("<b>Sandbox Machine:</b>", self.styles['TableBodyBold']), Paragraph(self._esc(d.machine_name), self.styles['TableBody'])],
            [Paragraph("<b>Operating System:</b>", self.styles['TableBodyBold']), Paragraph(self._esc(d.machine_os), self.styles['TableBody'])],
            [Paragraph("<b>Network Routing:</b>", self.styles['TableBodyBold']), Paragraph(self._esc(d.route), self.styles['TableBody'])],
            [Paragraph("<b>Sandbox Version:</b>", self.styles['TableBodyBold']), Paragraph(f"{self._esc(d.version)} (Commit: {self._esc(d.commit or 'N/A')})", self.styles['TableBody'])],
            [Paragraph("<b>Package / Loader:</b>", self.styles['TableBodyBold']), Paragraph(self._esc(d.package), self.styles['TableBody'])],
            [Paragraph("<b>Custom Options:</b>", self.styles['TableBodyBold']), Paragraph(self._esc(d.options) or "None specified", self.styles['TableBody'])],
        ]

        if d.statistics:
            proc_time = d.statistics.get("processing", {})
            if isinstance(proc_time, dict):
                times = [f"{k}: {v:.2f}s" for k, v in proc_time.items() if isinstance(v, (int, float))]
                if times:
                    rows.append([Paragraph("<b>Module Execution Times:</b>", self.styles['TableBodyBold']), Paragraph(self._esc(", ".join(times)), self.styles['TableBody'])])

        tbl = Table(rows, colWidths=[150, 354])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), BG_LIGHT),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('TOPPADDING', (0, 0), (-1, -1), 3.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ]))
        items.append(tbl)
        return items

    # ─── SECTION 9: DISCLAIMER & LEGAL NOTICE ─────────────────────────────────

    def _build_disclaimer_block(self) -> Table:
        text = """
<b>ANALYTICAL NOTICE:</b> This dynamic malware analysis report was compiled from empirical execution telemetry 
captured within an isolated virtual machine sandbox. Dynamic analysis reflects the observable behaviors of the submitted 
artifact under specific environmental and temporal constraints. Evasive techniques, dormant timers, or target-dependent 
triggers may alter behavior outside this sandbox environment. All indicators and credentials extracted should be handled 
according to your organization's security procedures.
"""
        p_disc = Paragraph(text, ParagraphStyle(name='Disc', fontName='Helvetica', fontSize=7.5, leading=10.5, textColor=TEXT_MUTED))
        box = Table([[p_disc]], colWidths=[504])
        box.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        return box


def generate_pdf_report(
    json_path: str,
    output_pdf_path: Optional[str] = None,
    options: Optional[Dict[str, Any]] = None
) -> str:
    """Convenience function to parse a JSON report and render a publication-grade PDF report."""
    if not output_pdf_path:
        base, _ = os.path.splitext(json_path)
        output_pdf_path = f"{base}_Analysis_Report.pdf"

    with open(json_path, 'r', encoding='utf-8', errors='ignore') as f:
        raw_data = json.load(f)

    data = CapeReportData(raw_data, filepath=json_path)
    engine = CapePdfReport(data, output_pdf_path, options=options)
    return engine.build_pdf()
