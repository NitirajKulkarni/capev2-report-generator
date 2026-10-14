"""
CAPEv2 Professional PDF Report Engine (Commercial Grade - Redesigned)
Developed by Nitiraj Kulkarni.

Features:
- Professional, minimalist cybersecurity design system.
- Two-pass rendering with in-memory page counting: guarantees 100% accurate anchor link
  jumping to the exact destination page and vertical coordinate without breaking ReportLab destinations.
- Dynamic Table of Contents: Automatically excludes empty sections and renumbers active sections.
- Monospace copyable Cryptographic Hashes Card: Full hashes without border clipping.
- Clean Page 1 Executive Overview with verdict banner, telemetry card, and interactive TOC.
"""

import os
import io
import json
import datetime
from typing import Optional, List, Dict, Any, Tuple

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable, Flowable, Preformatted
)
from reportlab.pdfgen import canvas

try:
    from .parser import CapeReportData, defang, format_bytes
except ImportError:
    from parser import CapeReportData, defang, format_bytes


# ─── Color Palette (Executive Minimalist Theme) ────────────────────────────────
SLATE_900 = colors.HexColor("#0F172A")       # Primary text & deep accents
SLATE_800 = colors.HexColor("#1E293B")       # Table headers & dark cards
SLATE_700 = colors.HexColor("#334155")       # Borders & subheadings
SLATE_500 = colors.HexColor("#64748B")       # Muted text & footers
SLATE_200 = colors.HexColor("#E2E8F0")       # Light borders
SLATE_100 = colors.HexColor("#F1F5F9")       # Code block background
SLATE_50  = colors.HexColor("#F8FAFC")       # Soft card fill

BLUE_600  = colors.HexColor("#2563EB")       # Active links & hyperlinks
BLUE_50   = colors.HexColor("#EFF6FF")       # Link hover tint

RED_600   = colors.HexColor("#DC2626")       # Malicious verdict
RED_50    = colors.HexColor("#FEF2F2")

AMBER_600 = colors.HexColor("#D97706")       # Suspicious verdict
AMBER_50  = colors.HexColor("#FFFBEB")

GREEN_600 = colors.HexColor("#059669")       # Clean / Low risk verdict
GREEN_50  = colors.HexColor("#ECFDF5")


class Bookmark(Flowable):
    """Generates native PDF document outline bookmarks."""
    def __init__(self, key: str, title: str = "", level: int = 0):
        super().__init__()
        self.key = key
        self.title = title
        self.level = level

    def wrap(self, availWidth, availHeight):
        return 0, 0

    def draw(self):
        if self.title:
            self.canv.addOutlineEntry(self.title, self.key, self.level, closed=False)


class SinglePassNumberedCanvas(canvas.Canvas):
    """
    Single-pass canvas that knows total_pages in advance.
    Draws headers and footers dynamically on showPage() without replaying __dict__,
    preserving ReportLab's internal page destination references and anchor links.
    """
    def __init__(self, *args, total_pages: int = 1, header_title: str = "", id_str: str = "", footer_str: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        self.total_pages = max(1, total_pages)
        self.header_title = header_title
        self.id_str = id_str
        self.footer_str = footer_str

    def showPage(self):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(SLATE_500)

        # Header (Pages 2+)
        if self._pageNumber > 1:
            self.drawString(54, 755, self.header_title)
            self.drawRightString(612 - 54, 755, self.id_str)
            self.setStrokeColor(SLATE_200)
            self.setLineWidth(0.5)
            self.line(54, 747, 612 - 54, 747)

        # Footer (All pages)
        self.setStrokeColor(SLATE_200)
        self.setLineWidth(0.5)
        self.line(54, 42, 612 - 54, 42)

        self.drawString(54, 30, self.footer_str)
        self.drawRightString(612 - 54, 30, f"Page {self._pageNumber} of {self.total_pages}")
        self.restoreState()
        super().showPage()


class CapePdfReport:
    """Enterprise-grade PDF Report Generator with dynamic sections and copyable hashes."""

    def __init__(self, data: CapeReportData, output_path: str, options: Optional[Dict[str, Any]] = None):
        self.data = data
        self.output_path = output_path
        self.options = options or {}

        # User customization (Neutral defaults, no forced vendors)
        self.analyst_name = self.options.get("analyst", "").strip()
        self.org_name = self.options.get("organization", "").strip()
        self.report_title = self.options.get("report_title", "").strip() or "CAPEv2 Sandbox Malware Analysis Report"
        self.classification = self.options.get("classification", "").strip()
        if self.classification in ("(None / White Label)", "None"):
            self.classification = ""

        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Define refined typography styles."""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            fontName='Helvetica-Bold',
            fontSize=20,
            leading=24,
            textColor=SLATE_900,
            spaceAfter=2
        ))
        self.styles.add(ParagraphStyle(
            name='ReportSubtitle',
            fontName='Helvetica',
            fontSize=9.5,
            leading=13,
            textColor=SLATE_500,
            spaceAfter=8
        ))
        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=16,
            textColor=SLATE_900,
            spaceBefore=14,
            spaceAfter=6,
            keepWithNext=True
        ))
        self.styles.add(ParagraphStyle(
            name='SubSectionHeading',
            fontName='Helvetica-Bold',
            fontSize=10,
            leading=13,
            textColor=SLATE_800,
            spaceBefore=8,
            spaceAfter=4,
            keepWithNext=True
        ))
        self.styles.add(ParagraphStyle(
            name='TableBody',
            fontName='Helvetica',
            fontSize=8,
            leading=11,
            textColor=SLATE_900
        ))
        self.styles.add(ParagraphStyle(
            name='TableBodyBold',
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=11,
            textColor=SLATE_900
        ))
        self.styles.add(ParagraphStyle(
            name='TableMono',
            fontName='Courier',
            fontSize=7.5,
            leading=10,
            textColor=SLATE_900
        ))
        self.styles.add(ParagraphStyle(
            name='TableMonoSmall',
            fontName='Courier',
            fontSize=7.0,
            leading=9,
            textColor=SLATE_900
        ))
        self.styles.add(ParagraphStyle(
            name='TOCItem',
            fontName='Helvetica',
            fontSize=9,
            leading=14,
            textColor=SLATE_900
        ))

    def _esc(self, text: Any) -> str:
        """Escape XML entities for ReportLab Paragraphs."""
        if text is None:
            return ""
        s = str(text)
        return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    # ─── DYNAMIC SECTION DISCOVERY ────────────────────────────────────────────

    def _determine_active_sections(self) -> List[Dict[str, Any]]:
        """
        Dynamically determine which technical sections have data.
        Returns a list of dicts with keys: 'key', 'title', 'builder'.
        Empty sections are excluded completely from the report and TOC.
        """
        d = self.data
        sections = []

        # 1. Target Hashes (Always included)
        sections.append({
            "key": "sec_target",
            "title": "Target Sample Identification & Cryptographic Checksums",
            "builder": self._build_complete_hashes_block
        })

        # 2. CAPE Configurations & Payloads
        has_configs = bool(d.configs)
        has_payloads = bool(d.payloads)
        if has_configs or has_payloads:
            title = "Decrypted Malware Configurations & Payload Extractions" if has_configs else "Extracted Injected Payloads & Binaries"
            sections.append({
                "key": "sec_cape",
                "title": title,
                "builder": self._build_complete_cape_block
            })

        # 3. MITRE ATT&CK & Behavioral Signatures
        if d.signatures or d.ttps:
            sections.append({
                "key": "sec_mitre",
                "title": "MITRE ATT&CK® Matrix & Dynamic Behavioral Signatures",
                "builder": self._build_complete_mitre_signatures_block
            })

        # 4. Process Execution Hierarchy
        if d.process_list:
            sections.append({
                "key": "sec_processes",
                "title": "Process Execution Hierarchy & Monitored Tasks",
                "builder": self._build_complete_processes_block
            })

        # 5. Network Communications & IOCs
        if d.network_iocs:
            sections.append({
                "key": "sec_network",
                "title": "Network Communications & Defanged IOCs",
                "builder": self._build_complete_network_block
            })

        # 6. Behavioral Modifications (Registry, Files, Mutexes)
        has_behavior = any([
            d.persistence_keys, d.security_bypass_keys, d.files_written, d.files_deleted, d.mutexes
        ])
        if has_behavior:
            sections.append({
                "key": "sec_behavior",
                "title": "File System & Registry Behavioral Modifications",
                "builder": self._build_complete_behavior_block
            })

        # 7. Dropped Files
        if d.dropped:
            sections.append({
                "key": "sec_dropped",
                "title": "Dropped Files & Extracted Artifacts",
                "builder": self._build_complete_dropped_block
            })

        # 8. Sandbox Telemetry (Always included)
        sections.append({
            "key": "sec_telemetry",
            "title": "Sandbox Telemetry & Execution Statistics",
            "builder": self._build_telemetry_block
        })

        # 9. Disclaimer (Always included)
        sections.append({
            "key": "sec_disclaimer",
            "title": "Analytical Methodology & Legal Notice",
            "builder": self._build_disclaimer_block
        })

        return sections

    # ─── STORY COMPILER ───────────────────────────────────────────────────────

    def _compile_story(self, active_sections: List[Dict[str, Any]]) -> List[Any]:
        """Assemble all document Flowables for the report."""
        story = []

        # ═══════════════════════════════════════════════════════════════════════
        # PAGE 1: EXECUTIVE SUMMARY & DYNAMIC CLICKABLE TABLE OF CONTENTS
        # ═══════════════════════════════════════════════════════════════════════
        story.extend(self._build_header_block())
        story.append(Spacer(1, 8))

        story.append(self._build_verdict_banner())
        story.append(Spacer(1, 10))

        story.append(self._build_executive_overview_card())
        story.append(Spacer(1, 10))

        story.append(self._build_dynamic_clickable_toc(active_sections))
        story.append(PageBreak())  # Page 1 dedicated strictly to Executive Overview

        # ═══════════════════════════════════════════════════════════════════════
        # TECHNICAL SECTIONS (Numbered dynamically based only on existing data)
        # ═══════════════════════════════════════════════════════════════════════
        for idx, sec in enumerate(active_sections, 1):
            sec_num_title = f"{idx}. {sec['title']}"
            anchor_key = sec['key']

            # Bookmark for native PDF outline
            story.append(Bookmark(anchor_key, sec_num_title))

            # Heading with anchor tag inside paragraph so <a href="#anchor"> jumps to it
            heading_p = Paragraph(f'<a name="{anchor_key}"/><b>{self._esc(sec_num_title)}</b>', self.styles['SectionHeading'])
            story.append(heading_p)

            # Call section builder
            content = sec['builder']()
            if isinstance(content, list):
                story.extend(content)
            elif content is not None:
                story.append(content)

            story.append(Spacer(1, 14))

        return story

    def build_pdf(self) -> str:
        """
        Two-pass compilation:
        1. Pass 1 renders into an in-memory buffer to determine the exact total page count.
        2. Pass 2 renders to the destination file with SinglePassNumberedCanvas, ensuring
           interactive anchor links jump accurately to the exact page and destination coordinate.
        """
        active_sections = self._determine_active_sections()

        # Pass 1: In-memory calculation
        story1 = self._compile_story(active_sections)
        buf = io.BytesIO()
        doc1 = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )
        doc1.build(story1)
        total_pages = doc1.page

        # Pass 2: Final rendering with precomputed total_pages
        story2 = self._compile_story(active_sections)
        doc2 = SimpleDocTemplate(
            self.output_path,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )

        header_title = self.report_title.upper()
        id_str = f"Task #{self.data.id} | {self.data.filename[:28]}"
        footer_parts = []
        if self.classification:
            footer_parts.append(self.classification)
        if self.org_name:
            footer_parts.append(self.org_name)
        footer_str = " | ".join(footer_parts) if footer_parts else "CAPEv2 Threat Intelligence"

        def canvas_maker(*args, **kwargs):
            return SinglePassNumberedCanvas(
                *args,
                total_pages=total_pages,
                header_title=header_title,
                id_str=id_str,
                footer_str=footer_str,
                **kwargs
            )

        doc2.build(story2, canvasmaker=canvas_maker)
        return self.output_path

    # ─── PAGE 1 BUILDERS ──────────────────────────────────────────────────────

    def _build_header_block(self) -> List[Any]:
        items = []
        date_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

        if self.classification:
            left_p = Paragraph(f"<b>{self._esc(self.classification)}</b>", ParagraphStyle(
                name='HdrClass', fontName='Helvetica-Bold', fontSize=8.5, textColor=SLATE_900
            ))
            right_p = Paragraph(f"Report Generated: <b>{date_str}</b>", ParagraphStyle(
                name='HdrDate', fontName='Helvetica', fontSize=8, textColor=SLATE_500, alignment=2
            ))
            tbl = Table([[left_p, right_p]], colWidths=[250, 254])
            tbl.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            items.append(tbl)
        else:
            right_p = Paragraph(f"Report Generated: <b>{date_str}</b>", ParagraphStyle(
                name='HdrDate', fontName='Helvetica', fontSize=8, textColor=SLATE_500, alignment=2
            ))
            tbl = Table([[right_p]], colWidths=[504])
            tbl.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            items.append(tbl)

        items.append(Paragraph(self._esc(self.report_title), self.styles['ReportTitle']))

        sub_parts = ["Dynamic Sandbox Detonation & Threat Analysis"]
        if self.org_name:
            sub_parts.append(f"Org: <b>{self._esc(self.org_name)}</b>")
        if self.analyst_name:
            sub_parts.append(f"Analyst: <b>{self._esc(self.analyst_name)}</b>")
        sub_parts.append("Developed by Nitiraj Kulkarni")

        items.append(Paragraph(" | ".join(sub_parts), self.styles['ReportSubtitle']))
        items.append(HRFlowable(width="100%", thickness=1.5, color=SLATE_900, spaceAfter=4))
        return items

    def _build_verdict_banner(self) -> Table:
        v = self.data.verdict
        score = self.data.malscore

        if v == "MALICIOUS":
            banner_bg = RED_600
            score_desc = "MALICIOUS ACTIVITY CONFIRMED"
        elif v == "SUSPICIOUS":
            banner_bg = AMBER_600
            score_desc = "SUSPICIOUS BEHAVIOR DETECTED"
        elif v == "LOW RISK":
            banner_bg = colors.HexColor("#CA8A04")
            score_desc = "LOW RISK / HEURISTIC FINDINGS"
        else:
            banner_bg = GREEN_600
            score_desc = "CLEAN / NO MALICIOUS BEHAVIOR DETECTED"

        fam_str = f" | Malware Family: <b>{self._esc(', '.join(self.data.families))}</b>" if self.data.families else ""

        p1 = Paragraph(
            f"<b>{v} (Threat Score: {score:.1f}/10.0)</b>",
            ParagraphStyle(name='V1', fontName='Helvetica-Bold', fontSize=13, textColor=colors.white, alignment=1)
        )
        p2 = Paragraph(
            f"{score_desc}{fam_str}",
            ParagraphStyle(name='V2', fontName='Helvetica', fontSize=8.5, textColor=colors.white, alignment=1)
        )

        tbl = Table([[p1], [p2]], colWidths=[504])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), banner_bg),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        return tbl

    def _build_executive_overview_card(self) -> Table:
        d = self.data
        data = [
            [
                Paragraph("<b>Analysis Task ID:</b>", self.styles['TableBodyBold']),
                Paragraph(f"#{self._esc(d.id)}", self.styles['TableBody']),
                Paragraph("<b>Target Filename:</b>", self.styles['TableBodyBold']),
                Paragraph(self._esc(d.filename), self.styles['TableBody']),
            ],
            [
                Paragraph("<b>Analysis Package:</b>", self.styles['TableBodyBold']),
                Paragraph(self._esc(d.package), self.styles['TableBody']),
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
                Paragraph(f"<code>{d.sha256[:36]}...</code>" if len(d.sha256) > 36 else f"<code>{d.sha256}</code>", self.styles['TableMonoSmall']),
                Paragraph("<b>Lead Analyst:</b>", self.styles['TableBodyBold']),
                Paragraph(self._esc(self.analyst_name) or "Unassigned", self.styles['TableBody']),
            ]
        ]
        tbl = Table(data, colWidths=[105, 147, 105, 147])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), SLATE_50),
            ('BOX', (0, 0), (-1, -1), 1, SLATE_200),
            ('GRID', (0, 0), (-1, -1), 0.5, SLATE_200),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
            ('BACKGROUND', (2, 0), (2, -1), colors.HexColor("#F1F5F9")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        return tbl

    def _build_dynamic_clickable_toc(self, active_sections: List[Dict[str, Any]]) -> Table:
        """
        Renders an interactive, polished Table of Contents containing ONLY
        sections that exist in the analysis data.
        """
        p_title = Paragraph("<b>TABLE OF CONTENTS (INTERACTIVE JUMP INDEX)</b>", ParagraphStyle(
            name='TOCHdr', fontName='Helvetica-Bold', fontSize=9, textColor=SLATE_900
        ))

        rows = [[p_title, ""]]

        for idx, sec in enumerate(active_sections, 1):
            num_str = f"<b>{idx:02d}</b>"
            anchor_key = sec['key']
            sec_name = sec['title']

            left_p = Paragraph(
                f'<a href="#{anchor_key}" color="#0F172A"><u><b>{num_str}</b>  {self._esc(sec_name)}</u></a>',
                self.styles['TOCItem']
            )
            right_p = Paragraph(
                f'<a href="#{anchor_key}" color="#2563EB"><u>Jump to Section &rarr;</u></a>',
                ParagraphStyle(name='TOCJump', fontName='Helvetica', fontSize=8.5, textColor=BLUE_600, alignment=2)
            )
            rows.append([left_p, right_p])

        tbl = Table(rows, colWidths=[400, 104])
        t_style = [
            ('SPAN', (0, 0), (1, 0)),
            ('BACKGROUND', (0, 0), (-1, 0), SLATE_200),
            ('BOX', (0, 0), (-1, -1), 1, SLATE_200),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 3.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]
        # Alternating subtle row colors
        for r_idx in range(1, len(rows)):
            bg = SLATE_50 if (r_idx % 2 == 1) else colors.white
            t_style.append(('BACKGROUND', (0, r_idx), (-1, r_idx), bg))

        tbl.setStyle(TableStyle(t_style))
        return tbl

    # ─── SECTION 1: TARGET SAMPLE IDENTIFICATION & HASHES ─────────────────────

    def _build_complete_hashes_block(self) -> List[Any]:
        items = []
        d = self.data

        # 1. Target Format Metadata Card
        meta_rows = [
            [Paragraph("<b>File Format:</b>", self.styles['TableBodyBold']), Paragraph(self._esc(d.file_type), self.styles['TableBody'])],
            [Paragraph("<b>MIME Type:</b>", self.styles['TableBodyBold']), Paragraph(self._esc(d.mime) or "application/octet-stream", self.styles['TableBody'])],
            [Paragraph("<b>Submitted Path:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{self._esc(d.file_path or d.filename)}</code>", self.styles['TableMonoSmall'])],
        ]
        if d.guest_paths:
            meta_rows.append([Paragraph("<b>Guest Placement:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{self._esc(', '.join(d.guest_paths))}</code>", self.styles['TableMonoSmall'])])

        tbl_meta = Table(meta_rows, colWidths=[105, 399])
        tbl_meta.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
            ('GRID', (0, 0), (-1, -1), 0.5, SLATE_200),
            ('TOPPADDING', (0, 0), (-1, -1), 2.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        items.append(tbl_meta)
        items.append(Spacer(1, 6))

        # 2. Monospace Copyable Hashes Card (Guaranteed never to overflow borders)
        hdr_hashes = Paragraph("<b>CRYPTOGRAPHIC HASHES &amp; CHECKSUMS (COPYABLE)</b>", ParagraphStyle(
            name='HHdr', fontName='Helvetica-Bold', fontSize=8, textColor=SLATE_800
        ))

        hash_entries = [
            ("MD5", d.md5),
            ("SHA-1", d.sha1),
            ("SHA-256", d.sha256),
            ("SHA-512", d.sha512),
            ("SSDEEP", d.ssdeep),
            ("TLSH", d.tlsh),
            ("CRC32", d.crc32),
            ("RH_HASH", d.rh_hash),
            ("SHA3-384", d.sha3_384),
        ]

        hash_table_rows = [[hdr_hashes, ""]]
        for label, val in hash_entries:
            val_clean = val if val else "N/A"
            p_lbl = Paragraph(f"<b>{label}:</b>", ParagraphStyle(name='HLbl', fontName='Helvetica-Bold', fontSize=7.5, textColor=SLATE_700))
            p_val = Paragraph(f"<code>{self._esc(val_clean)}</code>", ParagraphStyle(name='HVal', fontName='Courier', fontSize=7.0, leading=9, textColor=SLATE_900))
            hash_table_rows.append([p_lbl, p_val])

        tbl_hashes = Table(hash_table_rows, colWidths=[80, 424])
        h_style = [
            ('SPAN', (0, 0), (1, 0)),
            ('BACKGROUND', (0, 0), (-1, 0), SLATE_200),
            ('BOX', (0, 0), (-1, -1), 1, SLATE_200),
            ('GRID', (0, 1), (-1, -1), 0.5, SLATE_200),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]
        for r_idx in range(1, len(hash_table_rows)):
            bg = SLATE_50 if (r_idx % 2 == 1) else colors.white
            h_style.append(('BACKGROUND', (0, r_idx), (-1, r_idx), bg))

        tbl_hashes.setStyle(TableStyle(h_style))
        items.append(tbl_hashes)

        # 3. YARA & ClamAV Detections if present
        if d.clamav or d.yara_matches or d.cape_yara:
            items.append(Spacer(1, 6))
            det_rows = []
            if d.clamav:
                det_rows.append([Paragraph("<b>ClamAV Signature:</b>", self.styles['TableBodyBold']), Paragraph(f"<font color='#DC2626'><b>{self._esc(d.clamav)}</b></font>", self.styles['TableBody'])])
            if d.yara_matches:
                yara_names = [y.get("name") if isinstance(y, dict) else str(y) for y in d.yara_matches]
                det_rows.append([Paragraph("<b>YARA Rules Matched:</b>", self.styles['TableBodyBold']), Paragraph(self._esc(", ".join(yara_names)), self.styles['TableBody'])])
            if d.cape_yara:
                cape_yaras = [y.get("name") if isinstance(y, dict) else str(y) for y in d.cape_yara]
                det_rows.append([Paragraph("<b>CAPE YARA Signatures:</b>", self.styles['TableBodyBold']), Paragraph(self._esc(", ".join(cape_yaras)), self.styles['TableBody'])])

            tbl_det = Table(det_rows, colWidths=[130, 374])
            tbl_det.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#FEE2E2")),
                ('GRID', (0, 0), (-1, -1), 0.5, SLATE_200),
                ('TOPPADDING', (0, 0), (-1, -1), 2.5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))
            items.append(tbl_det)

        return items

    # ─── SECTION 2: CAPE CONFIGS & PAYLOADS ───────────────────────────────────

    def _build_complete_cape_block(self) -> List[Any]:
        items = []
        d = self.data

        # 1. Decrypted C2 Configuration Cards
        if d.configs:
            items.append(Paragraph("<b>Decrypted Command &amp; Control (C2) Configurations</b>", self.styles['SubSectionHeading']))
            for cfg in d.configs:
                if not isinstance(cfg, dict):
                    continue
                for fam_name, conf_data in cfg.items():
                    if fam_name.startswith("_"):
                        continue
                    rows = [[Paragraph(f"<b>Malware Family: {self._esc(fam_name)} (Decrypted C2 Credentials)</b>", ParagraphStyle(name='C2H', fontName='Helvetica-Bold', fontSize=8.5, textColor=colors.white)), ""]]
                    if isinstance(conf_data, dict):
                        for k, v in conf_data.items():
                            if isinstance(v, list):
                                v_str = ", ".join(str(item) for item in v)
                            else:
                                v_str = str(v)
                            rows.append([
                                Paragraph(f"<b>{self._esc(k)}:</b>", self.styles['TableBodyBold']),
                                Paragraph(f"<code>{self._esc(v_str)}</code>", self.styles['TableMono'])
                            ])
                    elif isinstance(conf_data, list):
                        rows.append([
                            Paragraph("<b>Extracted Items:</b>", self.styles['TableBodyBold']),
                            Paragraph(self._esc(", ".join(str(x) for x in conf_data)), self.styles['TableBody'])
                        ])

                    tbl = Table(rows, colWidths=[120, 384])
                    tbl.setStyle(TableStyle([
                        ('SPAN', (0, 0), (1, 0)),
                        ('BACKGROUND', (0, 0), (-1, 0), SLATE_800),
                        ('BOX', (0, 0), (-1, -1), 1, SLATE_700),
                        ('GRID', (0, 1), (-1, -1), 0.5, SLATE_200),
                        ('BACKGROUND', (0, 1), (0, -1), SLATE_50),
                        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
                        ('LEFTPADDING', (0, 0), (-1, -1), 6),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ]))
                    items.append(tbl)
                    items.append(Spacer(1, 6))

        # 2. Extracted Payloads & Memory Dumps (All payloads, untruncated)
        if d.payloads:
            items.append(Paragraph(f"<b>Extracted Payload Binaries &amp; Injected Shellcodes ({len(d.payloads)} Extracted)</b>", self.styles['SubSectionHeading']))
            rows = [
                [
                    Paragraph("<b>#</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Process / Target</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Type</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Size</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>SHA-256 Checksum</b>", self.styles['TableBodyBold']),
                ]
            ]
            for p_idx, pl in enumerate(d.payloads, 1):
                p_name = pl.get("name") or pl.get("process_name") or "Injected Buffer"
                p_type = pl.get("type") or pl.get("cape_type") or "PE32/Shellcode"
                p_size = format_bytes(pl.get("size", 0))
                p_sha = pl.get("sha256", "N/A")

                rows.append([
                    Paragraph(str(p_idx), self.styles['TableBody']),
                    Paragraph(self._esc(p_name), self.styles['TableBody']),
                    Paragraph(self._esc(p_type), self.styles['TableBody']),
                    Paragraph(p_size, self.styles['TableBody']),
                    Paragraph(f"<code>{p_sha}</code>", self.styles['TableMonoSmall']),
                ])

            tbl = Table(rows, colWidths=[20, 110, 80, 54, 240])
            p_style = [
                ('BACKGROUND', (0, 0), (-1, 0), SLATE_800),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, SLATE_200),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 2.5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ]
            for r in range(1, len(rows)):
                if r % 2 == 0:
                    p_style.append(('BACKGROUND', (0, r), (-1, r), SLATE_50))
            tbl.setStyle(TableStyle(p_style))
            items.append(tbl)

        return items

    # ─── SECTION 3: MITRE ATT&CK & SIGNATURES ─────────────────────────────────

    def _build_complete_mitre_signatures_block(self) -> List[Any]:
        items = []
        d = self.data

        rows = [
            [
                Paragraph("<b>Severity</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Signature Name</b>", self.styles['TableBodyBold']),
                Paragraph("<b>MITRE Technique</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Behavioral Description</b>", self.styles['TableBodyBold']),
            ]
        ]

        for sig in d.signatures:
            name = sig.get("name", "Unknown")
            desc = sig.get("description", "")
            sev = sig.get("severity", 1)
            ttp = sig.get("ttp", "") or sig.get("mitre", "")

            if sev >= 3:
                sev_p = Paragraph(f"<font color='#DC2626'><b>HIGH ({sev})</b></font>", self.styles['TableBodyBold'])
            elif sev == 2:
                sev_p = Paragraph(f"<font color='#D97706'><b>MED ({sev})</b></font>", self.styles['TableBodyBold'])
            else:
                sev_p = Paragraph(f"<font color='#64748B'>LOW ({sev})</font>", self.styles['TableBody'])

            rows.append([
                sev_p,
                Paragraph(self._esc(name), self.styles['TableBodyBold']),
                Paragraph(f"<code>{self._esc(ttp)}</code>" if ttp else "Dynamic", self.styles['TableMonoSmall']),
                Paragraph(self._esc(desc), self.styles['TableBody']),
            ])

        tbl = Table(rows, colWidths=[55, 125, 75, 249])
        s_style = [
            ('BACKGROUND', (0, 0), (-1, 0), SLATE_800),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, SLATE_200),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 2.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]
        for r in range(1, len(rows)):
            if r % 2 == 0:
                s_style.append(('BACKGROUND', (0, r), (-1, r), SLATE_50))
        tbl.setStyle(TableStyle(s_style))
        items.append(tbl)
        return items

    # ─── SECTION 4: PROCESS EXECUTION HIERARCHY ───────────────────────────────

    def _build_complete_processes_block(self) -> List[Any]:
        items = []
        d = self.data

        rows = [
            [
                Paragraph("<b>PID</b>", self.styles['TableBodyBold']),
                Paragraph("<b>PPID</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Process Image / Path</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Command Line Arguments</b>", self.styles['TableBodyBold']),
            ]
        ]

        for p in d.process_list:
            pid = str(p.get("pid") or "N/A")
            ppid = str(p.get("ppid") or "N/A")
            name = p.get("name") or "unknown.exe"
            path = p.get("path") or ""
            cmd = p.get("cmd") or ""

            img_text = f"<b>{self._esc(name)}</b><br/><font color='#64748B'>{self._esc(path)}</font>" if path else f"<b>{self._esc(name)}</b>"

            rows.append([
                Paragraph(pid, self.styles['TableBody']),
                Paragraph(ppid, self.styles['TableBody']),
                Paragraph(img_text, self.styles['TableBody']),
                Paragraph(f"<code>{self._esc(cmd)}</code>" if cmd else "<font color='#94A3B8'>None specified</font>", self.styles['TableMonoSmall']),
            ])

        tbl = Table(rows, colWidths=[40, 40, 144, 280])
        p_style = [
            ('BACKGROUND', (0, 0), (-1, 0), SLATE_800),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, SLATE_200),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 2.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]
        for r in range(1, len(rows)):
            if r % 2 == 0:
                p_style.append(('BACKGROUND', (0, r), (-1, r), SLATE_50))
        tbl.setStyle(TableStyle(p_style))
        items.append(tbl)
        return items

    # ─── SECTION 5: NETWORK COMMUNICATIONS & DEFANGED IOCS ────────────────────

    def _build_complete_network_block(self) -> List[Any]:
        items = []
        d = self.data

        rows = [
            [
                Paragraph("<b>Type</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Defanged Indicator of Compromise (IOC)</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Port / Details</b>", self.styles['TableBodyBold']),
            ]
        ]

        for ioc in d.network_iocs:
            itype = ioc.get("type", "UNKNOWN")
            ival = defang(ioc.get("value", ""))
            iport = str(ioc.get("port") or "")
            idetails = ioc.get("details") or ""
            port_detail = f"{iport} ({idetails})" if (iport and idetails) else (iport or idetails or "N/A")

            rows.append([
                Paragraph(f"<b>{itype}</b>", self.styles['TableBody']),
                Paragraph(f"<code>{self._esc(ival)}</code>", self.styles['TableMono']),
                Paragraph(self._esc(port_detail), self.styles['TableBody']),
            ])

        tbl = Table(rows, colWidths=[64, 330, 110])
        n_style = [
            ('BACKGROUND', (0, 0), (-1, 0), SLATE_800),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, SLATE_200),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 2.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]
        for r in range(1, len(rows)):
            if r % 2 == 0:
                n_style.append(('BACKGROUND', (0, r), (-1, r), SLATE_50))
        tbl.setStyle(TableStyle(n_style))
        items.append(tbl)
        return items

    # ─── SECTION 6: BEHAVIORAL MODIFICATIONS ──────────────────────────────────

    def _build_complete_behavior_block(self) -> List[Any]:
        items = []
        d = self.data

        # Persistence Registry Keys
        if d.persistence_keys:
            items.append(Paragraph("<b>Observed Persistence Registry Keys (Run, RunOnce, Startup)</b>", self.styles['SubSectionHeading']))
            rows = [[Paragraph(f"<code>{self._esc(k)}</code>", self.styles['TableMonoSmall'])] for k in d.persistence_keys]
            tbl = Table(rows, colWidths=[504])
            tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#FEF2F2")),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#FCA5A5")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#FECACA")),
                ('TOPPADDING', (0, 0), (-1, -1), 2),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ]))
            items.append(tbl)
            items.append(Spacer(1, 6))

        # Security Tampering Keys
        if d.security_bypass_keys:
            items.append(Paragraph("<b>Security Defense Tampering &amp; Policy Modifications</b>", self.styles['SubSectionHeading']))
            rows = [[Paragraph(f"<code>{self._esc(k)}</code>", self.styles['TableMonoSmall'])] for k in d.security_bypass_keys]
            tbl = Table(rows, colWidths=[504])
            tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#FFFBEB")),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#FDE68A")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#FEF3C7")),
                ('TOPPADDING', (0, 0), (-1, -1), 2),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ]))
            items.append(tbl)
            items.append(Spacer(1, 6))

        # Files Written / Modified
        if d.files_written:
            items.append(Paragraph(f"<b>Files Written or Modified by Sandbox Processes ({len(d.files_written)} Total)</b>", self.styles['SubSectionHeading']))
            rows = [[Paragraph(f"<code>{self._esc(f)}</code>", self.styles['TableMonoSmall'])] for f in d.files_written[:40]]
            if len(d.files_written) > 40:
                rows.append([Paragraph(f"<i>... and {len(d.files_written) - 40} additional files written</i>", self.styles['TableBody'])])
            tbl = Table(rows, colWidths=[504])
            tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), SLATE_50),
                ('BOX', (0, 0), (-1, -1), 1, SLATE_200),
                ('GRID', (0, 0), (-1, -1), 0.5, SLATE_200),
                ('TOPPADDING', (0, 0), (-1, -1), 2),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ]))
            items.append(tbl)
            items.append(Spacer(1, 6))

        # Mutexes
        if d.mutexes:
            items.append(Paragraph("<b>Created Synchronization Mutexes</b>", self.styles['SubSectionHeading']))
            rows = [[Paragraph(f"<code>{self._esc(m)}</code>", self.styles['TableMonoSmall'])] for m in d.mutexes[:30]]
            tbl = Table(rows, colWidths=[504])
            tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                ('BOX', (0, 0), (-1, -1), 1, SLATE_200),
                ('GRID', (0, 0), (-1, -1), 0.5, SLATE_200),
                ('TOPPADDING', (0, 0), (-1, -1), 2),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ]))
            items.append(tbl)

        return items

    # ─── SECTION 7: DROPPED FILES ─────────────────────────────────────────────

    def _build_complete_dropped_block(self) -> List[Any]:
        items = []
        d = self.data

        rows = [
            [
                Paragraph("<b>File Name / Relative Path</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Size</b>", self.styles['TableBodyBold']),
                Paragraph("<b>File Type / Characteristics</b>", self.styles['TableBodyBold']),
            ]
        ]

        for df in d.dropped:
            name = df.get("name") or os.path.basename(df.get("path", "dropped_file"))
            size = format_bytes(df.get("size", 0))
            ftype = df.get("type") or "Unknown"

            rows.append([
                Paragraph(self._esc(name), self.styles['TableBodyBold']),
                Paragraph(size, self.styles['TableBody']),
                Paragraph(self._esc(ftype), self.styles['TableBody']),
            ])

        tbl = Table(rows, colWidths=[150, 60, 294])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), SLATE_800),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, SLATE_200),
            ('TOPPADDING', (0, 0), (-1, -1), 2.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        items.append(tbl)
        return items

    # ─── SECTION 8: SANDBOX TELEMETRY ─────────────────────────────────────────

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

        tbl = Table(rows, colWidths=[140, 364])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
            ('GRID', (0, 0), (-1, -1), 0.5, SLATE_200),
            ('TOPPADDING', (0, 0), (-1, -1), 2.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        items.append(tbl)
        return items

    # ─── SECTION 9: DISCLAIMER ────────────────────────────────────────────────

    def _build_disclaimer_block(self) -> Table:
        text = """
<b>ANALYTICAL NOTICE:</b> This dynamic malware analysis report was compiled from empirical execution telemetry 
captured within an isolated virtual machine sandbox. Dynamic analysis reflects the observable behaviors of the submitted 
artifact under specific environmental and temporal constraints. Evasive techniques, dormant timers, or target-dependent 
triggers may alter behavior outside this sandbox environment. All indicators and credentials extracted should be handled 
according to your organization's security procedures.<br/><br/>
<b>capev2-report-generator</b> &bull; Developed by Nitiraj Kulkarni &bull; Open-Source Commercial Threat Intelligence Suite.
"""
        p_disc = Paragraph(text, ParagraphStyle(name='Disc', fontName='Helvetica', fontSize=7.5, leading=10, textColor=SLATE_500))
        box = Table([[p_disc]], colWidths=[504])
        box.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), SLATE_50),
            ('BOX', (0, 0), (-1, -1), 1, SLATE_200),
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
