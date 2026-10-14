"""
CAPEv2 Professional PDF Report Engine
Generates high-impact, publication-grade executive malware analysis PDF reports
with interactive index, executive summary, threat verdicts, payload extractions,
process trees, MITRE ATT&CK mappings, and IOC tables.
"""

import os
import json
import datetime
from typing import Optional, List, Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

try:
    from .parser import CapeReportData, defang, format_bytes
except ImportError:
    from parser import CapeReportData, defang, format_bytes


# ─── Color Palette (Modern Executive Cybersecurity Theme) ──────────────────────
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
BG_CARD = colors.HexColor("#FFFFFF")
BORDER_LIGHT = colors.HexColor("#E2E8F0")       # Slate 200
TEXT_MAIN = colors.HexColor("#0F172A")
TEXT_MUTED = colors.HexColor("#64748B")         # Slate 500


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
            self.drawString(54, 755, "CAPEv2 SANDBOX MALWARE ANALYSIS REPORT")
            self.drawRightString(612 - 54, 755, getattr(self, "report_id_str", "CONFIDENTIAL"))
            self.setStrokeColor(BORDER_LIGHT)
            self.setLineWidth(0.5)
            self.line(54, 747, 612 - 54, 747)

        # Footer (all pages)
        self.setStrokeColor(BORDER_LIGHT)
        self.setLineWidth(0.5)
        self.line(54, 42, 612 - 54, 42)

        self.setFont("Helvetica", 8)
        self.setFillColor(TEXT_MUTED)
        self.drawString(54, 30, getattr(self, "footer_tlp_str", "TLP:AMBER | STRICTLY CONFIDENTIAL"))
        self.drawRightString(612 - 54, 30, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


class CapePdfReport:
    """PDF Report Generator for CAPEv2 Sandbox Reports."""

    def __init__(self, data: CapeReportData, output_path: str, options: Optional[Dict[str, Any]] = None):
        self.data = data
        self.output_path = output_path
        self.options = options or {}

        self.analyst_name = self.options.get("analyst", "Automated Sandbox Engine")
        self.org_name = self.options.get("organization", "Cyber Threat Intelligence & SOC Lab")
        self.tlp_banner = self.options.get("tlp", f"TLP:{data.tlp}").upper()

        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Define fine-tuned typography styles for report elements."""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=NAVY_PRIMARY,
            spaceAfter=4
        ))
        self.styles.add(ParagraphStyle(
            name='ReportSubtitle',
            fontName='Helvetica',
            fontSize=11,
            leading=14,
            textColor=TEXT_MUTED,
            spaceAfter=12
        ))
        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=NAVY_PRIMARY,
            spaceBefore=14,
            spaceAfter=6,
            keepWithNext=True
        ))
        self.styles.add(ParagraphStyle(
            name='SubSectionHeading',
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=14,
            textColor=ACCENT_BLUE,
            spaceBefore=10,
            spaceAfter=4,
            keepWithNext=True
        ))
        self.styles.add(ParagraphStyle(
            name='TableBody',
            fontName='Helvetica',
            fontSize=8.5,
            leading=11,
            textColor=TEXT_MAIN
        ))
        self.styles.add(ParagraphStyle(
            name='TableBodyBold',
            fontName='Helvetica-Bold',
            fontSize=8.5,
            leading=11,
            textColor=TEXT_MAIN
        ))
        self.styles.add(ParagraphStyle(
            name='TableMono',
            fontName='Courier',
            fontSize=8,
            leading=10,
            textColor=NAVY_SECONDARY
        ))
        self.styles.add(ParagraphStyle(
            name='TableMonoRed',
            fontName='Courier-Bold',
            fontSize=8,
            leading=10,
            textColor=RED_CRITICAL
        ))
        self.styles.add(ParagraphStyle(
            name='VerdictBadge',
            fontName='Helvetica-Bold',
            fontSize=16,
            leading=18,
            textColor=colors.white,
            alignment=1  # Centered
        ))
        self.styles.add(ParagraphStyle(
            name='IndexItem',
            fontName='Helvetica',
            fontSize=9.5,
            leading=14,
            textColor=NAVY_SECONDARY
        ))

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

        # ─── 1. Header Banner & Title Block ───────────────────────────────────
        story.extend(self._build_header_block())
        story.append(Spacer(1, 12))

        # ─── 2. Verdict & Threat Rating Banner ────────────────────────────────
        story.append(self._build_verdict_banner())
        story.append(Spacer(1, 14))

        # ─── 3. Report Section Index (Table of Contents) ──────────────────────
        story.append(self._build_index_block())
        story.append(Spacer(1, 14))

        # ─── 4. Section 1: Executive Summary & Overview ───────────────────────
        story.append(self._build_section_heading("1. Executive Summary & Analysis Metadata"))
        story.append(self._build_executive_summary_table())
        story.append(Spacer(1, 14))

        # ─── 5. Section 2: Target File Identification & Hashes ────────────────
        story.append(self._build_section_heading("2. Target File Identification & Cryptographic Hashes"))
        story.append(self._build_hashes_table())
        story.append(Spacer(1, 14))

        # ─── 6. Section 3: CAPE Advanced Payload & Configuration Extraction ───
        if self.data.configs or self.data.payloads:
            story.append(self._build_section_heading("3. CAPE Advanced Payload & Configuration Extraction"))
            story.extend(self._build_cape_extractions_block())
            story.append(Spacer(1, 14))

        # ─── 7. Section 4: MITRE ATT&CK Matrix & Signatures ───────────────────
        if self.data.signatures or self.data.ttps:
            story.append(self._build_section_heading("4. MITRE ATT&CK Matrix & Behavioral Signatures"))
            story.extend(self._build_mitre_signatures_block())
            story.append(Spacer(1, 14))

        # ─── 8. Section 5: Process Execution Hierarchy ────────────────────────
        if self.data.process_list or self.data.processtree:
            story.append(self._build_section_heading("5. Process Execution Hierarchy"))
            story.append(self._build_process_tree_block())
            story.append(Spacer(1, 14))

        # ─── 9. Section 6: Network Communication & Indicators (IOCs) ──────────
        story.append(self._build_section_heading("6. Network Communication & Indicators of Compromise (IOCs)"))
        story.extend(self._build_network_block())
        story.append(Spacer(1, 14))

        # ─── 10. Section 7: Behavioral & System Modifications ─────────────────
        story.append(self._build_section_heading("7. Behavioral & System Modifications"))
        story.append(self._build_behavior_summary_block())
        story.append(Spacer(1, 14))

        # ─── 11. Section 8: Dropped Files & Extracted Artifacts ───────────────
        if self.data.dropped:
            story.append(self._build_section_heading("8. Dropped Files & Extracted Artifacts"))
            story.append(self._build_dropped_files_table())
            story.append(Spacer(1, 14))

        # ─── 12. Section 9: Sign-off & Disclaimer ─────────────────────────────
        story.append(self._build_signoff_block())

        # Build document with custom canvas for page numbers
        def canvas_maker(*args, **kwargs):
            c = NumberedCanvas(*args, **kwargs)
            c.report_id_str = f"CAPE ID #{self.data.id} | {self.data.filename[:30]}"
            c.footer_tlp_str = f"{self.tlp_banner} | {self.org_name}"
            return c

        doc.build(story, canvasmaker=canvas_maker)
        return self.output_path

    # ─── Block Builders ───────────────────────────────────────────────────────

    def _build_header_block(self) -> List[Any]:
        """Construct top classification tag, title, and organization metadata."""
        items = []

        # TLP pill banner
        tlp_color = colors.HexColor("#92400E") if "AMBER" in self.tlp_banner else (
            RED_CRITICAL if "RED" in self.tlp_banner else GREEN_CLEAN
        )
        tlp_bg = colors.HexColor("#FEF3C7") if "AMBER" in self.tlp_banner else (
            RED_BG if "RED" in self.tlp_banner else GREEN_BG
        )

        tlp_p = Paragraph(f"<b>{self.tlp_banner}</b>", ParagraphStyle(
            name='TlpText', fontName='Helvetica-Bold', fontSize=8, textColor=tlp_color, alignment=1
        ))
        date_p = Paragraph(f"Report Generated: <b>{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</b>", ParagraphStyle(
            name='DateText', fontName='Helvetica', fontSize=8, textColor=TEXT_MUTED, alignment=2
        ))

        header_tbl = Table([[tlp_p, date_p]], colWidths=[130, 374])
        header_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), tlp_bg),
            ('BOX', (0, 0), (0, 0), 1, tlp_color),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (0, 0), 3),
            ('BOTTOMPADDING', (0, 0), (0, 0), 3),
        ]))
        items.append(header_tbl)
        items.append(Spacer(1, 8))

        # Title
        items.append(Paragraph("CAPEv2 Malware Analysis Report", self.styles['ReportTitle']))
        items.append(Paragraph(
            f"Automated Dynamic Sandbox Detonation & Intelligence Report | Organization: <b>{self.org_name}</b>",
            self.styles['ReportSubtitle']
        ))
        items.append(HRFlowable(width="100%", thickness=1.5, color=NAVY_PRIMARY, spaceAfter=8))
        return items

    def _build_verdict_banner(self) -> Table:
        """Create prominent, high-impact threat verdict banner with score and family."""
        v = self.data.verdict
        score = self.data.malscore

        if v == "MALICIOUS":
            banner_bg = RED_CRITICAL
            score_desc = "CRITICAL THREAT DETECTED"
        elif v == "SUSPICIOUS":
            banner_bg = AMBER_WARNING
            score_desc = "SUSPICIOUS BEHAVIOR DETECTED"
        elif v == "LOW RISK":
            banner_bg = colors.HexColor("#EAB308")
            score_desc = "LOW RISK / HEURISTIC FINDINGS"
        else:
            banner_bg = GREEN_CLEAN
            score_desc = "NO THREATS DETECTED"

        fam_str = f" | Family: <b>{', '.join(self.data.families)}</b>" if self.data.families else ""
        verdict_html = f"<b>{v}</b> (Threat Score: <b>{score:.1f}/10.0</b>)<br/><font size=9>{score_desc}{fam_str}</font>"

        p = Paragraph(verdict_html, self.styles['VerdictBadge'])
        tbl = Table([[p]], colWidths=[504])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), banner_bg),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        return tbl

    def _build_index_block(self) -> Table:
        """Table of Contents / Report Index."""
        p_title = Paragraph("<b>REPORT INDEX / TABLE OF CONTENTS</b>", ParagraphStyle(
            name='IndexTitle', fontName='Helvetica-Bold', fontSize=9, textColor=NAVY_PRIMARY
        ))

        idx_col1 = Paragraph("""
<b>1.</b> Executive Summary &amp; Metadata<br/>
<b>2.</b> Target Sample &amp; Cryptographic Hashes<br/>
<b>3.</b> CAPE Payloads &amp; Extracted Configs<br/>
<b>4.</b> MITRE ATT&amp;CK Matrix &amp; Signatures<br/>
<b>5.</b> Process Execution Hierarchy
""", self.styles['IndexItem'])

        idx_col2 = Paragraph("""
<b>6.</b> Network Communications &amp; IOCs<br/>
<b>7.</b> Behavioral &amp; System Modifications<br/>
<b>8.</b> Dropped Files &amp; Extracted Artifacts<br/>
<b>9.</b> Sign-off, Disclaimer &amp; Analyst Notes
""", self.styles['IndexItem'])

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
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]))
        return tbl

    def _build_section_heading(self, title: str) -> Paragraph:
        safe_title = title.replace('&', '&amp;') if '&amp;' not in title else title
        return Paragraph(f"<b>{safe_title}</b>", self.styles['SectionHeading'])

    def _build_executive_summary_table(self) -> Table:
        """Section 1: Summary Table."""
        d = self.data
        data = [
            [
                Paragraph("<b>Analysis Task ID:</b>", self.styles['TableBodyBold']),
                Paragraph(f"#{d.id}", self.styles['TableBody']),
                Paragraph("<b>Target Filename:</b>", self.styles['TableBodyBold']),
                Paragraph(f"<b>{d.filename}</b>", self.styles['TableBody']),
            ],
            [
                Paragraph("<b>Analysis Package:</b>", self.styles['TableBodyBold']),
                Paragraph(f"<code>{d.package}</code>", self.styles['TableBody']),
                Paragraph("<b>File Size:</b>", self.styles['TableBodyBold']),
                Paragraph(f"{d.file_size_fmt} ({d.file_size:,} bytes)", self.styles['TableBody']),
            ],
            [
                Paragraph("<b>Execution Time:</b>", self.styles['TableBodyBold']),
                Paragraph(f"{d.duration} seconds", self.styles['TableBody']),
                Paragraph("<b>Sandbox Environment:</b>", self.styles['TableBodyBold']),
                Paragraph(f"{d.machine_name} ({d.machine_os})", self.styles['TableBody']),
            ],
            [
                Paragraph("<b>Started At:</b>", self.styles['TableBodyBold']),
                Paragraph(str(d.started), self.styles['TableBody']),
                Paragraph("<b>Completed At:</b>", self.styles['TableBodyBold']),
                Paragraph(str(d.ended), self.styles['TableBody']),
            ],
            [
                Paragraph("<b>Lead Analyst:</b>", self.styles['TableBodyBold']),
                Paragraph(self.analyst_name, self.styles['TableBody']),
                Paragraph("<b>Classification:</b>", self.styles['TableBodyBold']),
                Paragraph(self.tlp_banner, self.styles['TableBody']),
            ],
        ]

        tbl = Table(data, colWidths=[110, 142, 110, 142])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), BG_LIGHT),
            ('BACKGROUND', (2, 0), (2, -1), BG_LIGHT),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        return tbl

    def _build_hashes_table(self) -> Table:
        """Section 2: Hashes Table."""
        d = self.data
        data = [
            [Paragraph("<b>File Format:</b>", self.styles['TableBodyBold']), Paragraph(d.file_type, self.styles['TableBody'])],
            [Paragraph("<b>MD5:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{d.md5}</code>", self.styles['TableMono'])],
            [Paragraph("<b>SHA-1:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{d.sha1}</code>", self.styles['TableMono'])],
            [Paragraph("<b>SHA-256:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{d.sha256}</code>", self.styles['TableMono'])],
            [Paragraph("<b>SSDEEP:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{d.ssdeep}</code>", self.styles['TableMono'])],
            [Paragraph("<b>TLSH:</b>", self.styles['TableBodyBold']), Paragraph(f"<code>{d.tlsh}</code>", self.styles['TableMono'])],
        ]

        if d.clamav:
            data.append([Paragraph("<b>ClamAV Verdict:</b>", self.styles['TableBodyBold']), Paragraph(f"<b>{d.clamav}</b>", self.styles['TableBody'])])

        if d.yara_matches:
            yara_names = ", ".join([y.get("name", "") for y in d.yara_matches if isinstance(y, dict)])
            data.append([Paragraph("<b>YARA Matches:</b>", self.styles['TableBodyBold']), Paragraph(yara_names or "None", self.styles['TableBody'])])

        tbl = Table(data, colWidths=[110, 394])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), BG_LIGHT),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        return tbl

    def _build_cape_extractions_block(self) -> List[Any]:
        """Section 3: CAPE Extracted Configurations and Injected Payloads."""
        items = []

        # A) Malware Configs
        if self.data.configs:
            items.append(Paragraph("<b>Extracted Malware Configurations & Command-and-Control (C2)</b>", self.styles['SubSectionHeading']))
            for cfg in self.data.configs:
                if not isinstance(cfg, dict):
                    continue
                for family, details in cfg.items():
                    if family.startswith("_"):
                        continue
                    rows = [
                        [Paragraph("<b>Malware Family:</b>", self.styles['TableBodyBold']), Paragraph(f"<b>{family}</b>", self.styles['TableBody'])],
                    ]
                    if isinstance(details, dict):
                        for k, v in details.items():
                            val_str = ", ".join(map(str, v)) if isinstance(v, list) else str(v)
                            # Defang if looks like URL/IP
                            if any(proto in val_str for proto in ['http', 'ftp', '://']):
                                val_str = defang(val_str)
                            rows.append([
                                Paragraph(f"<b>{k}:</b>", self.styles['TableBodyBold']),
                                Paragraph(f"<code>{val_str}</code>", self.styles['TableMonoRed'] if 'password' in k.lower() or 'c2' in k.lower() else self.styles['TableMono'])
                            ])

                    cfg_tbl = Table(rows, colWidths=[150, 354])
                    cfg_tbl.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), RED_BG),
                        ('BACKGROUND', (0, 1), (0, -1), BG_LIGHT),
                        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('TOPPADDING', (0, 0), (-1, -1), 4),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                        ('LEFTPADDING', (0, 0), (-1, -1), 6),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ]))
                    items.append(cfg_tbl)
                    items.append(Spacer(1, 8))

        # B) Extracted Payloads / Injected Shellcodes
        if self.data.payloads:
            items.append(Paragraph(f"<b>Extracted / Injected Payloads ({len(self.data.payloads)} Total)</b>", self.styles['SubSectionHeading']))
            p_rows = [
                [
                    Paragraph("<b>Type / Classification</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Size</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>SHA-256 Hash</b>", self.styles['TableBodyBold']),
                ]
            ]
            for p in self.data.payloads[:8]:  # Show top 8 payloads
                ctype = p.get("cape_type") or "Payload"
                psize = format_bytes(p.get("size", 0))
                psha = p.get("sha256", "N/A")
                p_rows.append([
                    Paragraph(ctype, self.styles['TableBody']),
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

        return items

    def _build_mitre_signatures_block(self) -> List[Any]:
        """Section 4: MITRE ATT&CK Matrix & Signatures."""
        items = []

        if self.data.ttps:
            items.append(Paragraph("<b>MITRE ATT&CK® Techniques Observed</b>", self.styles['SubSectionHeading']))
            ttp_rows = [
                [
                    Paragraph("<b>Technique ID</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Tactic</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Technique Name / Signature</b>", self.styles['TableBodyBold']),
                ]
            ]
            for t in self.data.ttps[:12]:
                ttp_id = t.get("ttp") or "N/A"
                sig = t.get("signature") or "Detected behavioral pattern"
                tactic = "Execution" if "1059" in ttp_id else ("Command & Control" if "1071" in ttp_id else "Defense Evasion")
                ttp_rows.append([
                    Paragraph(f"<code>{ttp_id}</code>", self.styles['TableMonoRed']),
                    Paragraph(tactic, self.styles['TableBody']),
                    Paragraph(sig, self.styles['TableBody']),
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

        if self.data.signatures:
            items.append(Paragraph(f"<b>Triggered Behavioral Signatures ({len(self.data.signatures)} Total)</b>", self.styles['SubSectionHeading']))
            sig_rows = [
                [
                    Paragraph("<b>Severity</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Signature Name</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Description</b>", self.styles['TableBodyBold']),
                ]
            ]
            for s in self.data.signatures[:10]:
                sev = s.get("severity", 1)
                sev_label = "HIGH" if sev >= 3 else ("MEDIUM" if sev == 2 else "LOW")
                sev_color = RED_CRITICAL if sev >= 3 else (AMBER_WARNING if sev == 2 else NAVY_LIGHT)
                sig_rows.append([
                    Paragraph(f"<b><font color='{sev_color.hexval()}'>{sev_label} ({sev})</font></b>", self.styles['TableBody']),
                    Paragraph(f"<b>{s.get('name', 'N/A')}</b>", self.styles['TableBodyBold']),
                    Paragraph(s.get("description", ""), self.styles['TableBody']),
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

    def _build_process_tree_block(self) -> Table:
        """Section 5: Process Tree."""
        rows = [
            [
                Paragraph("<b>PID / PPID</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Process Name</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Command Line & Image Path</b>", self.styles['TableBodyBold']),
            ]
        ]

        for p in self.data.process_list[:12]:
            pid = p.get("pid", "?")
            ppid = p.get("ppid", "?")
            name = p.get("name", "Unknown")
            cmd = p.get("command_line") or p.get("path") or "No command line arguments captured"
            # Truncate very long command lines
            if len(cmd) > 160:
                cmd = cmd[:160] + "..."

            rows.append([
                Paragraph(f"<code>{pid} &larr; {ppid}</code>", self.styles['TableMono']),
                Paragraph(f"<b>{name}</b>", self.styles['TableBodyBold']),
                Paragraph(f"<code>{cmd}</code>", self.styles['TableMono']),
            ])

        tbl = Table(rows, colWidths=[90, 114, 300])
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
        return tbl

    def _build_network_block(self) -> List[Any]:
        """Section 6: Network activity and IOC table."""
        items = []

        if self.data.network_iocs:
            items.append(Paragraph("<b>Defanged Network Indicators of Compromise (IOCs)</b>", self.styles['SubSectionHeading']))
            ioc_rows = [
                [
                    Paragraph("<b>Indicator Type</b>", self.styles['TableBodyBold']),
                    Paragraph("<b>Defanged Value (Ready for SIEM / Firewalls)</b>", self.styles['TableBodyBold']),
                ]
            ]
            for ioc in self.data.network_iocs:
                ioc_rows.append([
                    Paragraph(f"<b>{ioc['type']}</b>", self.styles['TableBody']),
                    Paragraph(f"<code>{ioc['defanged']}</code>", self.styles['TableMonoRed']),
                ])

            ioc_tbl = Table(ioc_rows, colWidths=[160, 344])
            ioc_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), RED_CRITICAL),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            items.append(ioc_tbl)
            items.append(Spacer(1, 8))
        else:
            items.append(Paragraph("<i>No outbound network activity was captured during detonation (Guest network isolation active).</i>", self.styles['TableBody']))
            items.append(Spacer(1, 4))

        return items

    def _build_behavior_summary_block(self) -> Table:
        """Section 7: Behavioral activity counts and key modifications."""
        d = self.data
        data = [
            [
                Paragraph("<b>Files Written:</b>", self.styles['TableBodyBold']),
                Paragraph(str(len(d.files_written)), self.styles['TableBody']),
                Paragraph("<b>Registry Keys Modified:</b>", self.styles['TableBodyBold']),
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

        tbl = Table(data, colWidths=[130, 122, 130, 122])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), BG_LIGHT),
            ('BACKGROUND', (2, 0), (2, -1), BG_LIGHT),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        return tbl

    def _build_dropped_files_table(self) -> Table:
        """Section 8: Dropped files."""
        rows = [
            [
                Paragraph("<b>File Name</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Size</b>", self.styles['TableBodyBold']),
                Paragraph("<b>Type Description</b>", self.styles['TableBodyBold']),
            ]
        ]
        for f in self.data.dropped[:10]:
            name = f.get("name")
            if isinstance(name, list):
                name = name[0] if name else "Unknown"
            size = format_bytes(f.get("size", 0))
            ftype = f.get("type", "Unknown")
            if len(ftype) > 80:
                ftype = ftype[:80] + "..."

            rows.append([
                Paragraph(f"<b>{name}</b>", self.styles['TableBody']),
                Paragraph(size, self.styles['TableBody']),
                Paragraph(ftype, self.styles['TableBody']),
            ])

        tbl = Table(rows, colWidths=[150, 60, 294])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_SECONDARY),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        return tbl

    def _build_signoff_block(self) -> KeepTogether:
        """Section 9: Disclaimer and Sign-off."""
        text = """
<b>DISCLAIMER & LEGAL NOTICE:</b> This dynamic malware analysis report was generated automatically by 
the CAPEv2 Automated Sandbox Analysis Framework. Findings reflect dynamic behavioral execution observed 
within an isolated virtual sandbox guest environment. Certain advanced malware samples may exhibit evasion 
or sleep mechanisms. This document contains sensitive threat intelligence and Indicators of Compromise (IOCs).
"""
        p_disc = Paragraph(text, ParagraphStyle(name='Disc', fontName='Helvetica', fontSize=7.5, leading=10, textColor=TEXT_MUTED))
        box = Table([[p_disc]], colWidths=[504])
        box.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        return KeepTogether([box])


def generate_pdf_report(
    json_path: str,
    output_pdf_path: Optional[str] = None,
    options: Optional[Dict[str, Any]] = None
) -> str:
    """Convenience function to parse a JSON report and render a PDF report."""
    if not output_pdf_path:
        base, _ = os.path.splitext(json_path)
        output_pdf_path = f"{base}_Analysis_Report.pdf"

    with open(json_path, 'r', encoding='utf-8', errors='ignore') as f:
        raw_data = json.load(f)
    data = CapeReportData(raw_data, filepath=json_path)
    engine = CapePdfReport(data, output_pdf_path, options=options)
    return engine.build_pdf()
