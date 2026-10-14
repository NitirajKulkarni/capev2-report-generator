"""
CAPEv2 Malware Analysis Report Generator
Convert CAPEv2 Sandbox JSON outputs into publication-grade executive PDF reports.
"""

__version__ = "1.0.0"
__author__ = "Nitiraj V. Kulkarni"

from .parser import CapeReportData, parse_cape_report
from .pdf_engine import CapePdfReport, generate_pdf_report

__all__ = ["CapeReportData", "parse_cape_report", "CapePdfReport", "generate_pdf_report"]
