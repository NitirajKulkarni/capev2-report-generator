"""
Unit tests for CAPEv2 Report Generator
Tests parser accuracy, threat evaluation, and PDF rendering.
"""

import os
import sys
import unittest
import tempfile

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from cape_report_generator.parser import parse_cape_report, defang, format_bytes, CapeReportData
from cape_report_generator.pdf_engine import generate_pdf_report


class TestCapeParserAndPdf(unittest.TestCase):
    """Test suite for CAPEv2 Report Generator."""

    @classmethod
    def setUpClass(cls):
        # Locate sample reports
        cls.workspace_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        cls.sample_11 = os.path.join(cls.workspace_dir, "11_report.json")
        cls.sample_14 = os.path.join(cls.workspace_dir, "14_report.json")
        cls.sample_15 = os.path.join(cls.workspace_dir, "15_report.json")

    def test_defang_utility(self):
        """Test URL and IP defanging."""
        self.assertEqual(defang("http://malware.com/payload.exe"), "hxxp://malware[.]com/payload[.]exe")
        self.assertEqual(defang("https://192.168.1.1:8080/c2"), "hxxps://192[.]168[.]1[.]1:8080/c2")
        self.assertEqual(defang("ftp://ftp.example.com"), "fxp://ftp[.]example[.]com")

    def test_format_bytes(self):
        """Test human readable byte formatting."""
        self.assertEqual(format_bytes(500), "500 B")
        self.assertEqual(format_bytes(1024), "1.0 KB")
        self.assertEqual(format_bytes(1048576), "1.0 MB")
        self.assertEqual(format_bytes(1073741824), "1.0 GB")

    def test_parse_report_11_agent_tesla(self):
        """Test parsing 11_report.json and extracting AgentTesla configs."""
        if not os.path.isfile(self.sample_11):
            self.skipTest("Sample 11_report.json not found")

        report = parse_cape_report(self.sample_11)
        self.assertEqual(report.id, 11)
        self.assertEqual(report.package, "ps1")
        self.assertEqual(report.verdict, "MALICIOUS")
        self.assertEqual(report.malscore, 10.0)
        self.assertIn("AgentTesla", report.families)
        self.assertGreater(len(report.payloads), 0)
        self.assertGreater(len(report.configs), 0)
        self.assertGreater(len(report.network_iocs), 0)

        # Check extracted C2
        cfg = report.configs[0]
        self.assertIn("AgentTesla", cfg)
        c2_list = cfg["AgentTesla"].get("C2", [])
        self.assertTrue(any("hhautoinvestment" in c for c in c2_list))

    def test_parse_report_14_js(self):
        """Test parsing 14_report.json (JavaScript sample)."""
        if not os.path.isfile(self.sample_14):
            self.skipTest("Sample 14_report.json not found")

        report = parse_cape_report(self.sample_14)
        self.assertEqual(report.id, 14)
        self.assertEqual(report.package, "js")
        self.assertGreaterEqual(report.malscore, 4.0)
        self.assertGreater(len(report.payloads), 0)
        self.assertGreater(len(report.process_list), 0)

    def test_parse_report_15_vbs(self):
        """Test parsing 15_report.json (VBScript sample)."""
        if not os.path.isfile(self.sample_15):
            self.skipTest("Sample 15_report.json not found")

        report = parse_cape_report(self.sample_15)
        self.assertEqual(report.id, 15)
        self.assertEqual(report.package, "vbs")
        self.assertGreaterEqual(report.malscore, 4.0)
        self.assertGreater(len(report.payloads), 0)

    def test_pdf_generation_single(self):
        """Test end-to-end PDF generation on sample 11."""
        if not os.path.isfile(self.sample_11):
            self.skipTest("Sample 11_report.json not found")

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_pdf = tmp.name

        try:
            out = generate_pdf_report(
                self.sample_11,
                tmp_pdf,
                options={
                    "analyst": "Automated Tester",
                    "organization": "Security Testing Lab",
                    "tlp": "TLP:AMBER"
                }
            )
            self.assertTrue(os.path.isfile(out))
            self.assertGreater(os.path.getsize(out), 5000)
        finally:
            if os.path.isfile(tmp_pdf):
                try:
                    os.remove(tmp_pdf)
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()
