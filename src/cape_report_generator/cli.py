"""
CAPEv2 Report Generator CLI & Entry Point
Provides headless command-line interface for automation and launches GUI when invoked interactively.
"""

import sys
import os
import argparse
import glob
from typing import List, Optional

try:
    from .parser import parse_cape_report
    from .pdf_engine import generate_pdf_report
except ImportError:
    from parser import parse_cape_report
    from pdf_engine import generate_pdf_report


def run_cli(args: Optional[List[str]] = None) -> int:
    """CLI handler for CAPEv2 Report Generator."""
    parser = argparse.ArgumentParser(
        prog="cape-report",
        description="Convert CAPEv2 Sandbox JSON analysis reports into publication-grade executive PDF reports.",
        epilog="If run without arguments, launches the modern desktop GUI application."
    )

    parser.add_argument(
        "json_path",
        nargs="?",
        default=None,
        help="Path to CAPEv2 report.json file (e.g. 11_report.json)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Custom output PDF path or output directory."
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Treat json_path as a directory and convert all *.json reports inside."
    )
    parser.add_argument(
        "--analyst",
        default="Nitiraj V. Kulkarni",
        help="Name of the lead malware analyst."
    )
    parser.add_argument(
        "--org",
        default="Quick Heal Security Labs",
        help="Organization or security operations center name."
    )
    parser.add_argument(
        "--tlp",
        default="TLP:AMBER",
        choices=["TLP:CLEAR", "TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"],
        help="Traffic Light Protocol (TLP) confidentiality marking."
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Explicitly launch the desktop Graphical User Interface."
    )

    parsed = parser.parse_args(args)

    # If no arguments provided or --gui flag passed, launch the GUI
    if parsed.gui or (not parsed.json_path and len(sys.argv) <= 1):
        try:
            try:
                from .gui import launch_gui
            except ImportError:
                from gui import launch_gui
            launch_gui()
            return 0
        except Exception as e:
            print(f"[!] Could not launch GUI: {e}")
            print("[*] Falling back to CLI usage:")
            parser.print_help()
            return 1

    if not parsed.json_path:
        parser.print_help()
        return 1

    options = {
        "analyst": parsed.analyst,
        "organization": parsed.org,
        "tlp": parsed.tlp,
    }

    # Batch mode
    if parsed.batch or os.path.isdir(parsed.json_path):
        target_dir = parsed.json_path
        json_files = glob.glob(os.path.join(target_dir, "*.json"))
        if not json_files:
            print(f"[-] No JSON report files found in directory: {target_dir}")
            return 1

        print(f"[*] Found {len(json_files)} reports to convert in {target_dir}...")
        out_dir = parsed.output if (parsed.output and os.path.isdir(parsed.output)) else target_dir
        os.makedirs(out_dir, exist_ok=True)

        success = 0
        for jf in json_files:
            bname = os.path.splitext(os.path.basename(jf))[0]
            out_pdf = os.path.join(out_dir, f"{bname}_Analysis_Report.pdf")
            try:
                print(f"  -> Processing {os.path.basename(jf)}...")
                generate_pdf_report(jf, out_pdf, options=options)
                print(f"     [+] Created {os.path.basename(out_pdf)}")
                success += 1
            except Exception as e:
                print(f"     [-] Failed {os.path.basename(jf)}: {e}")

        print(f"\n[+] Batch complete: {success}/{len(json_files)} reports generated.")
        return 0 if success > 0 else 1

    # Single file mode
    if not os.path.isfile(parsed.json_path):
        print(f"[-] Error: Report file does not exist: {parsed.json_path}")
        return 1

    out_pdf = parsed.output
    if out_pdf and os.path.isdir(out_pdf):
        bname = os.path.splitext(os.path.basename(parsed.json_path))[0]
        out_pdf = os.path.join(out_pdf, f"{bname}_Analysis_Report.pdf")

    print(f"[*] Parsing CAPEv2 report: {parsed.json_path}...")
    try:
        report_data = parse_cape_report(parsed.json_path)
        print(f"[+] Sample: {report_data.filename} ({report_data.file_size_fmt})")
        print(f"[+] Threat Verdict: {report_data.verdict} (Score: {report_data.malscore}/10.0)")
        if report_data.families:
            print(f"[+] Detected Malware Family: {', '.join(report_data.families)}")

        print(f"[*] Rendering executive PDF document...")
        final_pdf = generate_pdf_report(parsed.json_path, out_pdf, options=options)
        print(f"[+] SUCCESS! Report generated: {final_pdf}")
        print(f"[+] File Size: {os.path.getsize(final_pdf):,} bytes")
        return 0
    except Exception as e:
        print(f"[-] ERROR generating PDF report: {e}")
        import traceback
        traceback.print_exc()
        return 1
