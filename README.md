# capev2-report-generator

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![CAPEv2](https://img.shields.io/badge/CAPEv2-Sandbox%20Compatible-red.svg)](https://github.com/kevoreilly/CAPEv2)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-success.svg)]()
[![Single-File Portable EXE](https://img.shields.io/badge/Release-Portable%20EXE-blueviolet.svg)](releases/capev2-report-generator.exe)

> **Enterprise-grade, publication-ready PDF reporting suite for CAPEv2 Sandbox analysis.**  
> Automatically parses raw 30MB–100MB+ CAPEv2 JSON reports and transforms them into beautifully indexed, executive-level threat intelligence PDF reports with malware C2 extraction, process execution trees, copyable cryptographic checksums, and defanged IOC tables.  
> **Developed by Nitiraj Kulkarni**

---

## 🌟 Key Features

| Feature | Description |
|---|---|
| **🎨 Sleek Desktop GUI** | Modern dark-mode interface built with CustomTkinter. Drag-and-drop JSON reports, live threat inspector, and 1-click PDF viewing. |
| **⚡ Standalone Native EXE** | Ready-to-run zero-dependency executable (`releases/capev2-report-generator.exe`). Built with native GUI subsystem (no black terminal window popup!). |
| **💾 Persistent User Memory** | Remembers Analyst Name, Organization, Report Title, and Classification across sessions in `%APPDATA%\cape_report_generator\settings.json`. |
| **📑 Dynamic Clickable TOC** | Interactive Page 1 Table of Contents that automatically excludes absent sections, with 100% accurate link jumping directly to technical sections. |
| **🔒 Monospace Hashes Block** | Copyable cryptographic checksum block (MD5, SHA-1, SHA-256, SHA-512, SSDEEP, TLSH) formatted cleanly within table borders. |
| **🔍 In-Depth CAPE Extractions** | Decrypts and surfaces extracted malware configurations (AgentTesla, RedLine, Remcos, FormBook, etc.) including C2 servers, FTP credentials, and persistence files. |
| **💯 Exhaustive Uncut Details** | Includes every extracted payload (no truncation), every monitored process, complete dynamic signatures, defanged network IOCs, dropped files, and behavioral registry keys. |
| **🏷️ White-Label & Customizable** | Fully commercial: no forced vendor watermarks. Classification markings (TLP:AMBER, CONFIDENTIAL, etc.) are completely optional. |
| **🚀 Batch Conversion** | Convert entire directories of analysis JSON reports in parallel with progress tracking. |
| **💻 Universal CLI & GUI** | Seamlessly works as both an interactive desktop application and a headless automation CLI tool. |

---

## 📸 Executive PDF Report Structure

Each generated report is styled using an executive cybersecurity design system (Midnight Slate, Crimson Threat Warnings, and Emerald Status Badges):

1. **Page 1: Executive Overview & Interactive Index**:
   - Threat Verdict Banner (`MALICIOUS`, `SUSPICIOUS`, `CLEAN`) with numeric risk score gauge.
   - Sample Analysis Metadata Card (Sample Name, Size, File Type, Package, Analysis ID, Detonation Duration).
   - **Interactive Clickable Table of Contents**: Clicking any section jumps straight to that technical section in the PDF.
2. **Section 1: Target Sample Identification & Cryptographic Hashes**:
   - Complete cryptographic hashes (MD5, SHA-1, SHA-256, SHA-512, SSDEEP, TLSH, CRC32, RH-Hash, SHA3-384) + YARA matches.
3. **Section 2: CAPE Advanced Payload & Configuration Extraction**:
   - Decrypted C2 configuration cards (e.g. AgentTesla FTP credentials, ports, persistence) + Complete Payload Dumps table.
4. **Section 3: MITRE ATT&CK® Matrix & Dynamic Behavioral Signatures**:
   - Observed tactics, techniques, and severity-scored dynamic behavioral detections.
5. **Section 4: Process Execution Hierarchy & Monitored Processes**:
   - Complete execution hierarchy tree detailing PIDs, PPIDs, image paths, and command-line arguments.
6. **Section 5: Network Communications & Defanged IOCs**:
   - Defanged DNS domains, HTTP/HTTPS URLs, and TCP/UDP connections for safe SOC/SIEM threat hunting.
7. **Section 6: File System & Registry Behavioral Modifications**:
   - Persistence keys (Run, RunOnce), security evasion keys, files written, and deleted artifacts.
8. **Section 7: Dropped Files & Extracted Artifacts**:
   - Names, paths, sizes, and types of all dropped files.
9. **Section 8: Sandbox Telemetry & Execution Statistics**:
   - Machine environment, OS architecture, network routing, and module execution times.
10. **Section 9: Analytical Methodology & Disclaimer**:
   - Formal analytical notice for enterprise forensic documentation.

---

## 🚀 Quick Start

### Option 1: Standalone Portable Executable (Zero Setup)

Download and run the pre-compiled single-file executable directly from the repository:

```bash
# Path to portable executable:
releases/CAPE-Report-Generator.exe
```

- **Double-click** the executable to launch the **Desktop GUI**.
- Or run it via **Terminal / Command Prompt** for automated batch jobs:
  ```powershell
  .\releases\CAPE-Report-Generator.exe 11_report.json -o Analysis_Report.pdf
  ```

---

### Option 2: Run via Python

#### 1. Clone & Install Dependencies
```bash
git clone https://github.com/NitirajKulkarni/capev2-report-generator.git
cd capev2-report-generator

pip install -r requirements.txt
# Or install in editable mode:
pip install -e .
```

#### 2. Launch the Desktop GUI
```bash
python -m cape_report_generator
# Or run the installed command:
cape-report
```

#### 3. Run Headless via CLI
```bash
# Convert a single report:
cape-report 11_report.json -o 11_report.pdf --analyst "Lead Analyst" --org "Cyber Defense Center"

# Convert all reports in a folder (Batch Mode):
cape-report --batch /path/to/cape_reports/ -o /path/to/output_pdfs/
```

---

## 🛠️ CLI Options Reference

```text
usage: cape-report [-h] [-o OUTPUT] [--batch] [--analyst ANALYST] [--org ORG]
                   [--title TITLE] [--classification CLASSIFICATION]
                   [--gui] [json_path]

Convert CAPEv2 Sandbox JSON analysis reports into publication-grade executive PDF reports.

positional arguments:
  json_path             Path to CAPEv2 report.json file (e.g. 11_report.json)

options:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   Custom output PDF path or output directory
  --batch               Treat json_path as a directory and convert all *.json reports
  --analyst ANALYST     Name of the malware analyst (defaults to saved memory preference or blank)
  --org ORG             Organization or SOC lab name (defaults to saved memory preference or blank)
  --title TITLE         Report Title (defaults to saved memory preference)
  --classification CLASSIFICATION
                        Confidentiality marking or TLP protocol (optional, e.g. TLP:AMBER, CONFIDENTIAL). Leave blank for white-label reports
  --gui                 Explicitly launch the desktop Graphical User Interface
```

---

## 📂 Repository Structure

```text
cape-report-generator/
├── .gitignore                      # Git ignore rules
├── LICENSE                         # MIT License
├── README.md                       # Comprehensive documentation
├── pyproject.toml                  # Modern Python package specification
├── setup.py                        # Pip packaging & console entry points
├── build_exe.py                    # Standalone PyInstaller build script
├── src/
│   └── cape_report_generator/
│       ├── __init__.py             # Package init & version metadata
│       ├── __main__.py             # Entry point for python -m
│       ├── config.py               # Persistent user settings manager (%APPDATA%)
│       ├── parser.py               # Memory-efficient CAPEv2 JSON parser (exhaustive extraction)
│       ├── pdf_engine.py           # Publication-grade PDF engine with clickable TOC & bookmarks
│       ├── gui.py                  # CustomTkinter dark-mode desktop GUI
│       └── cli.py                  # Headless command-line interface
├── tests/
│   └── test_parser_and_pdf.py      # Automated unit test suite
└── releases/
    ├── capev2-report-generator.exe # Standalone native single-file binary (Zero-console GUI)
    └── CAPE-Report-Generator.exe   # Compatible binary alias
```

---

## 🧪 Running Unit Tests

Run the full automated test suite:

```bash
python -m unittest discover tests
```

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
