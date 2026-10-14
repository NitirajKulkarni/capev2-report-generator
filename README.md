# CAPEv2 Sandbox Report Generator & Executive PDF Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![CAPEv2](https://img.shields.io/badge/CAPEv2-Sandbox%20Compatible-red.svg)](https://github.com/kevoreilly/CAPEv2)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-success.svg)]()
[![Single-File Portable EXE](https://img.shields.io/badge/Release-Portable%20EXE-blueviolet.svg)](releases/CAPE-Report-Generator.exe)

> **Enterprise-grade, publication-ready PDF reporting suite for CAPEv2 Sandbox analysis.**  
> Automatically parses raw 30MB–100MB+ CAPEv2 JSON reports and transforms them into beautifully indexed, executive-level threat intelligence PDF reports with malware C2 extraction, MITRE ATT&CK® matrix, process trees, and defanged IOC tables.

---

## 🌟 Key Features

| Feature | Description |
|---|---|
| **🎨 Sleek Desktop GUI** | Modern dark-mode interface built with CustomTkinter. Drag-and-drop JSON reports, live threat inspector, and 1-click PDF viewing. |
| **⚡ Standalone Portable EXE** | Ready-to-run zero-dependency executable (`releases/CAPE-Report-Generator.exe`). No Python installation required! |
| **🔍 In-Depth CAPE Extractions** | Decrypts and surfaces extracted malware configurations (AgentTesla, RedLine, Remcos, FormBook, etc.) including C2 servers, FTP credentials, and persistence files. |
| **📑 Two-Pass Numbered Index** | Professional Table of Contents and running `Page X of Y` headers and footers with customizable confidentiality tags (TLP:AMBER, TLP:RED). |
| **🎯 MITRE ATT&CK® Mapping** | Maps observed dynamic behaviors to MITRE ATT&CK techniques, tactics, and high-severity signatures. |
| **🌲 Process Hierarchy Tree** | Clean parent-child execution tree detailing PIDs, PPIDs, module paths, and command-line arguments. |
| **🛡️ Defanged Network IOCs** | Automatically defangs URLs (`hxxp://`), FTP (`fxp://`), and domains (`[.]`) ready for direct SIEM, EDR, and firewall ingestion. |
| **🚀 Batch Conversion** | Convert entire directories of analysis JSON reports in parallel with progress tracking. |
| **💻 Universal CLI & GUI** | Seamlessly works as both an interactive desktop application and a headless automation CLI tool. |

---

## 📸 Executive PDF Report Preview

Each generated report is styled using an executive cybersecurity design system (Midnight Slate, Crimson Threat Warnings, and Emerald Status Badges):

1. **Cover & Threat Verdict Banner**: Malscore gauge, malware family tag, and verdict classification (`MALICIOUS`, `SUSPICIOUS`, `CLEAN`).
2. **Table of Contents (Index)**: Interactive structured section navigation.
3. **Executive Summary & Metadata**: Analysis ID, duration, sandbox VM environment, and analyst credentials.
4. **Target File Identification & Hashes**: Monospace cryptographic table (MD5, SHA-1, SHA-256, SSDEEP, TLSH) plus YARA and Antivirus matches.
5. **CAPE Payload & Configuration Extraction**: Dedicated credential card showing decrypted C2 servers, usernames, passwords, and unpacked shellcodes.
6. **MITRE ATT&CK & Signatures**: Tactics and techniques observed during sandbox execution.
7. **Process Execution Hierarchy**: Parent-child execution relationships with command lines.
8. **Network Communications & Defanged IOCs**: Safe Indicators of Compromise for threat hunting.
9. **Behavioral Summary & Dropped Files**: Files written, modified registry keys, mutexes, and dropped artifacts.

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
cape-report 11_report.json -o 11_report.pdf --analyst "Nitiraj V. Kulkarni" --org "Quick Heal Security Labs"

# Convert all reports in a folder (Batch Mode):
cape-report --batch /path/to/cape_reports/ -o /path/to/output_pdfs/
```

---

## 🛠️ CLI Options Reference

```text
usage: cape-report [-h] [-o OUTPUT] [--batch] [--analyst ANALYST] [--org ORG]
                   [--tlp {TLP:CLEAR,TLP:WHITE,TLP:GREEN,TLP:AMBER,TLP:AMBER+STRICT,TLP:RED}]
                   [--gui] [json_path]

Convert CAPEv2 Sandbox JSON analysis reports into publication-grade executive PDF reports.

positional arguments:
  json_path             Path to CAPEv2 report.json file (e.g. 11_report.json)

options:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   Custom output PDF path or output directory
  --batch               Treat json_path as a directory and convert all *.json reports
  --analyst ANALYST     Name of the lead malware analyst (Default: Nitiraj V. Kulkarni)
  --org ORG             Organization or SOC lab name (Default: Quick Heal Security Labs)
  --tlp {TLP:CLEAR,...} Traffic Light Protocol confidentiality marking (Default: TLP:AMBER)
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
│       ├── parser.py               # Memory-efficient CAPEv2 JSON parser
│       ├── pdf_engine.py           # ReportLab publication-grade PDF generator
│       ├── gui.py                  # CustomTkinter dark-mode desktop GUI
│       └── cli.py                  # Headless command-line interface
├── tests/
│   └── test_parser_and_pdf.py      # Automated unit test suite (6/6 passing)
└── releases/
    └── CAPE-Report-Generator.exe   # Standalone portable single-file binary (23 MB)
```

---

## 🧪 Running Unit Tests

Run the full automated test suite:

```bash
python -m unittest discover tests
```

---

## 👤 Author & Research Attribution

**Nitiraj V. Kulkarni**  
*AI Safety & Cybersecurity Researcher*  
Quick Heal Security Labs / CAPEv2 Sandbox Automation  

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
