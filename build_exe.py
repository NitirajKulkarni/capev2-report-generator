"""
Build script to compile CAPEv2 Report Generator into a standalone portable executable.
Outputs the compiled binary to releases/CAPE-Report-Generator.exe.
"""

import os
import sys
import shutil
import subprocess

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
ENTRY_POINT = os.path.join(SRC_DIR, "cape_report_generator", "__main__.py")
RELEASES_DIR = os.path.join(PROJECT_ROOT, "releases")
DIST_DIR = os.path.join(PROJECT_ROOT, "dist")
BUILD_DIR = os.path.join(PROJECT_ROOT, "build")

def build_portable_exe():
    print("=" * 70)
    print("  Building capev2-report-generator Portable Executable (No-Console Native GUI)")
    print("=" * 70)
    os.makedirs(RELEASES_DIR, exist_ok=True)

    # PyInstaller arguments: --noconsole ensures no black terminal appears on double-click
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=capev2-report-generator",
        "--onefile",
        "--noconsole",
        "--clean",
        f"--paths={SRC_DIR}",
        "--hidden-import=reportlab",
        "--hidden-import=reportlab.lib",
        "--hidden-import=reportlab.lib.colors",
        "--hidden-import=reportlab.platypus",
        "--hidden-import=reportlab.pdfgen",
        "--hidden-import=customtkinter",
        "--hidden-import=darkdetect",
        "--hidden-import=PIL",
        "--hidden-import=tkinter",
        "--collect-all=customtkinter",
        "--collect-all=reportlab",
        ENTRY_POINT
    ]

    print(f"Executing: {' '.join(cmd)}")
    res = subprocess.run(cmd, cwd=PROJECT_ROOT)
    if res.returncode != 0:
        print(f"[-] PyInstaller build failed with exit code: {res.returncode}")
        return False

    # Move from dist/ to releases/
    primary_name = "capev2-report-generator.exe" if sys.platform.startswith("win") else "capev2-report-generator"
    built_path = os.path.join(DIST_DIR, primary_name)
    release_path = os.path.join(RELEASES_DIR, primary_name)

    if os.path.isfile(built_path):
        shutil.copy2(built_path, release_path)
        print(f"\n[+] SUCCESS! Portable executable generated (Zero-Console Window):")
        print(f"    Release Path: {release_path}")
        print(f"    File Size:    {os.path.getsize(release_path):,} bytes ({os.path.getsize(release_path)/(1024*1024):.1f} MB)")
        return True
    else:
        print(f"[-] Compiled binary not found at: {built_path}")
        return False

if __name__ == "__main__":
    success = build_portable_exe()
    sys.exit(0 if success else 1)
