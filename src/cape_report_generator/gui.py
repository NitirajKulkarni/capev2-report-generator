"""
Modern Desktop Graphical User Interface (GUI) for CAPEv2 Report Generator
Built using CustomTkinter with sleek dark-mode aesthetics, live sample inspector,
batch conversion tab, and one-click PDF viewer integration.
"""

import os
import sys
import threading
import subprocess
from typing import Optional

try:
    import customtkinter as ctk
    from tkinter import filedialog, messagebox
    HAS_CTK = True
except ImportError:
    import tkinter as ctk
    from tkinter import ttk, filedialog, messagebox
    HAS_CTK = False

try:
    from .parser import parse_cape_report, CapeReportData
    from .pdf_engine import generate_pdf_report
    from .config import load_settings, save_settings
except ImportError:
    from parser import parse_cape_report, CapeReportData
    from pdf_engine import generate_pdf_report
    from config import load_settings, save_settings


class CapeReportGui:
    """Modern Desktop GUI for generating CAPEv2 PDF analysis reports."""

    def __init__(self):
        if HAS_CTK:
            ctk.set_appearance_mode("Dark")
            ctk.set_default_color_theme("blue")
            self.root = ctk.CTk()
        else:
            self.root = ctk.Tk()

        self.root.title("capev2-report-generator — Enterprise Threat Intelligence Suite")
        self.root.geometry("980x780")
        self.root.minsize(860, 680)

        self.settings = load_settings()
        self.current_report_data: Optional[CapeReportData] = None
        self.current_json_path: str = ""
        self.last_generated_pdf: str = ""

        self._build_ui()

    def _build_ui(self):
        """Construct the UI layout."""
        # Top Header Banner
        header_frame = ctk.CTkFrame(self.root, corner_radius=0, fg_color=("#1E293B", "#0F172A"))
        header_frame.pack(fill="x", padx=0, pady=0)

        header_content = ctk.CTkFrame(header_frame, fg_color="transparent")
        header_content.pack(fill="x", padx=24, pady=16)

        title_lbl = ctk.CTkLabel(
            header_content,
            text="capev2-report-generator",
            font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"),
            text_color="#F8FAFC"
        )
        title_lbl.pack(anchor="w")

        subtitle_lbl = ctk.CTkLabel(
            header_content,
            text="Executive Sandbox Threat Intelligence & Forensics Suite • Developed by Nitiraj Kulkarni",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#94A3B8"
        )
        subtitle_lbl.pack(anchor="w", pady=(2, 0))

        # Main Tabview
        self.tabview = ctk.CTkTabview(self.root, fg_color=("#F1F5F9", "#1E293B"))
        self.tabview.pack(fill="both", expand=True, padx=20, pady=16)

        self.tab_single = self.tabview.add("  Single Report Conversion  ")
        self.tab_batch = self.tabview.add("  Batch Directory Conversion  ")
        self.tab_about = self.tabview.add("  About & Capabilities  ")

        self._build_single_tab()
        self._build_batch_tab()
        self._build_about_tab()

        # Bottom Status Bar
        self.status_bar = ctk.CTkFrame(self.root, height=36, corner_radius=0, fg_color=("#E2E8F0", "#0F172A"))
        self.status_bar.pack(fill="x", side="bottom")

        self.status_lbl = ctk.CTkLabel(
            self.status_bar,
            text="Ready. Select a CAPEv2 report.json file to begin.",
            font=ctk.CTkFont(size=11),
            text_color="#64748B"
        )
        self.status_lbl.pack(side="left", padx=16, pady=6)

    # ─── TAB 1: Single Report Conversion ─────────────────────────────────────

    def _build_single_tab(self):
        tab = self.tab_single

        # 1. File Selection Section
        sel_frame = ctk.CTkFrame(tab, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8, border_width=1, border_color="#334155")
        sel_frame.pack(fill="x", padx=12, pady=(10, 8))

        sel_top = ctk.CTkFrame(sel_frame, fg_color="transparent")
        sel_top.pack(fill="x", padx=14, pady=(12, 8))

        ctk.CTkLabel(
            sel_top,
            text="CAPEv2 JSON Report File:",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(side="left")

        browse_btn = ctk.CTkButton(
            sel_top,
            text="Browse JSON...",
            width=130,
            command=self._on_browse_json,
            fg_color="#2563EB",
            hover_color="#1D4ED8"
        )
        browse_btn.pack(side="right")

        self.json_path_var = ctk.StringVar()
        self.json_path_entry = ctk.CTkEntry(
            sel_frame,
            textvariable=self.json_path_var,
            placeholder_text="Select a CAPEv2 report JSON file (e.g., 11_report.json)...",
            height=34
        )
        self.json_path_entry.pack(fill="x", padx=14, pady=(0, 12))

        # 2. Quick Inspector Card (Threat Overview)
        self.inspector_card = ctk.CTkFrame(tab, fg_color=("#F8FAFC", "#0F172A"), corner_radius=8, border_width=1, border_color="#334155")
        self.inspector_card.pack(fill="x", padx=12, pady=6)

        self.insp_content = ctk.CTkFrame(self.inspector_card, fg_color="transparent")
        self.insp_content.pack(fill="x", padx=16, pady=12)

        self.insp_title = ctk.CTkLabel(
            self.insp_content,
            text="Sample Threat Overview (Load a report to inspect)",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#94A3B8"
        )
        self.insp_title.pack(anchor="w")

        self.insp_grid = ctk.CTkFrame(self.insp_content, fg_color="transparent")
        self.insp_grid.pack(fill="x", pady=(8, 0))

        # 3. Report Customization Settings (Saved in memory)
        opts_frame = ctk.CTkFrame(tab, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8, border_width=1, border_color="#334155")
        opts_frame.pack(fill="x", padx=12, pady=6)

        opts_inner = ctk.CTkFrame(opts_frame, fg_color="transparent")
        opts_inner.pack(fill="x", padx=14, pady=12)

        opts_header = ctk.CTkFrame(opts_inner, fg_color="transparent")
        opts_header.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(opts_header, text="Report Customization & Metadata", font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")

        save_btn = ctk.CTkButton(
            opts_header,
            text="💾 Remember Preferences",
            width=160,
            height=26,
            font=ctk.CTkFont(size=11),
            fg_color="#334155",
            hover_color="#475569",
            command=self._on_save_preferences
        )
        save_btn.pack(side="right")

        row1 = ctk.CTkFrame(opts_inner, fg_color="transparent")
        row1.pack(fill="x", pady=4)

        ctk.CTkLabel(row1, text="Analyst Name:", width=110, anchor="w").pack(side="left")
        self.analyst_var = ctk.StringVar(value=self.settings.get("analyst_name", ""))
        self.analyst_entry = ctk.CTkEntry(row1, textvariable=self.analyst_var, placeholder_text="e.g. Lead Malware Analyst", width=280)
        self.analyst_entry.pack(side="left", padx=(0, 20))

        ctk.CTkLabel(row1, text="Organization:", width=90, anchor="w").pack(side="left")
        self.org_var = ctk.StringVar(value=self.settings.get("organization", ""))
        self.org_entry = ctk.CTkEntry(row1, textvariable=self.org_var, placeholder_text="e.g. Cyber Security Incident Response", width=280)
        self.org_entry.pack(side="left")

        row2 = ctk.CTkFrame(opts_inner, fg_color="transparent")
        row2.pack(fill="x", pady=6)

        ctk.CTkLabel(row2, text="Report Title:", width=110, anchor="w").pack(side="left")
        self.report_title_var = ctk.StringVar(value=self.settings.get("report_title", "CAPEv2 Sandbox Malware Analysis Report"))
        self.report_title_entry = ctk.CTkEntry(row2, textvariable=self.report_title_var, width=280)
        self.report_title_entry.pack(side="left", padx=(0, 20))

        ctk.CTkLabel(row2, text="Classification:", width=90, anchor="w").pack(side="left")
        saved_cls = self.settings.get("classification", "")
        self.tlp_var = ctk.StringVar(value=saved_cls if saved_cls else "(None / White Label)")
        classification_options = [
            "(None / White Label)",
            "TLP:CLEAR",
            "TLP:GREEN",
            "TLP:AMBER",
            "TLP:AMBER+STRICT",
            "TLP:RED",
            "CONFIDENTIAL",
            "RESTRICTED",
            "INTERNAL ONLY"
        ]
        if self.tlp_var.get() not in classification_options:
            classification_options.append(self.tlp_var.get())
        self.tlp_dropdown = ctk.CTkOptionMenu(
            row2,
            variable=self.tlp_var,
            values=classification_options,
            width=200
        )
        self.tlp_dropdown.pack(side="left")

        row3 = ctk.CTkFrame(opts_inner, fg_color="transparent")
        row3.pack(fill="x", pady=(4, 0))

        ctk.CTkLabel(row3, text="Output Folder:", width=110, anchor="w").pack(side="left")
        self.out_dir_var = ctk.StringVar(value=self.settings.get("output_dir", ""))
        self.out_dir_entry = ctk.CTkEntry(row3, textvariable=self.out_dir_var, placeholder_text="Default (Same folder as JSON report)", width=480)
        self.out_dir_entry.pack(side="left", padx=(0, 8), fill="x", expand=True)
        ctk.CTkButton(row3, text="Browse...", width=80, command=self._on_browse_out_dir).pack(side="left")

        # 4. Action Section
        action_frame = ctk.CTkFrame(tab, fg_color="transparent")
        action_frame.pack(fill="x", padx=12, pady=(12, 6))

        self.gen_btn = ctk.CTkButton(
            action_frame,
            text="⚡ Generate Executive PDF Report",
            font=ctk.CTkFont(size=15, weight="bold"),
            height=44,
            command=self._on_generate_single,
            fg_color="#059669",
            hover_color="#047857"
        )
        self.gen_btn.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.open_pdf_btn = ctk.CTkButton(
            action_frame,
            text="📄 Open PDF",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=44,
            width=140,
            command=self._on_open_pdf,
            state="disabled",
            fg_color="#2563EB",
            hover_color="#1D4ED8"
        )
        self.open_pdf_btn.pack(side="left", padx=4)

        self.open_folder_btn = ctk.CTkButton(
            action_frame,
            text="📁 Open Folder",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=44,
            width=140,
            command=self._on_open_folder,
            state="disabled",
            fg_color="#475569",
            hover_color="#334155"
        )
        self.open_folder_btn.pack(side="left")

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(tab)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", padx=12, pady=(8, 4))
        self.progress_bar.pack_forget()

    # ─── TAB 2: Batch Directory Conversion ───────────────────────────────────

    def _build_batch_tab(self):
        tab = self.tab_batch

        intro_box = ctk.CTkFrame(tab, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8, border_width=1, border_color="#334155")
        intro_box.pack(fill="x", padx=12, pady=(12, 8))

        ctk.CTkLabel(
            intro_box,
            text="Bulk PDF Generation",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=14, pady=(12, 2))

        ctk.CTkLabel(
            intro_box,
            text="Select a directory containing multiple CAPEv2 JSON reports to convert them all in parallel.",
            font=ctk.CTkFont(size=11),
            text_color="#94A3B8"
        ).pack(anchor="w", padx=14, pady=(0, 12))

        dir_sel = ctk.CTkFrame(tab, fg_color="transparent")
        dir_sel.pack(fill="x", padx=12, pady=6)

        ctk.CTkLabel(dir_sel, text="Reports Directory:", width=130, anchor="w").pack(side="left")
        self.batch_dir_var = ctk.StringVar()
        ctk.CTkEntry(dir_sel, textvariable=self.batch_dir_var, placeholder_text="Select folder containing *.json reports...", height=34).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(dir_sel, text="Browse Folder...", width=130, height=34, command=self._on_browse_batch_dir).pack(side="left")

        batch_act = ctk.CTkFrame(tab, fg_color="transparent")
        batch_act.pack(fill="x", padx=12, pady=10)

        self.batch_btn = ctk.CTkButton(
            batch_act,
            text="🚀 Convert All Reports in Directory",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
            command=self._on_generate_batch,
            fg_color="#059669",
            hover_color="#047857"
        )
        self.batch_btn.pack(fill="x")

        # Log Text Box
        self.batch_log = ctk.CTkTextbox(tab, font=ctk.CTkFont(family="Consolas", size=11), height=320)
        self.batch_log.pack(fill="both", expand=True, padx=12, pady=8)
        self.batch_log.insert("end", "Batch processing output will be displayed here...\n")

    # ─── TAB 3: About & Capabilities ─────────────────────────────────────────

    def _build_about_tab(self):
        tab = self.tab_about

        about_box = ctk.CTkScrollableFrame(tab, fg_color=("#FFFFFF", "#1E293B"))
        about_box.pack(fill="both", expand=True, padx=12, pady=12)

        ctk.CTkLabel(about_box, text="capev2-report-generator", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", pady=(8, 4))
        desc = (
            "capev2-report-generator is an executive malware reporting suite that transforms raw 30MB-100MB+ "
            "CAPEv2 sandbox JSON outputs into publication-grade, professionally indexed executive PDF reports.\n\n"
            "Developed by Nitiraj Kulkarni\n"
            "Repository: https://github.com/NitirajKulkarni/capev2-report-generator"
        )
        ctk.CTkLabel(about_box, text=desc, font=ctk.CTkFont(size=12), justify="left", text_color="#CBD5E1").pack(anchor="w", pady=(0, 14))

        ctk.CTkLabel(about_box, text="Key Capabilities & In-Depth Extraction:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", pady=(6, 4))
        caps = (
            "• Executive Summary: Analysis metadata, sandbox telemetry, duration, verdict, and threat rating gauge.\n"
            "• Dynamic Interactive Table of Contents: Automatically excludes absent sections and features 100% accurate link jumping.\n"
            "• Monospace Hashes & Checksums Block: Copyable cryptographic block formatted cleanly inside table borders.\n"
            "• CAPE Config Decryption: Automatic extraction and decryption of malware configurations (AgentTesla, RedLine, etc.) with C2 endpoints and credentials.\n"
            "• Exhaustive Payload Extractions: Injected shellcodes, unpacked PEs, and memory dumps with full cryptographic hashes.\n"
            "• MITRE ATT&CK Matrix: Maps observed dynamic behaviors to MITRE ATT&CK techniques and tactics.\n"
            "• Process Execution Hierarchy: Indented visual execution tree with parent-child PIDs, image paths, and command lines.\n"
            "• Defanged IOC Table: Automatic defanging of URLs, domains, and IP addresses ready for SOC/SIEM consumption.\n"
            "• Behavioral Modifications: Highlights persistence registry keys (Run, RunOnce), security bypasses, mutexes, and dropped files.\n"
            "• Publication Quality: Dynamic 'Page X of Y' numbering, confidentiality badges, running headers, and clean tables."
        )
        ctk.CTkLabel(about_box, text=caps, font=ctk.CTkFont(size=11), justify="left", text_color="#94A3B8").pack(anchor="w", pady=(0, 14))

    # ─── Settings Persistence & Helpers ──────────────────────────────────────

    def _on_save_preferences(self):
        """Manually save user preferences into persistent memory."""
        self._persist_settings()
        self.status_lbl.configure(text="Preferences saved into memory.")
        messagebox.showinfo("Preferences Saved", "Your Analyst Name, Organization, Report Title, and Classification preferences have been remembered.")

    def _persist_settings(self):
        """Save form fields to persistent settings."""
        cls_val = self.tlp_var.get().strip()
        if cls_val in ("(None / White Label)", "None"):
            cls_val = ""
        cfg = {
            "analyst_name": self.analyst_var.get().strip(),
            "organization": self.org_var.get().strip(),
            "report_title": self.report_title_var.get().strip() or "CAPEv2 Sandbox Malware Analysis Report",
            "classification": cls_val,
            "output_dir": self.out_dir_var.get().strip(),
        }
        save_settings(cfg)

    def _get_report_options(self) -> dict:
        """Collect current report configuration and update persistent memory."""
        self._persist_settings()
        cls_val = self.tlp_var.get().strip()
        if cls_val in ("(None / White Label)", "None"):
            cls_val = ""
        return {
            "analyst": self.analyst_var.get().strip(),
            "organization": self.org_var.get().strip(),
            "report_title": self.report_title_var.get().strip() or "CAPEv2 Sandbox Malware Analysis Report",
            "classification": cls_val,
        }

    # ─── Event Handlers ──────────────────────────────────────────────────────

    def _on_browse_json(self):
        filename = filedialog.askopenfilename(
            title="Select CAPEv2 Report JSON",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.json_path_var.set(filename)
            self._inspect_loaded_json(filename)

    def _on_browse_out_dir(self):
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            self.out_dir_var.set(folder)
            self._persist_settings()

    def _on_browse_batch_dir(self):
        folder = filedialog.askdirectory(title="Select Reports Folder")
        if folder:
            self.batch_dir_var.set(folder)

    def _inspect_loaded_json(self, path: str):
        """Parse JSON in background and populate Inspector Card."""
        self.status_lbl.configure(text=f"Inspecting report: {os.path.basename(path)}...")

        def worker():
            try:
                data = parse_cape_report(path)
                self.current_report_data = data
                self.current_json_path = path
                self.root.after(0, self._update_inspector_ui, data)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Parsing Error", f"Could not parse CAPEv2 JSON:\n{e}"))

        threading.Thread(target=worker, daemon=True).start()

    def _update_inspector_ui(self, data: CapeReportData):
        """Update the Live Inspector Card with parsed report metrics."""
        for widget in self.insp_grid.winfo_children():
            widget.destroy()

        v_color = "#DC2626" if data.verdict == "MALICIOUS" else ("#D97706" if data.verdict == "SUSPICIOUS" else "#059669")
        fam_text = f" [{', '.join(data.families)}]" if data.families else ""

        self.insp_title.configure(
            text=f"Target: {data.filename} ({data.file_size_fmt})  |  Verdict: {data.verdict} (Score: {data.malscore:.1f}/10.0){fam_text}",
            text_color=v_color
        )

        r1 = ctk.CTkFrame(self.insp_grid, fg_color="transparent")
        r1.pack(fill="x", pady=2)
        ctk.CTkLabel(r1, text=f"• ID: #{data.id}", width=80, anchor="w", font=ctk.CTkFont(size=11, weight="bold")).pack(side="left")
        ctk.CTkLabel(r1, text=f"• Package: {data.package}", width=110, anchor="w", font=ctk.CTkFont(size=11)).pack(side="left")
        ctk.CTkLabel(r1, text=f"• Extracted Configs: {len(data.configs)}", width=140, anchor="w", font=ctk.CTkFont(size=11)).pack(side="left")
        ctk.CTkLabel(r1, text=f"• Payloads: {len(data.payloads)}", width=110, anchor="w", font=ctk.CTkFont(size=11)).pack(side="left")
        ctk.CTkLabel(r1, text=f"• Processes: {len(data.process_list)}", width=100, anchor="w", font=ctk.CTkFont(size=11)).pack(side="left")

        r2 = ctk.CTkFrame(self.insp_grid, fg_color="transparent")
        r2.pack(fill="x", pady=2)
        sha_short = data.sha256[:32] + "..." if len(data.sha256) > 32 else data.sha256
        ctk.CTkLabel(r2, text=f"SHA-256: {sha_short}", font=ctk.CTkFont(family="Consolas", size=10), text_color="#94A3B8").pack(side="left")

        self.status_lbl.configure(text=f"Loaded #{data.id} - {data.filename} ({data.verdict})")

    def _on_generate_single(self):
        json_path = self.json_path_var.get().strip()
        if not json_path or not os.path.isfile(json_path):
            messagebox.showwarning("File Required", "Please select a valid CAPEv2 JSON report file first.")
            return

        out_dir = self.out_dir_var.get().strip()
        if not out_dir:
            out_dir = os.path.dirname(os.path.abspath(json_path))
        os.makedirs(out_dir, exist_ok=True)

        base_name = os.path.splitext(os.path.basename(json_path))[0]
        out_pdf = os.path.join(out_dir, f"{base_name}_Analysis_Report.pdf")

        options = self._get_report_options()

        self.gen_btn.configure(state="disabled", text="⏳ Rendering PDF Document...")
        self.progress_bar.pack(fill="x", padx=12, pady=(8, 4))
        self.progress_bar.set(0.3)
        self.status_lbl.configure(text=f"Generating PDF report for {os.path.basename(json_path)}...")

        def worker():
            try:
                generate_pdf_report(json_path, out_pdf, options=options)
                self.last_generated_pdf = out_pdf
                self.root.after(0, self._on_single_success, out_pdf)
            except Exception as e:
                self.root.after(0, self._on_single_error, str(e))

        threading.Thread(target=worker, daemon=True).start()

    def _on_single_success(self, pdf_path: str):
        self.gen_btn.configure(state="normal", text="⚡ Generate Executive PDF Report")
        self.progress_bar.set(1.0)
        self.open_pdf_btn.configure(state="normal")
        self.open_folder_btn.configure(state="normal")
        self.status_lbl.configure(text=f"SUCCESS: Generated {os.path.basename(pdf_path)} ({os.path.getsize(pdf_path):,} bytes)")

        messagebox.showinfo(
            "Report Generated Successfully",
            f"PDF Analysis Report has been created:\n\n{pdf_path}\n\nClick 'Open PDF' to view the document."
        )

    def _on_single_error(self, err_msg: str):
        self.gen_btn.configure(state="normal", text="⚡ Generate Executive PDF Report")
        self.progress_bar.pack_forget()
        self.status_lbl.configure(text="Generation failed.")
        messagebox.showerror("Generation Error", f"Failed to generate PDF report:\n\n{err_msg}")

    def _on_open_pdf(self):
        if self.last_generated_pdf and os.path.isfile(self.last_generated_pdf):
            try:
                if sys.platform.startswith("win"):
                    os.startfile(self.last_generated_pdf)
                elif sys.platform.startswith("darwin"):
                    subprocess.Popen(["open", self.last_generated_pdf])
                else:
                    subprocess.Popen(["xdg-open", self.last_generated_pdf])
            except Exception as e:
                messagebox.showerror("Open Error", f"Could not launch PDF viewer:\n{e}")

    def _on_open_folder(self):
        if self.last_generated_pdf and os.path.isfile(self.last_generated_pdf):
            folder = os.path.dirname(os.path.abspath(self.last_generated_pdf))
            try:
                if sys.platform.startswith("win"):
                    subprocess.Popen(f'explorer /select,"{os.path.abspath(self.last_generated_pdf)}"')
                else:
                    subprocess.Popen(["xdg-open", folder])
            except Exception as e:
                messagebox.showerror("Open Folder Error", f"Could not open directory:\n{e}")

    def _on_generate_batch(self):
        target_dir = self.batch_dir_var.get().strip()
        if not target_dir or not os.path.isdir(target_dir):
            messagebox.showwarning("Directory Required", "Please select a valid folder containing CAPEv2 JSON reports.")
            return

        import glob
        json_files = glob.glob(os.path.join(target_dir, "*.json"))
        if not json_files:
            messagebox.showwarning("No Reports Found", f"No *.json files found in {target_dir}")
            return

        self.batch_btn.configure(state="disabled", text="⏳ Processing Batch...")
        self.batch_log.delete("1.0", "end")
        self.batch_log.insert("end", f"Starting batch conversion of {len(json_files)} reports in:\n{target_dir}\n" + "=" * 65 + "\n")

        options = self._get_report_options()

        def worker():
            success = 0
            for i, jf in enumerate(json_files, 1):
                bname = os.path.splitext(os.path.basename(jf))[0]
                out_pdf = os.path.join(target_dir, f"{bname}_Analysis_Report.pdf")
                msg = f"[{i}/{len(json_files)}] Converting {os.path.basename(jf)}... "
                self.root.after(0, lambda m=msg: self.batch_log.insert("end", m))
                try:
                    generate_pdf_report(jf, out_pdf, options=options)
                    msg_ok = f"DONE ({os.path.getsize(out_pdf):,} bytes)\n"
                    self.root.after(0, lambda m=msg_ok: self.batch_log.insert("end", m))
                    success += 1
                except Exception as e:
                    msg_err = f"FAILED: {e}\n"
                    self.root.after(0, lambda m=msg_err: self.batch_log.insert("end", m))

            fin_msg = f"\n" + "=" * 65 + f"\nBatch finished: {success}/{len(json_files)} reports successfully converted to PDF!\n"
            self.root.after(0, lambda: self.batch_log.insert("end", fin_msg))
            self.root.after(0, lambda: self.batch_btn.configure(state="normal", text="🚀 Convert All Reports in Directory"))
            self.root.after(0, lambda: messagebox.showinfo("Batch Complete", f"Batch conversion complete!\n\nConverted: {success}/{len(json_files)} reports."))

        threading.Thread(target=worker, daemon=True).start()

    def run(self):
        self.root.mainloop()


def launch_gui():
    """Launch the GUI application."""
    app = CapeReportGui()
    app.run()
