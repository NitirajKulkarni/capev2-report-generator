"""
CAPEv2 JSON Sandbox Report Parser (Exhaustive & Memory-Efficient)
Extracts, structures, and normalizes all data from CAPEv2 report.json files
without arbitrary truncation or slicing, ready for commercial-grade reporting.
"""

import os
import json
import re
from typing import Dict, Any, List, Optional


def defang(text: str) -> str:
    """Defang URLs and IPs for safe inclusion in reports."""
    if not text or not isinstance(text, str):
        return ""
    # Defang http/https
    t = re.sub(r'https?://', lambda m: m.group(0).replace('http', 'hxxp'), text, flags=re.IGNORECASE)
    # Defang ftp
    t = re.sub(r'ftp://', 'fxp://', t, flags=re.IGNORECASE)
    # Defang dots in domains / IPv4 addresses
    return re.sub(r'(?<=\w)\.(?=\w)', '[.]', t)


def format_bytes(size: Optional[int]) -> str:
    """Format byte size into human readable string."""
    if size is None:
        return "Unknown"
    try:
        size = float(size)
    except (ValueError, TypeError):
        return str(size)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(size) < 1024.0:
            return f"{size:3.1f} {unit}" if unit != 'B' else f"{int(size)} B"
        size /= 1024.0
    return f"{size:.1f} TB"


class CapeReportData:
    """Complete, exhaustive representation of a CAPEv2 analysis report."""

    def __init__(self, raw: Dict[str, Any], filepath: str = ""):
        self.raw_path = filepath
        self.raw_filesize = os.path.getsize(filepath) if filepath and os.path.isfile(filepath) else 0

        # ─── 1. Info / Metadata ───────────────────────────────────────────────
        info = raw.get("info", {}) or {}
        self.id = info.get("id", "N/A")
        self.category = info.get("category", "file")
        self.package = info.get("package", "unknown")
        self.started = info.get("started", "N/A")
        self.ended = info.get("ended", "N/A")
        self.duration = info.get("duration", 0)
        self.version = info.get("version", "CAPEv2")
        self.commit = info.get("CAPE_current_commit", "")
        self.tlp = (info.get("tlp") or "").upper()
        self.route = info.get("route", "none")
        self.options = info.get("options", "")
        self.custom = info.get("custom", "")

        machine = info.get("machine", {}) or {}
        if isinstance(machine, dict):
            self.machine_name = machine.get("name", "cape-win")
            self.machine_os = machine.get("label", "Windows 10 x64")
            self.machine_ip = machine.get("ip", "")
        else:
            self.machine_name = str(machine)
            self.machine_os = "Windows"
            self.machine_ip = ""

        # ─── 2. Target Sample Information ─────────────────────────────────────
        target = raw.get("target", {}) or {}
        target_file = target.get("file", {}) if isinstance(target, dict) else {}
        self.filename = target_file.get("name") or os.path.basename(target_file.get("path", "unknown_sample"))
        self.file_path = target_file.get("path", "")
        self.guest_paths = target_file.get("guest_paths", []) or []
        self.file_size = target_file.get("size", 0)
        self.file_size_fmt = format_bytes(self.file_size)
        self.file_type = target_file.get("type", "Unknown binary format")
        self.mime = target_file.get("mime", "")
        self.cape_type = target_file.get("cape_type", self.package)

        # Hashes (All of them)
        self.crc32 = target_file.get("crc32", "N/A")
        self.md5 = target_file.get("md5", "N/A")
        self.sha1 = target_file.get("sha1", "N/A")
        self.sha256 = target_file.get("sha256", "N/A")
        self.sha512 = target_file.get("sha512", "N/A")
        self.ssdeep = target_file.get("ssdeep", "N/A")
        self.tlsh = target_file.get("tlsh", "N/A")
        self.rh_hash = target_file.get("rh_hash", "N/A")
        self.sha3_384 = target_file.get("sha3_384", "N/A")

        # Antivirus & YARA
        self.clamav = target_file.get("clamav", "")
        self.yara_matches = target_file.get("yara", []) or []
        self.cape_yara = target_file.get("cape_yara", []) or []
        self.virustotal = target_file.get("virustotal", {}) or {}

        # Static PE Analysis (if present)
        static = target_file.get("static", {}) or raw.get("static", {}) or {}
        self.static_pe = static.get("pe", {}) or {}
        self.pe_sections = self.static_pe.get("sections", []) or []
        self.pe_imports = self.static_pe.get("imports", []) or []
        self.pe_exports = self.static_pe.get("exports", []) or []
        self.pe_timestamp = self.static_pe.get("timestamp", "")
        self.pe_entrypoint = self.static_pe.get("entrypoint", "")
        self.pe_imagebase = self.static_pe.get("imagebase", "")

        # ─── 3. Threat Assessment & Scoring ───────────────────────────────────
        raw_score = raw.get("malscore")
        try:
            self.malscore = float(raw_score) if raw_score is not None else 0.0
        except (ValueError, TypeError):
            self.malscore = 0.0

        self.malstatus = raw.get("malstatus")

        # ─── 4. CAPE Specific Extractions (Configs, Payloads, Procdump) ────────
        cape_sec = raw.get("CAPE", {}) or {}
        self.configs = cape_sec.get("configs", []) or []
        self.payloads = cape_sec.get("payloads", []) or []
        self.procdump = raw.get("procdump", []) or []

        # Identify all detected malware families
        self.families = []
        for cfg in self.configs:
            if isinstance(cfg, dict):
                for k in cfg.keys():
                    if not k.startswith("_") and k not in self.families:
                        self.families.append(k)

        # Smart Threat Verdict Normalization
        if self.configs:
            if self.malscore == 0.0:
                self.malscore = 10.0
            if not self.malstatus:
                self.malstatus = "malicious"
        elif self.payloads and self.malscore == 0.0:
            self.malscore = 6.5
            if not self.malstatus:
                self.malstatus = "suspicious"

        if self.malscore >= 7.0 or self.malstatus == "malicious":
            self.verdict = "MALICIOUS"
            self.verdict_color = "red"
        elif self.malscore >= 4.0 or self.malstatus == "suspicious":
            self.verdict = "SUSPICIOUS"
            self.verdict_color = "amber"
        elif self.malscore > 0.0:
            self.verdict = "LOW RISK"
            self.verdict_color = "yellow"
        else:
            self.verdict = "CLEAN / BENIGN"
            self.verdict_color = "green"

        # ─── 5. Signatures & MITRE ATT&CK ─────────────────────────────────────
        self.signatures = raw.get("signatures", []) or []
        self.ttps = raw.get("ttps", []) or []

        # ─── 6. Processes & Hierarchy ─────────────────────────────────────────
        behavior = raw.get("behavior", {}) or {}
        self.processtree = behavior.get("processtree", []) or []
        self.raw_processes = behavior.get("processes", []) or []
        self.process_list = self._extract_flat_processes(behavior)

        # ─── 7. Behavioral Modifications (All items) ──────────────────────────
        summary = behavior.get("summary", {}) or {}
        self.files_written = summary.get("write_files", []) or []
        self.files_read = summary.get("read_files", []) or []
        self.files_deleted = summary.get("delete_files", []) or []
        self.keys_written = summary.get("write_keys", []) or []
        self.keys_read = summary.get("read_keys", []) or []
        self.keys_deleted = summary.get("delete_keys", []) or []
        self.executed_commands = summary.get("executed_commands", []) or []
        self.mutexes = summary.get("mutexes", []) or []
        self.started_services = summary.get("started_services", []) or []
        self.created_services = summary.get("created_services", []) or []
        self.resolved_apis = summary.get("resolved_apis", []) or []

        # Categorize persistence & security bypass keys
        self.persistence_keys = [k for k in self.keys_written if any(
            p in k.lower() for p in ['run', 'runonce', 'startup', 'shell', 'userinit', 'winlogon', 'currentversion\\run']
        )]
        self.security_bypass_keys = [k for k in self.keys_written if any(
            p in k.lower() for p in ['defender', 'uac', 'firewall', 'security', 'macro', 'protectedview', 'disableantivirus']
        )]

        # ─── 8. Dropped Files ─────────────────────────────────────────────────
        self.dropped = raw.get("dropped", []) or []

        # ─── 9. Network Activity ──────────────────────────────────────────────
        network = raw.get("network", {}) or {}
        self.dns_requests = network.get("dns", []) or []
        self.http_requests = network.get("http", []) or []
        self.https_requests = network.get("https", []) or []
        self.tcp_connections = network.get("tcp", []) or []
        self.udp_connections = network.get("udp", []) or []
        self.hosts = network.get("hosts", []) or []
        self.domains = network.get("domains", []) or []

        # Network IOCs
        self.network_iocs = self._extract_network_iocs()

        # ─── 10. Execution Statistics & Telemetry ─────────────────────────────
        self.statistics = raw.get("statistics", {}) or {}

    def _extract_flat_processes(self, behavior: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract a clean flat list of all monitored processes."""
        flat = []
        processes = behavior.get("processes", []) or []
        for p in processes:
            environ = p.get("environ", {}) or {}
            cmd = p.get("command_line") or environ.get("CommandLine") or ""
            flat.append({
                "pid": p.get("process_id") or p.get("pid"),
                "ppid": p.get("parent_id"),
                "name": p.get("process_name") or p.get("name") or "Unknown",
                "path": p.get("module_path") or "",
                "command_line": cmd,
                "first_seen": p.get("first_seen", ""),
                "threads_count": len(p.get("threads", [])) if isinstance(p.get("threads"), list) else 0,
                "calls_count": len(p.get("calls", [])) if isinstance(p.get("calls"), list) else 0,
            })
        return flat

    def _extract_network_iocs(self) -> List[Dict[str, str]]:
        """Collect and defang all network indicators."""
        iocs = []
        seen = set()

        # From CAPE configs (e.g. AgentTesla C2)
        for cfg in self.configs:
            if isinstance(cfg, dict):
                for fam, details in cfg.items():
                    if isinstance(details, dict):
                        for c2 in details.get("C2", []) or []:
                            if c2 not in seen:
                                seen.add(c2)
                                iocs.append({"type": "Malware C2 Server", "value": c2, "defanged": defang(c2)})
                        for ip_srv in details.get("ExternalIPCheckServices", []) or []:
                            val = ip_srv[0] if isinstance(ip_srv, list) and ip_srv else str(ip_srv)
                            if val not in seen:
                                seen.add(val)
                                iocs.append({"type": "IP Check Service", "value": val, "defanged": defang(val)})

        # From DNS
        for d in self.dns_requests:
            req = d.get("request") or d.get("domain") or ""
            if req and req not in seen:
                seen.add(req)
                iocs.append({"type": "DNS Query", "value": req, "defanged": defang(req)})

        # From HTTP
        for h in self.http_requests:
            uri = h.get("uri") or h.get("url") or ""
            if uri and uri not in seen:
                seen.add(uri)
                iocs.append({"type": "HTTP URL", "value": uri, "defanged": defang(uri)})

        # From TCP
        for conn in self.tcp_connections:
            dst = conn.get("dst")
            dport = conn.get("dport")
            val = f"{dst}:{dport}"
            if dst and dst not in seen and dst not in ("127.0.0.1", "192.168.250.1", "8.8.8.8", "1.1.1.1"):
                seen.add(dst)
                iocs.append({"type": "TCP Connection", "value": val, "defanged": defang(val)})

        return iocs


def parse_cape_report(filepath: str) -> CapeReportData:
    """Parse a CAPEv2 report.json file into a CapeReportData object."""
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Report file not found: {filepath}")

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    return CapeReportData(data, filepath=filepath)
