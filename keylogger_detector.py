"""
keylogger_detector.py
=====================
A Python-based security tool to detect potential keylogger activity on a system.

Detects:
- Suspicious processes using keyboard hooks / input monitoring
- Files writing to suspicious locations (temp, startup)
- Autorun registry entries (Windows)
- Network connections from suspicious processes
- Known keylogger process names

Usage:
    python keylogger_detector.py
    python keylogger_detector.py --verbose
    python keylogger_detector.py --output report.json
    python keylogger_detector.py --watch  (continuous monitoring mode)

Requirements:
    pip install psutil colorama
    pip install pywin32  (Windows only, for registry scan)
"""

import os
import sys
import json
import time
import argparse
import platform
import datetime
import subprocess
from pathlib import Path

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("[WARNING] psutil not installed. Run: pip install psutil")

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

# ──────────────────────────────────────────────
#  Color helpers
# ──────────────────────────────────────────────

def red(text):    return (Fore.RED + text + Style.RESET_ALL) if COLORAMA_AVAILABLE else text
def yellow(text): return (Fore.YELLOW + text + Style.RESET_ALL) if COLORAMA_AVAILABLE else text
def green(text):  return (Fore.GREEN + text + Style.RESET_ALL) if COLORAMA_AVAILABLE else text
def cyan(text):   return (Fore.CYAN + text + Style.RESET_ALL) if COLORAMA_AVAILABLE else text
def bold(text):   return (Style.BRIGHT + text + Style.RESET_ALL) if COLORAMA_AVAILABLE else text

# ──────────────────────────────────────────────
#  Known suspicious process names
# ──────────────────────────────────────────────

KNOWN_KEYLOGGERS = {
    "revealer keylogger", "spyrix", "refog", "actual keylogger",
    "iwantsoft", "perfect keylogger", "elite keylogger", "kidlogger",
    "keylogger pro", "all in one keylogger", "ardamax", "blackbox",
    "blazingtools", "family keylogger", "ghost keylogger", "hde free keylogger",
    "home keylogger", "keyboard logger", "logixoft", "micro keylogger",
    "paq keylogger", "powered keylogger", "remotespy", "shadow keylogger",
    "soft activity", "spytector", "stealth keyboard logger", "wolfeye",
}

SUSPICIOUS_KEYWORDS = [
    "keylog", "keystroke", "spy", "monitor", "hook", "logger",
    "record", "capture", "sniff", "stealth", "invisible", "hidden",
]

# ──────────────────────────────────────────────
#  Suspicious directories (log drop zones)
# ──────────────────────────────────────────────

SUSPICIOUS_WRITE_PATHS = []

if platform.system() == "Windows":
    SUSPICIOUS_WRITE_PATHS += [
        os.environ.get("TEMP", "C:\\Windows\\Temp"),
        os.environ.get("APPDATA", ""),
        "C:\\Windows\\System32",
        os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
    ]
elif platform.system() == "Darwin":
    home = str(Path.home())
    SUSPICIOUS_WRITE_PATHS += [
        "/tmp", "/var/tmp",
        os.path.join(home, "Library", "LaunchAgents"),
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
    ]
else:  # Linux
    home = str(Path.home())
    SUSPICIOUS_WRITE_PATHS += [
        "/tmp", "/var/tmp",
        os.path.join(home, ".config", "autostart"),
        "/etc/init.d",
        "/etc/cron.d",
    ]

# ──────────────────────────────────────────────
#  Finding class
# ──────────────────────────────────────────────

class Finding:
    SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    def __init__(self, severity: str, category: str, description: str, detail: str = ""):
        self.severity = severity.upper()
        self.category = category
        self.description = description
        self.detail = detail
        self.timestamp = datetime.datetime.now().isoformat()

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }

    def __str__(self):
        sev_color = {
            "LOW": yellow, "MEDIUM": yellow, "HIGH": red, "CRITICAL": red
        }.get(self.severity, lambda x: x)
        return (
            f"  [{sev_color(self.severity)}] {bold(self.category)} — {self.description}"
            + (f"\n         ↳ {self.detail}" if self.detail else "")
        )

# ──────────────────────────────────────────────
#  Scanner
# ──────────────────────────────────────────────

class KeyloggerDetector:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: list[Finding] = []
        self.scanned = {
            "processes": 0,
            "open_files": 0,
            "connections": 0,
        }

    def log(self, msg: str):
        if self.verbose:
            print(cyan("  [v] ") + msg)

    def add(self, finding: Finding):
        self.findings.append(finding)
        print(str(finding))

    # ── 1. Process name scan ──────────────────

    def scan_processes(self):
        print(bold("\n[1/4] Scanning running processes..."))
        if not PSUTIL_AVAILABLE:
            print(yellow("  Skipped — psutil not available."))
            return

        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                name = (proc.info["name"] or "").lower()
                exe  = (proc.info["exe"] or "").lower()
                cmd  = " ".join(proc.info["cmdline"] or []).lower()
                self.scanned["processes"] += 1

                # Check known keylogger names
                for kl in KNOWN_KEYLOGGERS:
                    if kl in name or kl in exe:
                        self.add(Finding(
                            "CRITICAL", "Known Keylogger",
                            f"Process matches known keylogger: '{proc.info['name']}'",
                            f"PID {proc.pid} | exe: {proc.info['exe']}"
                        ))
                        break

                # Check suspicious keywords
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw in name and kw not in {"record"}:  # filter common false positives
                        self.add(Finding(
                            "HIGH", "Suspicious Process Name",
                            f"Process name contains suspicious keyword '{kw}': {proc.info['name']}",
                            f"PID {proc.pid}"
                        ))
                        break

                self.log(f"Process: {proc.info['name']} (PID {proc.pid})")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    # ── 2. Open file handles scan ─────────────

    def scan_open_files(self):
        print(bold("\n[2/4] Scanning open file handles for suspicious log files..."))
        if not PSUTIL_AVAILABLE:
            print(yellow("  Skipped — psutil not available."))
            return

        suspicious_extensions = {".log", ".txt", ".dat", ".kl", ".klg"}

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                for f in proc.open_files():
                    path_lower = f.path.lower()
                    self.scanned["open_files"] += 1

                    # Suspicious path AND extension combo
                    ext = os.path.splitext(path_lower)[1]
                    if ext in suspicious_extensions:
                        for sp in SUSPICIOUS_WRITE_PATHS:
                            if sp and path_lower.startswith(sp.lower()):
                                self.add(Finding(
                                    "HIGH", "Suspicious File Write",
                                    f"Process writing log-like file in sensitive directory",
                                    f"Process: {proc.info['name']} (PID {proc.pid}) → {f.path}"
                                ))
                                break

                    # Keylog-related filename
                    for kw in SUSPICIOUS_KEYWORDS:
                        if kw in path_lower:
                            self.add(Finding(
                                "HIGH", "Suspicious Filename",
                                f"Open file contains suspicious keyword '{kw}'",
                                f"Process: {proc.info['name']} (PID {proc.pid}) → {f.path}"
                            ))
                            break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    # ── 3. Network connections scan ──────────

    def scan_network(self):
        print(bold("\n[3/4] Scanning network connections..."))
        if not PSUTIL_AVAILABLE:
            print(yellow("  Skipped — psutil not available."))
            return

        for conn in psutil.net_connections(kind="inet"):
            try:
                self.scanned["connections"] += 1
                if conn.status == "ESTABLISHED" and conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        name = (proc.name() or "").lower()
                        for kw in SUSPICIOUS_KEYWORDS:
                            if kw in name:
                                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "?"
                                self.add(Finding(
                                    "HIGH", "Suspicious Network Activity",
                                    f"Suspicious process has active network connection",
                                    f"Process: {proc.name()} (PID {conn.pid}) → {raddr}"
                                ))
                                break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception:
                continue

    # ── 4. Startup / autorun scan ─────────────

    def scan_startup(self):
        print(bold("\n[4/4] Scanning startup / autorun entries..."))
        system = platform.system()

        if system == "Windows":
            self._scan_windows_registry()
        elif system == "Darwin":
            self._scan_macos_launchagents()
        else:
            self._scan_linux_autostart()

    def _scan_windows_registry(self):
        try:
            import winreg
            keys = [
                (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ]
            for hive, subkey in keys:
                try:
                    with winreg.OpenKey(hive, subkey) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                self.log(f"Startup entry: {name} = {value}")
                                val_lower = value.lower()
                                for kw in SUSPICIOUS_KEYWORDS:
                                    if kw in val_lower or kw in name.lower():
                                        self.add(Finding(
                                            "CRITICAL", "Suspicious Startup Entry",
                                            f"Registry Run key contains suspicious keyword '{kw}'",
                                            f"{subkey}\\{name} = {value}"
                                        ))
                                        break
                                i += 1
                            except OSError:
                                break
                except (FileNotFoundError, PermissionError):
                    pass
        except ImportError:
            print(yellow("  winreg not available — skipping registry scan."))

    def _scan_macos_launchagents(self):
        paths = [
            Path.home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]
        for p in paths:
            if p.exists():
                for f in p.glob("*.plist"):
                    self.log(f"LaunchAgent: {f}")
                    content = f.read_text(errors="ignore").lower()
                    for kw in SUSPICIOUS_KEYWORDS:
                        if kw in content or kw in f.name.lower():
                            self.add(Finding(
                                "HIGH", "Suspicious LaunchAgent",
                                f"LaunchAgent plist contains suspicious keyword '{kw}'",
                                str(f)
                            ))
                            break

    def _scan_linux_autostart(self):
        paths = [
            Path.home() / ".config" / "autostart",
            Path("/etc/init.d"),
            Path("/etc/cron.d"),
            Path("/etc/cron.hourly"),
        ]
        for p in paths:
            if p.exists():
                for f in p.iterdir():
                    if f.is_file():
                        self.log(f"Autostart entry: {f}")
                        try:
                            content = f.read_text(errors="ignore").lower()
                            for kw in SUSPICIOUS_KEYWORDS:
                                if kw in content or kw in f.name.lower():
                                    self.add(Finding(
                                        "HIGH", "Suspicious Autostart Entry",
                                        f"Autostart file contains suspicious keyword '{kw}'",
                                        str(f)
                                    ))
                                    break
                        except PermissionError:
                            pass

    # ── Run all scans ─────────────────────────

    def run(self):
        print(bold(cyan("\n╔══════════════════════════════════════╗")))
        print(bold(cyan("║     KEYLOGGER DETECTOR  v1.0         ║")))
        print(bold(cyan("╚══════════════════════════════════════╝")))
        print(f"  Platform : {platform.system()} {platform.release()}")
        print(f"  Started  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        self.scan_processes()
        self.scan_open_files()
        self.scan_network()
        self.scan_startup()

        return self.report()

    def report(self) -> dict:
        print(bold("\n══════════════ SCAN SUMMARY ══════════════"))
        print(f"  Processes scanned   : {self.scanned['processes']}")
        print(f"  File handles scanned: {self.scanned['open_files']}")
        print(f"  Network connections : {self.scanned['connections']}")
        print(f"  Total findings      : {len(self.findings)}")

        if not self.findings:
            print(green("\n✔  No keylogger indicators detected. System appears clean.\n"))
        else:
            by_severity = {}
            for f in self.findings:
                by_severity.setdefault(f.severity, []).append(f)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = len(by_severity.get(sev, []))
                if count:
                    print(red(f"  ⚠  {count} {sev} finding(s)"))
            print()

        result = {
            "scan_time": datetime.datetime.now().isoformat(),
            "platform": f"{platform.system()} {platform.release()}",
            "scanned": self.scanned,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
        return result


# ──────────────────────────────────────────────
#  CLI entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Keylogger Detector — scan your system for keylogger indicators."
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Show verbose scan output")
    parser.add_argument("--output", "-o", metavar="FILE", help="Save report to JSON file")
    parser.add_argument("--watch", "-w", action="store_true", help="Continuous monitoring mode (60s interval)")
    args = parser.parse_args()

    def run_once():
        detector = KeyloggerDetector(verbose=args.verbose)
        report = detector.run()
        if args.output:
            with open(args.output, "w") as fp:
                json.dump(report, fp, indent=2)
            print(green(f"\n  Report saved to: {args.output}"))
        return report

    if args.watch:
        print(bold(cyan("Continuous monitoring mode. Press Ctrl+C to stop.\n")))
        try:
            while True:
                run_once()
                print(yellow(f"\n  Next scan in 60 seconds...\n"))
                time.sleep(60)
        except KeyboardInterrupt:
            print("\nMonitoring stopped.")
    else:
        run_once()


if __name__ == "__main__":
    main()
