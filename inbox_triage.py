#!/usr/bin/env python3
"""
inbox_triage.py — safe, local-first static file triage. v2.0.1

INBOX -> stable-file detection -> atomic claim -> read-only analysis copy ->
static analysis (signatures, encoding, Unicode, patterns, base64, entropy,
syntax, ClamAV) -> risk routing (with configurable sorting) ->
SQLite + JSON/Markdown reports + JSONL audit log.

SECURITY MODEL
--------------
* Never executes, imports, sources, or renders any input file.
* Analysis runs against a read-only copy in an isolated per-run directory.
* Originals are moved with atomic rename; content is never modified.
* Single-instance lock; same-filesystem requirement verified at startup.
* "clean" means "no indicators found" — never "proven safe".

POSIX only (Linux/macOS). Python 3.10+. Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import fcntl
import fnmatch
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
import unicodedata
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__version__ = "2.1.1"

EXIT_OK = 0
EXIT_FINDINGS = 10
EXIT_FAILURE = 40

TEXT_ANALYSIS_LIMIT = 10 * 1024 * 1024          # analyze at most 10 MiB of bytes
MAX_FINDINGS_PER_CATEGORY = 20                  # findings cap per category
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
RISK_RANK = {"clean": 0, "low": 1, "medium": 2, "high": 3}
RISK_FROM_RANK = {0: "clean", 1: "low", 2: "medium", 3: "high"}

# ======================================================================
# SECTION 1: CONFIGURATION
# ======================================================================

DEFAULT_CONFIG: dict[str, Any] = {
    "max_input_bytes": 100 * 1024 * 1024,
    "keep_analysis_copy": True,
    "retention_days_analysis": 14,
    "stability": {"interval": 1.0, "checks": 2},
    # Uploader/browser in-progress temp files — never processed, never rejected
    "ignore_patterns": ["*.part", "*.partial", "*.crdownload", "*.tmp",
                        "*.download", ".DS_Store", "*.swp", "*~", ".#*"],
    "routing": {
        "clean": "sorted", "low": "sorted", "medium": "review",
        "high": "quarantine", "workflow-failure": "errors",
    },
    # Sort rules: applied ONLY to clean/low files, first match wins,
    # destination is a single-level subdirectory of the clean destination.
    "sort_rules": [],
    "dedup": {"enabled": True, "action": "log"},        # log | route
    "scanners": {"clamav": True, "shellcheck": False},
    "watch": {"degraded_after": 3},
    "notifications": {"enabled": True, "min_severity": "medium"},
    "timeouts": {"clamav": 120, "bash": 30, "shellcheck": 60, "file": 15},
}

VALID_ROUTING_TARGETS = {"sorted", "review", "quarantine", "errors", "duplicates"}
_DEST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")


def _merge(base: dict, user: dict) -> None:
    for key, value in user.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value


def validate_config(cfg: dict[str, Any]) -> None:
    problems: list[str] = []
    routing = cfg.get("routing", {})
    for risk, target in routing.items():
        if target not in VALID_ROUTING_TARGETS:
            problems.append(f"routing.{risk}: unknown target '{target}'")
    if cfg["dedup"]["action"] not in {"log", "route"}:
        problems.append("dedup.action must be 'log' or 'route'")
    if cfg["max_input_bytes"] <= 0:
        problems.append("max_input_bytes must be positive")
    st = cfg["stability"]
    if st["checks"] < 1 or st["interval"] <= 0:
        problems.append("stability.checks must be >= 1 and stability.interval > 0")
    for i, rule in enumerate(cfg["sort_rules"]):
        if "match" not in rule or "destination" not in rule:
            problems.append(f"sort_rules[{i}]: needs 'match' and 'destination'")
            continue
        pats = rule["match"] if isinstance(rule["match"], list) else [rule["match"]]
        if not pats or not all(isinstance(p, str) and p for p in pats):
            problems.append(f"sort_rules[{i}].match: must be a pattern or list of patterns")
        dest = rule["destination"]
        if (not isinstance(dest, str) or not _DEST_RE.fullmatch(dest)
                or dest in {".", ".."} or "/" in dest):
            problems.append(
                f"sort_rules[{i}].destination: '{dest}' must be a single "
                f"safe directory name (no separators, no '..')")
    if problems:
        raise SystemExit("FATAL: invalid configuration:\n  - " + "\n  - ".join(problems))


def load_config(path: Path | None) -> dict[str, Any]:
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if path is not None:
        try:
            user = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"FATAL: cannot read config {path}: {exc}")
        if not isinstance(user, dict):
            raise SystemExit("FATAL: config root must be a JSON object")
        _merge(cfg, user)
    validate_config(cfg)
    return cfg


# ======================================================================
# SECTION 2: PATHS, LOCK, FILESYSTEM VERIFICATION
# ======================================================================

class Paths:
    def __init__(self, root: Path):
        self.root = root
        self.inbox = root / "inbox"
        self.processing = root / "processing"
        self.sorted_dir = root / "sorted"
        self.review = root / "review"
        self.quarantine = root / "quarantine"
        self.errors = root / "errors"
        self.duplicates = root / "duplicates"
        self.reports = root / "reports"
        self.logs = root / "logs"
        self.by_name = {
            "sorted": self.sorted_dir, "review": self.review,
            "quarantine": self.quarantine, "errors": self.errors,
            "duplicates": self.duplicates,
        }
        for p in (self.inbox, self.processing, self.sorted_dir, self.review,
                  self.quarantine, self.errors, self.duplicates,
                  self.reports, self.logs):
            p.mkdir(parents=True, exist_ok=True)


def verify_same_filesystem(paths: Paths) -> None:
    """Atomic os.replace() only works within one filesystem."""
    inbox_dev = os.stat(paths.inbox).st_dev
    for name in ("processing", "sorted_dir", "review", "quarantine",
                 "errors", "duplicates"):
        d = getattr(paths, name)
        if os.stat(d).st_dev != inbox_dev:
            raise SystemExit(
                f"FATAL: {d} is on a different filesystem than {paths.inbox}.\n"
                f"       Atomic moves would fail; keep all routing directories "
                f"on one filesystem (reports/ and logs/ may live elsewhere).")


@contextlib.contextmanager
def instance_lock(root: Path):
    """Advisory single-instance lock. Holder processes exclusively."""
    lock_path = root / ".triage.lock"
    fh = lock_path.open("w")
    try:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit("FATAL: another triage instance holds the lock "
                             f"({lock_path}). Refusing to run concurrently.")
        yield
    finally:
        fh.close()


# ======================================================================
# SECTION 3: SMALL UTILITIES
# ======================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_name(name: str) -> str:
    """Unified filename normalization: charset-safe, no traversal."""
    value = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    value = value.strip(".") or "unnamed"
    return value[:180]


def unique_destination(directory: Path, filename: str) -> Path:
    """Collision-resistant destination; never overwrites."""
    directory.mkdir(parents=True, exist_ok=True)
    candidate = directory / safe_name(filename)
    if not candidate.exists():
        return candidate
    stem, suffix = candidate.stem, candidate.suffix
    for _ in range(5):
        token = uuid.uuid4().hex[:12]
        candidate = directory / f"{stem}-{token}{suffix}"
        if not candidate.exists():
            return candidate
    return directory / f"{stem}-{uuid.uuid4().hex}{suffix}"


def sanitize_evidence(value: str) -> str:
    """Strip control/format characters so evidence is safe to store/print."""
    cleaned = "".join(
        ch if (ord(ch) >= 0x20 or ch == "\t")
        and unicodedata.category(ch)[0] != "C" else "\u00b7"
        for ch in value)
    return cleaned.strip()[:300]


def run_command(command: list[str], timeout: int) -> dict[str, Any]:
    """Run external scanner. Bytes decoded with errors='replace'."""
    if not shutil.which(command[0]):
        return {"available": False, "status": "not-installed", "command": command}
    try:
        proc = subprocess.run(command, capture_output=True,
                              timeout=timeout, check=False)
        return {
            "available": True, "return_code": proc.returncode, "command": command,
            "stdout": proc.stdout.decode("utf-8", "replace")[-4000:],
            "stderr": proc.stderr.decode("utf-8", "replace")[-4000:],
        }
    except subprocess.TimeoutExpired:
        return {"available": True, "status": "timeout", "command": command}
    except OSError as exc:
        return {"available": True, "status": "error",
                "error": str(exc), "command": command}


def add_finding(report: dict[str, Any], category: str, severity: str,
                description: str, *, line: int | None = None,
                evidence: str | None = None) -> None:
    """Add a finding with a per-category cap; excess counted as suppressed."""
    counts = report.setdefault("_category_counts", {})
    if counts.get(category, 0) >= MAX_FINDINGS_PER_CATEGORY:
        sup = report.setdefault("_suppressed", {})
        sup[category] = sup.get(category, 0) + 1
        return
    counts[category] = counts.get(category, 0) + 1
    finding: dict[str, Any] = {"category": category, "severity": severity,
                               "description": description}
    if line is not None:
        finding["line"] = line
    if evidence:
        finding["evidence"] = sanitize_evidence(evidence)
    report["findings"].append(finding)


def _finalize_suppressed(report: dict[str, Any]) -> None:
    """Convert suppression counts into summary findings; strip internal keys."""
    for category, count in report.get("_suppressed", {}).items():
        report["findings"].append({
            "category": category, "severity": "low",
            "description": f"{count} additional '{category}' matches suppressed "
                           f"(cap of {MAX_FINDINGS_PER_CATEGORY} reached).",
        })
    report.pop("_category_counts", None)
    report.pop("_suppressed", None)


def determine_risk(report: dict[str, Any]) -> str:
    best = 0
    for f in report.get("findings", []):
        best = max(best, SEVERITY_RANK.get(f.get("severity"), 0))
    return RISK_FROM_RANK[best]


def desktop_notify(title: str, message: str) -> None:
    """Best-effort desktop notification. Never raises, never blocks triage."""
    try:
        if shutil.which("notify-send"):
            subprocess.run(
                ["notify-send", "-t", "5000", "--", title, message],
                timeout=5, check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif shutil.which("osascript"):
            safe_title = title.replace("\\", "\\\\").replace('"', '\\"')
            safe_msg = message.replace("\\", "\\\\").replace('"', '\\"')
            subprocess.run(
                ["osascript", "-e",
                 f'display notification "{safe_msg}" '
                 f'with title "{safe_title}"'],
                timeout=5, check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass  # a notification failure must never affect triage


def _notify_if_needed(risk: str, name: str, run_id: str,
                      cfg: dict[str, Any]) -> None:
    """Alert on medium/high routing (per min_severity) and on any workflow
    failure — 'the scanner couldn't finish' is always worth knowing."""
    if not cfg["notifications"]["enabled"]:
        return
    threshold = RISK_RANK.get(cfg["notifications"]["min_severity"], 2)
    if (risk in ("medium", "high") and RISK_RANK[risk] >= threshold) \
            or risk == "workflow-failure":
        desktop_notify("QuietOps Triage",
                       f"{name}: {risk.upper()} — report {run_id}")


# ======================================================================
# SECTION 4: UNICODE TABLES AND PATTERNS
# ======================================================================

BIDI_OVERRIDE = {   # HIGH — Trojan-Source class: display differs from logic
    "\u202a": "LRE", "\u202b": "RLE", "\u202c": "PDF",
    "\u202d": "LRO", "\u202e": "RLO",
    "\u2066": "LRI", "\u2067": "RLI", "\u2068": "FSI", "\u2069": "PDI",
}
DIRECTIONAL_MARKS = {"\u200e": "LRM", "\u200f": "RLM", "\u061c": "ALM"}  # medium
ZERO_WIDTH = {"\u200b": "ZWSP", "\u200c": "ZWNJ", "\u200d": "ZWJ"}      # high
ZWNBSP = "\ufeff"          # BOM at offset 0 = benign; elsewhere = high
SOFT_HYPHEN = "\u00ad"     # medium
HOMOGLYPHS = {
    "\u0430": "Cyrillic \u0430 (U+0430) resembles Latin a",
    "\u0435": "Cyrillic \u0435 (U+0435) resembles Latin e",
    "\u043e": "Cyrillic \u043e (U+043E) resembles Latin o",
    "\u0440": "Cyrillic \u0440 (U+0440) resembles Latin p",
    "\u0441": "Cyrillic \u0441 (U+0441) resembles Latin c",
    "\u0445": "Cyrillic \u0445 (U+0445) resembles Latin x",
    "\u0456": "Cyrillic \u0456 (U+0456) resembles Latin i",
    "\u0458": "Cyrillic \u0458 (U+0458) resembles Latin j",
    "\u0391": "Greek \u0391 (U+0391) resembles Latin A",
    "\u0392": "Greek \u0392 (U+0392) resembles Latin B",
    "\u0395": "Greek \u0395 (U+0395) resembles Latin E",
    "\u0397": "Greek \u0397 (U+0397) resembles Latin H",
    "\u039a": "Greek \u039a (U+039A) resembles Latin K",
    "\u039c": "Greek \u039c (U+039C) resembles Latin M",
    "\u039d": "Greek \u039d (U+039D) resembles Latin N",
    "\u039f": "Greek \u039f (U+039F) resembles Latin O",
    "\u03a1": "Greek \u03a1 (U+03A1) resembles Latin P",
    "\u03a4": "Greek \u03a4 (U+03A4) resembles Latin T",
    "\u03a5": "Greek \u03a5 (U+03A5) resembles Latin Y",
    "\u03b1": "Greek \u03b1 (U+03B1) resembles Latin a",
    "\u03bf": "Greek \u03bf (U+03BF) resembles Latin o",
    "\u03c1": "Greek \u03c1 (U+03C1) resembles Latin p",
    "\u03c5": "Greek \u03c5 (U+03C5) resembles Latin u",
}

# Word-level indicators: MEDIUM severity only (words are not proof).
PATTERN_MEDIUM = {
    "download_command": re.compile(
        r"\b(?:curl|wget|certutil|bitsadmin|invoke-webrequest)\b", re.IGNORECASE),
    "shell_reference": re.compile(
        r"\b(?:bash|zsh|ksh|powershell|pwsh)\b"
        # 'dash' the shell — but not the punctuation word in 'em—dash' /
        # 'en–dash' / 'hyphen-dash' / 'minus−dash' (typographic dashes act as
        # word boundaries, so a bare \b fired on ordinary prose).
        r"|\b(?<![\u2010-\u2015\u2212-])dash\b"
        r"|\b(?:exec|eval)\s*\(", re.IGNORECASE),
    "encoded_content": re.compile(
        r"\b(?:base64|frombase64string|hexdecode)\b"
        r"|\bcertutil\s+-decode\b", re.IGNORECASE),
    "network_reference": re.compile(
        r"\bhttps?://|\bftp://"
        r"|\b(?:socket|urllib|requests|netcat|ncat|telnet)\b", re.IGNORECASE),
    "dynamic_loading": re.compile(
        r"\b(?:__import__|importlib|dlopen|loadlibrary)\b", re.IGNORECASE),
    "persistence_reference": re.compile(
        r"\b(?:crontab|systemctl|launchctl|schtasks)\b"
        r"|\breg\s+add\b|~/\.bashrc\b|/etc/cron\b|/etc/rc\.local\b"
        r"|/etc/ld\.so\.preload\b|/dev/shm\b", re.IGNORECASE),
}

# Execution-intent COMBINATIONS: HIGH severity.
PATTERN_HIGH = [
    ("download_pipe_shell", re.compile(
        r"\b(?:curl|wget|certutil|invoke-webrequest)\b[^\n|]{0,200}\|"
        r"[^\n]{0,40}\b(?:sudo\s+)?(?:ba|z|k)?sh\b", re.IGNORECASE)),
    ("base64_decode_pipe_shell", re.compile(
        r"\b(?:base64|openssl)\b[^\n|]{0,120}\|"
        r"[^\n]{0,40}\b(?:ba|z|k)?sh\b", re.IGNORECASE)),
    ("eval_encoded", re.compile(
        r"\beval\s*\(?\s*[\"']?\s*"
        r"(?:atob|base64|frombase64string|unescape|decodeuricomponent)\b",
        re.IGNORECASE)),
    ("bash_network_redirect", re.compile(r"/dev/(?:tcp|udp)/")),
    ("netcat_exec", re.compile(
        r"\b(?:nc|ncat|netcat)\b[^\n]{0,60}\s(?:-e|-c|--exec)\b", re.IGNORECASE)),
    ("recursive_delete_root", re.compile(
        r"\brm\s+-[rfRF]{1,3}\s+(?:--no-preserve-root\s+)?(?:/|~)(?:\s|$)")),
    ("powershell_download_cradle", re.compile(
        r"\b(?:iex|invoke-expression)\b[^\n]{0,60}"
        r"(?:new-object\s+net\.webclient|downloadstring|invoke-webrequest)\b",
        re.IGNORECASE)),
]

B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
URL_RE = re.compile(r"https?://[^\s'\"<>{}|\\^`\[\]]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# ======================================================================
# SECTION 5: FILE SIGNATURES (header-only, validated)
# ======================================================================

# ZIP containers that are legitimately expected, no finding.
# Plain document formats — the ZIP is expected, content is XML.
SAFE_ZIP_SUFFIXES = {
    ".docx", ".xlsx", ".pptx",          # Office (no macros)
    ".odt",  ".ods",  ".odp",  ".odg",  # LibreOffice (macros uncommon)
    ".epub", ".kmz",  ".3mf",           # books / maps / 3D (data containers)
}

# ZIP containers that carry executable/macro content. Flag MEDIUM.
# Macro-enabled Office (VBA code execution), archives that install/run
# code, and generic .zip (may nest executables).
RISKY_ZIP_SUFFIXES = {
    ".docm", ".xlsm", ".pptm",          # macro-enabled Office
    ".jar",  ".apk",                    # Java / Android (executes)
    ".whl",  ".xpi",  ".vsix", ".ipa",  # Python / Firefox / VS Code / iOS
    ".zip",                             # generic archive
}


def _looks_like_pe(raw: bytes) -> bool:
    """MZ alone is not proof of PE — validate the PE\\0\\0 offset."""
    if len(raw) < 0x40:
        return False
    e_lfanew = int.from_bytes(raw[0x3C:0x40], "little")
    if not (0 < e_lfanew <= len(raw) - 4):
        return False
    return raw[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"


def _classify_cafebabe(raw: bytes) -> str:
    """0xCAFEBABE is both Java-class and Mach-O FAT; disambiguate by version."""
    if len(raw) >= 8:
        minor = int.from_bytes(raw[4:6], "big")
        major = int.from_bytes(raw[6:8], "big")
        if major <= 0xFF and minor <= 0xFF:
            return "Java-class"
    return "Mach-O-FAT"


def _known_binary_format(raw: bytes) -> str | None:
    checks = [
        ("PNG", lambda r: r.startswith(b"\x89PNG\r\n\x1a\n")),
        ("JPEG", lambda r: r.startswith(b"\xff\xd8\xff")),
        ("GIF", lambda r: r[:6] in (b"GIF87a", b"GIF89a")),
        ("GZIP", lambda r: r.startswith(b"\x1f\x8b")),
        ("BZIP2", lambda r: r.startswith(b"BZh")),
        ("XZ", lambda r: r.startswith(b"\xfd7zXZ\x00")),
        ("7-Zip", lambda r: r.startswith(b"7z\xbc\xaf\x27\x1c")),
        ("RAR", lambda r: r.startswith(b"Rar!\x1a\x07")),
        ("SQLite", lambda r: r.startswith(b"SQLite format 3\x00")),
        ("Ogg", lambda r: r.startswith(b"OggS")),
        ("FLAC", lambda r: r.startswith(b"fLaC")),
        ("MP4", lambda r: len(r) >= 12 and r[4:8] == b"ftyp"),
        ("RIFF", lambda r: r[:4] == b"RIFF" and r[8:12] in (b"WAVE", b"AVI ", b"WEBP")),
        ("ICO", lambda r: r.startswith(b"\x00\x00\x01\x00")),
        ("PCAP", lambda r: r[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")),
        ("TAR", lambda r: len(r) >= 262 and r[257:262] == b"ustar"),
    ]
    for name, pred in checks:
        try:
            if pred(raw):
                return name
        except Exception:
            continue
    return None


def analyze_header_signatures(raw: bytes, suffix: str,
                              report: dict[str, Any]) -> set[str]:
    """Header-position signatures only. Returns matched names."""
    matched: set[str] = set()

    if raw.startswith(b"\x7fELF"):
        matched.add("ELF")
        add_finding(report, "embedded_signature", "high",
                    "ELF executable header — requires sandbox analysis, "
                    "never run on this host.")
    elif raw.startswith(b"MZ"):
        kind = "PE" if _looks_like_pe(raw) else "DOS-exe"
        matched.add(kind)
        add_finding(report, "embedded_signature", "high",
                    f"{kind} executable header — requires sandbox analysis, "
                    f"never run on this host.")
    elif raw[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                     b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        matched.add("Mach-O")
        add_finding(report, "embedded_signature", "high",
                    "Mach-O executable header — requires sandbox analysis.")
    elif raw[:4] == b"\xca\xfe\xba\xbe":
        kind = _classify_cafebabe(raw)
        matched.add(kind)
        add_finding(report, "embedded_signature", "high",
                    f"{kind} header (executable code) — requires sandbox analysis.")
    elif raw.startswith(b"PK\x03\x04"):
        matched.add("ZIP")
        if suffix in SAFE_ZIP_SUFFIXES:
            report.setdefault("encoding", {})["container"] = (
                f"zip-based container ({suffix}) — structural expectation met")
        elif suffix in RISKY_ZIP_SUFFIXES:
            if suffix in {".docm", ".xlsm", ".pptm"}:
                add_finding(report, "embedded_signature", "medium",
                            f"macro-enabled Office document ({suffix}) — "
                            f"VBA macros execute on open; inspect before opening")
            else:
                add_finding(report, "embedded_signature", "medium",
                            f"zip-based container ({suffix}) — may carry "
                            f"executable or macro content; inspect before opening")
        else:
            add_finding(report, "embedded_signature", "medium",
                        "ZIP archive at file start — inspect contents before "
                        "opening; archives can nest executables.")
    elif raw.startswith(b"%PDF-"):
        matched.add("PDF")
        add_finding(report, "embedded_signature", "medium",
                    "PDF document — PDFs can embed JavaScript and exploits; "
                    "open only in an isolated viewer if trusted.")
    else:
        fmt = _known_binary_format(raw)
        if fmt:
            matched.add(fmt)
            report.setdefault("encoding", {})["format"] = fmt
    return matched


# ======================================================================
# SECTION 6: TEXT-LEVEL ANALYSIS
# ======================================================================

def read_bounded(path: Path, limit: int) -> tuple[bytes, bool]:
    with path.open("rb") as fh:
        data = fh.read(limit + 1)
    return data[:limit], len(data) > limit


def decode_text(raw: bytes) -> tuple[str, bool]:
    """Returns (text, valid_utf8). NUL or invalid UTF-8 marks binary."""
    if b"\x00" in raw:
        return "", False
    try:
        return raw.decode("utf-8"), True
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace"), False


def analyze_unicode_chars(text: str, report: dict[str, Any]) -> None:
    """Line/col-precise scan for hidden/dangerous Unicode."""
    if text.isascii():          # C-speed short-circuit
        return
    line_no, col = 1, 0
    invisible_count = 0
    for ch in text:
        if ch == "\n":
            line_no += 1
            col = 0
            continue
        col += 1
        cp = ord(ch)
        if cp < 0x80:
            continue
        sev = label = None
        # HIGH: prompt-injection / Trojan-Source class
        if 0xE0000 <= cp <= 0xE007F:
            sev, label = "high", (f"Unicode TAG character U+{cp:04X} — "
                                  f"invisible, machine-readable, "
                                  f"prompt-injection vector")
        elif ch in BIDI_OVERRIDE:
            sev, label = "high", (f"bidirectional override "
                                  f"{BIDI_OVERRIDE[ch]} (Trojan-Source class: "
                                  f"display differs from logic)")
        elif ch in ZERO_WIDTH:
            sev, label = "high", f"zero-width character {ZERO_WIDTH[ch]}"
        elif ch == ZWNBSP:
            sev, label = "high", "zero-width no-break space outside BOM position"
        # MEDIUM: suspicious but contextually legitimate
        elif 0xE0100 <= cp <= 0xE01EF:
            sev, label = "medium", (f"variation selector supplement U+{cp:04X} "
                                    f"— invisible; can encode hidden data")
        elif ch == SOFT_HYPHEN:
            sev, label = "medium", "soft hyphen (invisible in most renderers)"
        elif ch in DIRECTIONAL_MARKS:
            sev, label = "medium", (f"directional mark "
                                    f"{DIRECTIONAL_MARKS[ch]} "
                                    f"(legitimate in RTL text; verify context)")
        elif ch in HOMOGLYPHS:
            sev, label = "medium", f"lookalike character: {HOMOGLYPHS[ch]}"
        elif unicodedata.category(ch) == "Cf":
            sev, label = "medium", f"Unicode format control U+{cp:04X}"
        if sev:
            invisible_count += 1
            add_finding(report, "unicode", sev, label, line=line_no,
                        evidence=f"line {line_no}, column {col}: U+{cp:04X}")

    if invisible_count >= 3:
        add_finding(report, "unicode", "medium",
                    f"{invisible_count} invisible/suspicious characters total "
                    f"— what you see may not be what the file actually contains")


def analyze_patterns(text: str, report: dict[str, Any]) -> None:
    for line_no, line in enumerate(text.splitlines(), 1):
        for category, pattern in PATTERN_MEDIUM.items():
            if pattern.search(line):
                add_finding(report, category, "medium",
                            f"indicator: {category} (word-level match; "
                            f"not proof of intent)", line=line_no, evidence=line)
        for name, pattern in PATTERN_HIGH:
            if pattern.search(line):
                add_finding(report, name, "high",
                            f"high-risk construct: {name}",
                            line=line_no, evidence=line)


def _try_b64_decode(blob: str) -> bytes | None:
    """Best-effort decode with padding correction. Hex-output use only."""
    candidates = [blob]
    pad = -len(blob) % 4
    if pad:
        candidates.append(blob + "=" * pad)
    for candidate in candidates:
        try:
            return base64.b64decode(candidate, validate=False)
        except Exception:
            continue
    return None


def analyze_base64_blobs(text: str, report: dict[str, Any]) -> None:
    """Report long base64-like blobs. Decode to HEX ONLY — never execute."""
    for match in list(B64_BLOB_RE.finditer(text))[:10]:
        blob = match.group(0)
        decoded = _try_b64_decode(blob)
        if decoded is None:
            note = "not decodable as standard base64"
        else:
            note = f"decodes to: {decoded[:32].hex()}..."
        add_finding(report, "base64_blob", "medium",
                    f"base64-like block ({len(blob)} chars); {note}",
                    evidence=blob[:120])


def analyze_entropy(raw: bytes, matched: set[str],
                    report: dict[str, Any]) -> None:
    """Record byte entropy for every file; flag only *unrecognized*
    high-entropy binaries (likely encrypted/packed). Recognized formats
    (PNG, JPEG, ZIP...) legitimately carry high entropy."""
    if len(raw) < 1024:
        return
    counts = Counter(raw)
    n = len(raw)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    report.setdefault("encoding", {})["entropy_bits_per_byte"] = round(entropy, 3)
    if (entropy > 7.5 and not matched
            and not report["encoding"].get("utf8_valid")):
        add_finding(report, "entropy", "medium",
                    f"unrecognized binary with high entropy "
                    f"({entropy:.2f} bits/byte) — likely encrypted or "
                    f"packed; requires sandbox analysis")


def analyze_structure(text: str, report: dict[str, Any]) -> None:
    lines = text.splitlines()
    crlf = text.count("\r\n")
    report["structure"] = {
        "line_count": len(lines),
        "max_line_length": max((len(ln) for ln in lines), default=0),
        "tab_lines": sum(1 for ln in lines if "\t" in ln),
        "crlf_lines": crlf,
    }
    truncated = report.get("encoding", {}).get("truncated", False)
    for number, line in enumerate(lines, 1):
        if len(line) > 500:
            note = " (file truncated; may be one long line split)" if truncated else ""
            add_finding(report, "structure", "medium",
                        f"unusually long line ({len(line)} chars){note}",
                        line=number, evidence=line[:200])
            break  # one representative finding is enough


def analyze_syntax(path: Path, text: str, report: dict[str, Any],
                   cfg: dict[str, Any]) -> None:
    if not text:
        return
    suffix = path.suffix.lower()
    truncated = report.get("encoding", {}).get("truncated", False)
    if suffix == ".py":
        try:
            compile(text, str(path), "exec")
            report["syntax"] = {"python": "valid"}
        except SyntaxError as exc:
            note = " (file was truncated for analysis)" if truncated else ""
            add_finding(report, "syntax", "medium",
                        f"Python syntax error: {exc.msg}{note}",
                        line=exc.lineno)
    elif suffix in {".sh", ".bash"}:
        res = run_command(["bash", "-n", str(path)], cfg["timeouts"]["bash"])
        report["syntax"] = {"bash": res}
        if res.get("status") == "timeout":
            add_finding(report, "syntax", "low", "bash -n timed out.")
        elif res.get("return_code") not in (None, 0):
            note = " (file was truncated for analysis)" if truncated else ""
            add_finding(report, "syntax", "medium",
                        f"Bash syntax validation failed{note}",
                        evidence=res.get("stderr"))
        if cfg["scanners"]["shellcheck"]:
            sc = run_command(["shellcheck", str(path)],
                             cfg["timeouts"]["shellcheck"])
            report["syntax"]["shellcheck"] = sc
            if sc.get("return_code") == 1:
                add_finding(report, "syntax", "medium",
                            "ShellCheck reported issues.",
                            evidence=sc.get("stdout"))
            elif sc.get("return_code") not in (None, 0, 1):
                add_finding(report, "syntax", "low",
                            f"ShellCheck error (rc={sc.get('return_code')}).")


def run_external_scanners(path: Path, report: dict[str, Any],
                          cfg: dict[str, Any]) -> None:
    """ClamAV with correct rc semantics: 0 clean, 1 detection, 2+ error."""
    if not cfg["scanners"]["clamav"]:
        return
    res = run_command(["clamscan", "--no-summary", str(path)],
                      cfg["timeouts"]["clamav"])
    report["scanners"] = {"clamav": res}
    rc = res.get("return_code")
    if rc == 1:
        add_finding(report, "antivirus", "high",
                    "ClamAV reported a detection.",
                    evidence=res.get("stdout") or res.get("stderr"))
    elif res.get("status") == "timeout":
        add_finding(report, "antivirus", "medium",
                    "ClamAV scan timed out — result unverified.")
    elif rc is not None and rc != 0:
        add_finding(report, "antivirus", "medium",
                    f"ClamAV scan error (rc={rc}) — result unverified; "
                    f"check scanner health.")


def analyze_file(path: Path, report: dict[str, Any],
                 cfg: dict[str, Any]) -> None:
    """Orchestrator. Pure static analysis; path is the read-only copy."""
    raw, truncated = read_bounded(path, TEXT_ANALYSIS_LIMIT)
    text, valid_utf8 = decode_text(raw)
    binary = not valid_utf8

    mime = None
    if shutil.which("file"):
        fr = run_command(["file", "--brief", "--mime-type", str(path)],
                         cfg["timeouts"]["file"])
        if fr.get("available") and fr.get("return_code") == 0:
            mime = fr["stdout"].strip() or None

    report["encoding"] = {
        "utf8_valid": valid_utf8,
        "binary_indicator": binary,
        "truncated": truncated,
        "declared_mime": mime,
    }
    if truncated:
        add_finding(report, "structure", "low",
                    f"file exceeded {TEXT_ANALYSIS_LIMIT} bytes; text analysis "
                    f"covered the first {TEXT_ANALYSIS_LIMIT} bytes only")

    matched = analyze_header_signatures(raw, path.suffix.lower(), report)

    if truncated and path.stat().st_size > cfg["max_input_bytes"]:
        add_finding(report, "structure", "medium",
                    "file exceeds configured max_input_bytes")

    # MIME cross-checks: declared type vs actual content
    if mime and binary and mime.startswith("text/"):
        add_finding(report, "encoding", "medium",
                    "libmagic declares text but file contains binary/invalid-"
                    "UTF-8 bytes — possible disguised content")
    if (mime and not binary and not matched and mime in
            ("application/x-executable", "application/x-sharedlib",
             "application/x-dosexec", "application/x-mach-binary")):
        add_finding(report, "encoding", "medium",
                    f"libmagic reports executable ({mime}) but no executable "
                    f"header signature matched — inspect manually")

    analyze_entropy(raw, matched, report)

    if not binary:
        # BOM policy: BOM at offset 0 is benign; strip before scanning.
        if text.startswith(ZWNBSP):
            report["encoding"]["bom"] = True
            text = text[1:]
        if raw.find(b"PK\x03\x04", 1) != -1 and "ZIP" not in matched:
            add_finding(report, "embedded_signature", "medium",
                        "embedded ZIP stream inside a text file — possible "
                        "smuggled archive")
        if text.startswith("#!"):
            add_finding(report, "structure", "medium",
                        "shebang: file declares itself an executable script",
                        evidence=text.splitlines()[0])
        analyze_unicode_chars(text, report)
        analyze_patterns(text, report)
        analyze_base64_blobs(text, report)
        analyze_structure(text, report)
        report["indicators"] = {
            "urls": sorted(set(URL_RE.findall(text)))[:50],
            "ips": sorted(set(IP_RE.findall(text)))[:50],
        }
        analyze_syntax(path, text, report, cfg)
    else:
        if not matched:
            add_finding(report, "encoding", "medium",
                        "binary file with no recognized format — unknown "
                        "content, review before opening")

    run_external_scanners(path, report, cfg)


# ======================================================================
# SECTION 7: DATABASE (SQLite reporting)
# ======================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    run_id TEXT UNIQUE,
    original_name TEXT,
    safe_name TEXT,
    sha256 TEXT,
    size INTEGER,
    risk TEXT,
    finding_count INTEGER,
    destination TEXT,
    json_report TEXT,
    markdown_report TEXT,
    started_at TEXT,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_sha ON scans(sha256);
CREATE INDEX IF NOT EXISTS idx_scans_risk ON scans(risk);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    severity TEXT, category TEXT, description TEXT,
    line INTEGER, evidence TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT, event TEXT, name TEXT, detail TEXT
);
"""


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def seen_hash(self, sha256: str) -> sqlite3.Row | None:
        cur = self.conn.execute(
            "SELECT run_id, risk, finished_at FROM scans "
            "WHERE sha256 = ? ORDER BY id DESC LIMIT 1", (sha256,))
        return cur.fetchone()

    def record_scan(self, report: dict[str, Any], destination: Path | None,
                    json_path: Path | None, md_path: Path | None) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (run_id, original_name, safe_name, sha256, size,"
            " risk, finding_count, destination, json_report, markdown_report,"
            " started_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (report.get("run_id"), report.get("original_name"),
             report.get("claimed_name"), report.get("sha256"),
             report.get("size"), report.get("risk", "workflow-failure"),
             len(report.get("findings", [])),
             str(destination) if destination else None,
             str(json_path) if json_path else None,
             str(md_path) if md_path else None,
             report.get("started"), report.get("finished")))
        self.conn.commit()
        scan_id = int(cur.lastrowid)
        self.record_findings(scan_id, report.get("findings", []))
        return scan_id

    def record_findings(self, scan_id: int, findings: list[dict[str, Any]]) -> None:
        self.conn.executemany(
            "INSERT INTO findings (scan_id, severity, category, description,"
            " line, evidence) VALUES (?,?,?,?,?,?)",
            [(scan_id, f.get("severity"), f.get("category"),
              f.get("description"), f.get("line"), f.get("evidence"))
             for f in findings])
        self.conn.commit()

    def record_event(self, event: str, name: str, detail: str) -> None:
        self.conn.execute(
            "INSERT INTO events (timestamp, event, name, detail) "
            "VALUES (?,?,?,?)", (utc_now(), event, name, detail))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


def append_event(paths: Paths, event: dict[str, Any]) -> None:
    log_path = paths.logs / "events.jsonl"
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")


# ======================================================================
# SECTION 8: REPORTS AND ROUTING
# ======================================================================

def write_reports(paths: Paths, run_id: str,
                  report: dict[str, Any]) -> tuple[Path, Path]:
    json_path = paths.reports / f"{run_id}.json"
    md_path = paths.reports / f"{run_id}.md"
    json_path.write_text(json.dumps(report, indent=2, default=str),
                         encoding="utf-8")

    findings = report.get("findings", [])
    risk = report.get("risk", "?")
    original_name = report.get("original_name", "?")

    MEANING = {
        "unicode": "Invisible or lookalike characters — what you see may not "
                   "be what the file contains. Often a paste artifact, "
                   "sometimes deliberate. Check line/column in raw findings.",
        "download_command": "The word 'curl'/'wget'/etc appears. By itself "
                            "this is prose mention, not a threat.",
        "shell_reference": "Mention of bash/sh/shell. Legitimate in docs and scripts.",
        "encoded_content": "Mention of base64/encoding. Check whether the file "
                           "is decoding *to run*, not just decoding to display.",
        "network_reference": "URLs, IPs, or network libraries.",
        "dynamic_loading": "Dynamic import/loading reference. Normal in some "
                           "code, suspicious in documents.",
        "persistence_reference": "Mentions of cron/systemd/autostart — check if "
                                 "the file claims to install itself.",
        "download_pipe_shell": "HIGH-RISK: download piped directly to shell "
                               "(curl URL | bash). Classic remote execution.",
        "base64_decode_pipe_shell": "HIGH-RISK: base64 decoding piped to shell.",
        "eval_encoded": "HIGH-RISK: eval on encoded content.",
        "bash_network_redirect": "HIGH-RISK: /dev/tcp or /dev/udp — bash "
                                 "network communication, often reverse shells.",
        "netcat_exec": "HIGH-RISK: netcat with execute flag — remote shell.",
        "recursive_delete_root": "HIGH-RISK: recursive delete of / or ~.",
        "powershell_download_cradle": "HIGH-RISK: PowerShell download-and-execute pattern.",
        "embedded_signature": "Executable header detected (ELF/PE/Mach-O/ZIP/PDF). "
                              "Requires sandbox review — never open normally.",
        "entropy": "High randomness — likely encrypted or packed content.",
        "base64_blob": "Base64-encoded block — decoded to hex for the report; "
                       "the tool never executes it.",
        "structure": "File layout quirks (long lines, shebang, truncation).",
        "syntax": "Python/bash syntax issue — check line numbers in raw findings.",
        "antivirus": "ClamAV finding — treat as high-priority review.",
        "integrity": "Analysis copy changed mid-scan — investigate immediately.",
        "encoding": "Encoding or format mismatch — the file's declared type "
                    "differs from its actual content.",
        "scanner": "External scanner unavailable or failed — result unverified.",
    }

    rows = [
        "# File Triage Report", "",
        f"- **Run ID:** `{run_id}`",
        f"- **Risk:** `{risk.upper()}`",
        f"- **Original name:** `{original_name}`",
        f"- **SHA-256:** `{report.get('sha256', '?')}`",
        f"- **Size:** {report.get('size', '?')} bytes",
        f"- **Tool version:** {__version__}", "",
        "## What this means", "",
    ]

    if not findings:
        rows += [
            "**No indicators found.** This is not proof of safety — it means "
            "the enabled checks found nothing suspicious.", "",
            "**Recommended action:** safe to use.", "",
        ]
    else:
        by_cat: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            by_cat.setdefault(f.get("category", "?"), []).append(f)

        rows += [f"**{risk.upper()} risk** — {len(findings)} finding(s). "
                 "Read the groups below, then the recommended action.", ""]

        for cat, items in sorted(by_cat.items()):
            sev_counts: dict[str, int] = {}
            for f in items:
                sev = f.get("severity", "?")
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            sev_str = ", ".join(f"{s}×{n}" for s, n in sev_counts.items())
            meaning = MEANING.get(cat, "Review the raw finding lines below.")
            rows.append(f"### {cat} ({sev_str})")
            rows.append(meaning)
            rows.append("")

        rows += ["**Recommended action:**"]
        if risk == "high":
            rows += ["Do **not** open normally. Inspect via the report only. "
                     "If it's an executable, use a disposable VM."]
        elif risk == "medium":
            rows += ["Read the findings above, then open in a text editor "
                     "(not a viewer) and verify the flagged lines. If "
                     "anything is unfamiliar, don't execute it."]
        elif risk in ("clean", "low"):
            rows += ["Safe to use. This is not proof of safety — use common sense."]
        elif risk == "workflow-failure":
            rows += ["Scan didn't complete. Retry, or check the error in the "
                     "raw report. **Do not assume this file is clean.**"]
        rows += [""]

        rows += ["## Findings (raw)", "",
                 "| Severity | Category | Description | Line |",
                 "|---|---|---|---:|"]
        for f in findings:
            desc = str(f.get("description", "")).replace("|", "\\|")
            cat = str(f.get("category", "")).replace("|", "\\|")
            rows.append(f"| {f.get('severity')} | {cat} | {desc} | "
                        f"{f.get('line', '')} |")

    ind = report.get("indicators", {})
    if ind.get("urls") or ind.get("ips"):
        rows += ["", "## Indicators (informational)", ""]
        for u in ind.get("urls", [])[:20]:
            rows.append(f"- URL: `{u}`")
        for i in ind.get("ips", [])[:20]:
            rows.append(f"- IP: `{i}`")

    if report.get("duplicate_of"):
        d = report["duplicate_of"]
        rows += ["", f"**Duplicate** of earlier scan `{d['run_id']}` "
                  f"(risk: {d['risk']})."]

    rows += ["", "## Handling", "",
             "- This file was never executed; analysis used a read-only copy.",
             "- High-risk files stay in quarantine until manually reviewed.",
             "- A clean result is not proof of safety.", ""]
    md_path.write_text("\n".join(rows), encoding="utf-8")
    return json_path, md_path


def apply_sort_rules(original_name: str, rules: list[dict[str, Any]],
                     clean_root: Path) -> Path:
    """First matching rule wins; destinations are pre-validated single-level."""
    for rule in rules:
        pats = rule["match"] if isinstance(rule["match"], list) else [rule["match"]]
        if any(fnmatch.fnmatch(original_name, p) for p in pats):
            dest = clean_root / rule["destination"]
            dest.mkdir(parents=True, exist_ok=True)
            return dest
    return clean_root


def route_by_risk(claimed: Path, paths: Paths, cfg: dict[str, Any],
                  report: dict[str, Any]) -> Path:
    risk = report["risk"]
    target = cfg["routing"].get(risk, "errors")
    dest_dir = paths.by_name[target]
    if risk in ("clean", "low"):
        dest_dir = apply_sort_rules(report.get("original_name", claimed.name),
                                    cfg["sort_rules"], dest_dir)
    destination = unique_destination(dest_dir, claimed.name)
    os.replace(claimed, destination)
    return destination


# ======================================================================
# SECTION 9: STABILITY, CLAIMING, RECOVERY, RETENTION
# ======================================================================

def select_stable_files(inbox: Path, *, checks: int, interval: float,
                        ignore_patterns: list[str]
                        ) -> tuple[list[Path], list[Path]]:
    """Batched passes; a file is stable only after `checks` consecutive
    identical (size, mtime_ns) samples. Non-regular entries are returned
    as `rejected` for routing to errors/."""
    survivors: dict[Path, tuple[int, int]] | None = None
    last_seen: dict[Path, tuple[int, int] | None] = {}
    for pass_no in range(checks):
        last_seen = {}
        try:
            entries = sorted(inbox.iterdir())
        except FileNotFoundError:
            return [], []
        for path in entries:
            if any(fnmatch.fnmatch(path.name, pat) for pat in ignore_patterns):
                continue
            try:
                st = os.lstat(path)          # lstat: never follows symlinks
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(st.st_mode):
                last_seen[path] = None       # symlink/fifo/dir → rejected
            else:
                last_seen[path] = (st.st_size, st.st_mtime_ns)
        if survivors is None:
            survivors = {p: s for p, s in last_seen.items() if s is not None}
        else:
            survivors = {p: s for p, s in last_seen.items()
                         if s is not None and survivors.get(p) == s}
        if pass_no < checks - 1:
            time.sleep(interval)
    stable = list(survivors or [])
    rejected = [p for p, s in last_seen.items() if s is None]
    return stable, rejected


def claim_file(path: Path, processing: Path) -> Path | None:
    """Atomic rename into processing/. Success = this worker owns the file."""
    name = safe_name(path.name)
    dest = processing / name
    if dest.exists():
        stem, suffix = dest.stem, dest.suffix
        dest = processing / f"{stem}-{uuid.uuid4().hex[:12]}{suffix}"
    try:
        os.replace(path, dest)
    except OSError:
        return None
    return dest


def handle_rejected(path: Path, paths: Paths, db: Database) -> None:
    """Non-regular entries leave the inbox; directories are reported."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(st.st_mode):
        db.record_event("inbox-directory-ignored", path.name,
                        "directories are not processed; remove manually")
        print(f"[inbox] directory left in place: {path.name}", file=sys.stderr)
        return
    try:
        dest = unique_destination(paths.errors, path.name)
        os.replace(path, dest)
        db.record_event("rejected", path.name, "not-a-regular-file")
        append_event(paths, {"timestamp": utc_now(), "event": "rejected",
                             "name": path.name,
                             "reason": "not-a-regular-file",
                             "destination": str(dest)})
    except OSError as exc:
        db.record_event("rejection-failed", path.name, str(exc))


def recover_processing(paths: Paths, db: Database) -> int:
    """With the lock held, everything in processing/ is from a crashed
    run. Move it to errors/ so nothing is stranded."""
    recovered = 0
    for p in list(paths.processing.iterdir()):
        try:
            dest = unique_destination(paths.errors, p.name)
            os.replace(p, dest)
            db.record_event("recovered", p.name, str(dest))
            append_event(paths, {"timestamp": utc_now(), "event": "recovered",
                                 "name": p.name, "destination": str(dest)})
            recovered += 1
        except OSError:
            continue
    return recovered


def sweep_analysis_retention(paths: Paths, days: int) -> int:
    """Delete analysis copies older than `days`. Reports and DB remain."""
    if days <= 0:
        return 0
    cutoff = time.time() - days * 86400
    base = paths.reports / "analysis"
    if not base.exists():
        return 0
    removed = 0
    for d in base.iterdir():
        try:
            if d.is_dir() and d.stat().st_mtime < cutoff:
                shutil.rmtree(d, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    return removed


# ======================================================================
# SECTION 10: PER-FILE PIPELINE
# ======================================================================

def process_one(claimed: Path, paths: Paths, cfg: dict[str, Any],
                db: Database, original_name: str) -> str:
    started = utc_now()
    run_id = (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
              + "-" + uuid.uuid4().hex[:10])
    report: dict[str, Any] = {
        "run_id": run_id, "started": started, "tool_version": __version__,
        "original_name": original_name,
        "claimed_name": claimed.name, "findings": [],
        "_category_counts": {}, "_suppressed": {},
    }
    try:
        st = claimed.stat()
        report["size"] = st.st_size

        # Defense-in-depth: strip execute bits from the claimed file.
        # (Content is never modified; only permission bits change.)
        try:
            claimed.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

        # Hard size limit — reject before any heavy work.
        if st.st_size > cfg["max_input_bytes"]:
            destination = unique_destination(paths.errors, claimed.name)
            os.replace(claimed, destination)
            db.record_event("rejected", original_name, "exceeds-size-limit")
            append_event(paths, {"timestamp": utc_now(), "event": "rejected",
                                 "original_name": original_name,
                                 "reason": "exceeds-size-limit",
                                 "size": st.st_size,
                                 "destination": str(destination)})
            return "rejected"

        sha = sha256_file(claimed)
        report["sha256"] = sha

        # Dedup on content hash.
        prior = db.seen_hash(sha) if cfg["dedup"]["enabled"] else None
        if prior is not None:
            if cfg["dedup"]["action"] == "route":
                destination = unique_destination(paths.duplicates, claimed.name)
                os.replace(claimed, destination)
                db.record_event("duplicate-routed", original_name,
                                f"prior run {prior['run_id']}")
                append_event(paths, {"timestamp": utc_now(),
                                     "event": "duplicate-routed",
                                     "original_name": original_name,
                                     "sha256": sha,
                                     "prior_run_id": prior["run_id"],
                                     "destination": str(destination)})
                return "duplicate-routed"
            report["duplicate_of"] = {"run_id": prior["run_id"],
                                      "risk": prior["risk"]}

        if cfg["keep_analysis_copy"]:
            analysis_dir = paths.reports / "analysis" / run_id
            analysis_dir.mkdir(parents=True, exist_ok=True)
            analysis_path = analysis_dir / safe_name(claimed.name)
            shutil.copy2(claimed, analysis_path)
            analysis_path.chmod(stat.S_IRUSR)   # read-only analysis copy
        else:
            analysis_path = claimed

        before = sha256_file(analysis_path)
        analyze_file(analysis_path, report, cfg)
        after = sha256_file(analysis_path)
        report["analysis_hash_before"] = before
        report["analysis_hash_after"] = after
        if before != after:
            add_finding(report, "integrity", "high",
                        "Analysis copy changed during scanning — "
                        "investigate immediately.")

        _finalize_suppressed(report)
        report["risk"] = determine_risk(report)
        report["finished"] = utc_now()

        json_path, md_path = write_reports(paths, run_id, report)
        destination = route_by_risk(claimed, paths, cfg, report)
        db.record_scan(report, destination, json_path, md_path)

        append_event(paths, {
            "timestamp": utc_now(), "event": "routed", "run_id": run_id,
            "original_name": original_name, "sha256": sha,
            "risk": report["risk"], "finding_count": len(report["findings"]),
            "destination": str(destination), "json_report": str(json_path),
        })
        db.record_event("routed", original_name,
                        f"{report['risk']} -> {destination}")
        _notify_if_needed(report["risk"], original_name, run_id, cfg)
        # One-line verdict for the operator
        cats: dict[str, int] = {}
        for f in report["findings"]:
            key = f.get("category", "?")
            cats[key] = cats.get(key, 0) + 1
        reason = ", ".join(f"{c}×{n}" for c, n in
                          sorted(cats.items(), key=lambda kv: -kv[1])[:4]) \
                 or "no findings"
        print(f"  {report['risk'].upper():8s} {original_name:40s} → "
              f"{destination.parent.name:12s} [{reason}]", file=sys.stderr)
        return report["risk"]

    except Exception as exc:  # defensive: a file must never be lost
        report["risk"] = "workflow-failure"
        report["error"] = f"{type(exc).__name__}: {exc}"
        report["finished"] = utc_now()
        _finalize_suppressed(report)
        destination = None
        try:
            destination = unique_destination(paths.errors, claimed.name)
            os.replace(claimed, destination)
        except OSError:
            destination = claimed
        try:
            db.record_scan(report, destination, None, None)
        except sqlite3.Error:
            pass
        append_event(paths, {"timestamp": utc_now(), "event": "error",
                             "run_id": run_id, "original_name": original_name,
                             "error": report["error"],
                             "destination": str(destination)})
        db.record_event("error", original_name, report["error"])
        _notify_if_needed("workflow-failure", original_name, run_id, cfg)
        return "workflow-failure"


def process_cycle(paths: Paths, cfg: dict[str, Any],
                  db: Database) -> dict[str, int]:
    summary = {"processed": 0, "clean": 0, "findings": 0, "failures": 0,
               "rejected": 0, "duplicates": 0}
    stable, rejected = select_stable_files(
        paths.inbox, checks=cfg["stability"]["checks"],
        interval=cfg["stability"]["interval"],
        ignore_patterns=cfg["ignore_patterns"])
    for p in rejected:
        handle_rejected(p, paths, db)
        summary["rejected"] += 1
    for p in stable:
        original_name = p.name
        claimed = claim_file(p, paths.processing)
        if claimed is None:
            continue
        risk = process_one(claimed, paths, cfg, db, original_name)
        summary["processed"] += 1
        if risk in ("clean", "low"):
            summary["clean"] += 1
        elif risk in ("medium", "high"):
            summary["findings"] += 1
        elif risk in ("workflow-failure", "rejected"):
            summary["failures"] += 1
        elif risk == "duplicate-routed":
            summary["duplicates"] += 1
    return summary


def exit_code_from(summary: dict[str, int]) -> int:
    if summary["failures"]:
        return EXIT_FAILURE
    if summary["findings"] or summary["rejected"]:
        return EXIT_FINDINGS
    return EXIT_OK


# ======================================================================
# SECTION 11: CLI
# ======================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safe static file triage: inbox -> analyze -> route.")
    parser.add_argument("--root", type=Path, default=Path("data"),
                        help="Root directory (default ./data).")
    parser.add_argument("--config", type=Path,
                        help="JSON config file (see --print-default-config).")
    parser.add_argument("--db", type=Path,
                        help="Override SQLite path (default <root>/logs/triage.db).")
    parser.add_argument("--once", action="store_true",
                        help="Process current inbox, then exit.")
    parser.add_argument("--watch", action="store_true",
                        help="Poll the inbox continuously.")
    parser.add_argument("--interval", type=float, default=5.0,
                        help="Watch polling interval seconds (default 5).")
    parser.add_argument("--file", type=Path,
                        help="Single-file mode: copy FILE into the inbox and "
                             "run one cycle (symlinks rejected before copy).")
    parser.add_argument("--print-default-config", action="store_true")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    if args.print_default_config:
        print(json.dumps(DEFAULT_CONFIG, indent=2))
        return 0
    if args.interval <= 0:
        parser.error("--interval must be positive")

    cfg = load_config(args.config)
    root = args.root.expanduser().resolve()
    paths = Paths(root)
    verify_same_filesystem(paths)

    single_file = False
    if args.file is not None:
        src = args.file.expanduser()
        try:
            st = os.lstat(src)               # lstat BEFORE any copy
        except FileNotFoundError:
            print(f"FATAL: no such file: {src}", file=sys.stderr)
            return EXIT_FAILURE
        if stat.S_ISLNK(st.st_mode):
            print("FATAL: symbolic links are not accepted as input.",
                  file=sys.stderr)
            return EXIT_FAILURE
        if not stat.S_ISREG(st.st_mode):
            print("FATAL: input must be a regular file.", file=sys.stderr)
            return EXIT_FAILURE
        if st.st_size > cfg["max_input_bytes"]:
            print(f"FATAL: file exceeds max_input_bytes "
                  f"({cfg['max_input_bytes']}).", file=sys.stderr)
            return EXIT_FAILURE
        shutil.copy2(src, unique_destination(paths.inbox, src.name))
        single_file = True

    if not args.once and not args.watch and not single_file:
        parser.error("specify --once, --watch, or --file")

    db_path = (args.db.expanduser().resolve() if args.db
               else paths.logs / "triage.db")

    with instance_lock(root):
        db = Database(db_path)
        try:
            recovered = recover_processing(paths, db)
            if recovered:
                print(f"[startup] recovered {recovered} file(s) from "
                      f"processing/ into errors/")
            sweep_analysis_retention(paths, cfg["retention_days_analysis"])

            if args.once or single_file:
                summary = process_cycle(paths, cfg, db)
                print(f"[done] processed={summary['processed']} "
                      f"clean={summary['clean']} findings={summary['findings']} "
                      f"failures={summary['failures']} "
                      f"rejected={summary['rejected']} "
                      f"duplicates={summary['duplicates']}")
                return exit_code_from(summary)

            # --watch
            print(f"[watch] root={root} db={db_path} "
                  f"interval={args.interval}s (Ctrl-C to stop)")
            degraded = 0
            cycle = 0
            while True:
                cycle += 1
                try:
                    summary = process_cycle(paths, cfg, db)
                except Exception as exc:             # keep the watcher alive
                    summary = {"processed": 0, "clean": 0, "findings": 0,
                               "failures": 1, "rejected": 0, "duplicates": 0}
                    db.record_event("cycle-error", "-", repr(exc))
                if summary["failures"]:
                    degraded += 1
                    if degraded >= cfg["watch"]["degraded_after"]:
                        db.record_event("watch-degraded", "-",
                                        json.dumps(summary))
                        append_event(paths, {"timestamp": utc_now(),
                                             "event": "watch-degraded",
                                             "summary": summary})
                        degraded = 0
                else:
                    degraded = 0
                if cycle % 60 == 0:
                    sweep_analysis_retention(paths, cfg["retention_days_analysis"])
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[watch] stopped by user")
            return EXIT_OK
        finally:
            db.close()


if __name__ == "__main__":
    raise SystemExit(main())
