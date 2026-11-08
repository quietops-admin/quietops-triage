# QuietOps Triage

A self-sorting, security-triaging INBOX. Every file that lands in it is
scanned statically, logged to a database, and routed by risk. Nothing is
ever executed, imported, or rendered to find out what it is.

**Owner:** QuietOps Labs · **Version:** 2.0.1 · **Runtime:** Python 3.10+, Linux/macOS

---

## 2. My original idea → what the system actually does

| The idea | Implemented as |
|---|---|
| File lands in INBOX | `data/inbox/` — drop, download, or create files here |
| Triggers the triage scan | `--watch` polls every 5 s; `--once` for manual runs |
| Results stored in database | SQLite `triage.db` + JSON/Markdown reports + JSONL audit log |
| Fail → quarantine + alert | high → `data/quarantine/`, medium → `data/review/` (desktop alert: v2.1, §12) |
| Pass → sort by rules, logged | clean/low → `data/sorted/`, plus `sort_rules` subfolders |
| Keep watching the failed folder & logs | `data/logs/events.jsonl` + DB queries (§7) |

## 3. Directory layout

### The project (the code — safe to publish)

    quietops-triage-2.1.1/
    ├── inbox_triage.py          ← the entire engine + controller
    ├── config.example.json      ← copy to config.json, edit to taste
    ├── README.md                ← this file
    ├── CHANGELOG.md
    ├── tests/
    │   └── test_inbox_triage.py ← ~50 tests; run before every change
    ├── scripts/
    │   └── validate.sh          ← end-to-end acceptance check
    ├── deploy/
    │   └── inbox-triage.service ← systemd unit (optional always-on mode)
    └── .github/workflows/ci.yml ← CI (optional, for GitHub)

### The runtime (the data — NEVER publish, NEVER commit)

    data/
    ├── inbox/        files waiting to be scanned (I put things here)
    ├── processing/   file currently being scanned (exists only mid-scan)
    ├── sorted/       passed triage — sorted by my sort_rules
    ├── review/       medium risk — needs my eyes before I trust it
    ├── quarantine/   high risk — do not open; inspect reports instead
    ├── errors/       rejected (oversized, symlink, crash) — never lost
    ├── duplicates/   repeat content, when dedup action = "route"
    ├── reports/
    │   ├── <run-id>.json   machine-readable, full detail
    │   ├── <run-id>.md     human-readable summary
    │   └── analysis/<run-id>/  the read-only copy that was scanned
    └── logs/
        ├── triage.db       the database of every scan (§7)
        └── events.jsonl    one line per routing/rejection/recovery

## 4. Order of operations — the life of a file

1. **Lands in `inbox/`** — by hand, by download, or created there by a script.
2. **Stability wait** — the file must show the same size + mtime twice
   (1 s apart by default), so half-written downloads are never scanned.
   Browser temp names (`*.part`, `*.crdownload`, …) are ignored entirely.
3. **Sanity gate** — symlinks, FIFOs, and directories are routed to
   `errors/` and logged. They are never followed.
4. **Atomic claim** — the file is renamed into `processing/`. From this
   moment the pipeline owns it; two workers can never double-process it.
5. **Execute bits stripped** (permission bits only — content untouched).
6. **Size check** — over `max_input_bytes` → `errors/`, logged, done.
7. **SHA-256 recorded** — the file's permanent identity from here on.
8. **Duplicate check** — hash already in the DB? Noted, or routed to
   `duplicates/` (my setting: log only).
9. **Read-only copy** created under `reports/analysis/<run-id>/` — the
   copy is what gets scanned, never the original.
10. **Static analysis**, in order: bounded read (first 10 MiB) → UTF-8
    validation → libmagic MIME → header signatures (ELF/PE/Mach-O/Java/
    ZIP/PDF + 16 known formats, header-position only) → MIME cross-check
    → byte entropy → BOM handling → embedded ZIP stream check → shebang
    → Unicode scan (bidi overrides, zero-width, homoglyphs, soft hyphens)
    → word-level indicators (medium) → execution-intent constructs (high)
    → base64-like blobs (decoded to hex for the report, never executed)
    → long-line structure → Python/bash syntax validation → ClamAV.
11. **Integrity re-hash** — if the analysis copy changed during scanning,
    that is itself a high-severity finding.
12. **Risk computed** from the highest finding severity.
13. **Reports written** — JSON + Markdown + one DB row + all finding rows.
14. **Routing** — clean/low → `sorted/` (first matching `sort_rule` wins);
    medium → `review/`; high → `quarantine/`.
15. **Audit event** appended to `events.jsonl`.

**Failure branch:** an exception at any step routes the file to `errors/`,
writes the error to the DB and audit log, and exits 40. A file is never
silently lost. "Scan failed" is never reported as "file is clean."

## 5. Daily operation — cheat sheet

Run from `~/quietops-triage-2.1.1/`:

    # Scan whatever is in the inbox right now, then exit
    python3 inbox_triage.py --root ./data --once

    # Run continuously (this is the normal mode; Ctrl-C to stop)
    python3 inbox_triage.py --root ./data --watch

    # Scan one specific file without touching its location
    python3 inbox_triage.py --root ./data --file ~/Downloads/thing.pdf

    # See / change settings
    python3 inbox_triage.py --print-default-config
    cp config.example.json config.json && $EDITOR config.json

    # Run the tests (after ANY change to the code)
    python3 -m unittest discover -s tests -v

**Morning routine (2 minutes):**
1. `ls data/quarantine/ data/review/` — anything new?
2. If yes: read its Markdown report in `data/reports/` (same run-id as the
   filename). The report says exactly what was found, on which line and
   column, with the codepoint or pattern.
3. Decide: ignore (leave it), delete it, or pull the file out deliberately.

## 6. Exit codes

    0   nothing flagged      10   something flagged (or rejected)
    40   workflow failure    1/2  startup/usage error

`40` must never be interpreted as "clean."

## 7. Reading results — the database is the front door

    # Last 20 scans
    sqlite3 -header -column data/logs/triage.db \
      "SELECT id, original_name, risk, destination FROM scans ORDER BY id DESC LIMIT 20;"

    # Everything that was ever flagged
    sqlite3 -header -column data/logs/triage.db \
      "SELECT original_name, risk, destination FROM scans WHERE risk IN ('medium','high');"

    # The findings for one scan (use its run_id)
    sqlite3 -header -column data/logs/triage.db \
      "SELECT severity, category, description, line FROM findings
       WHERE scan_id = (SELECT id FROM scans WHERE run_id='RUN-ID-HERE');"

    # Risk breakdown of everything processed so far
    sqlite3 data/logs/triage.db "SELECT risk, COUNT(*) FROM scans GROUP BY risk;"

    # Export to CSV (for spreadsheets)
    sqlite3 -header -csv data/logs/triage.db "SELECT * FROM scans;" > scans.csv

    # Live tail of the audit log
    tail -f data/logs/events.jsonl

## 9. Maintenance

    # Back up the DB properly (WAL mode — a plain file copy can lose data)
    sqlite3 data/logs/triage.db ".backup 'data/logs/triage-backup.db'"

    # Analysis copies auto-expire after 14 days (retention_days_analysis);
    # the sweep runs at startup and hourly in watch mode. Reports and DB
    # rows are kept forever.

    # A crash mid-scan leaves the file in processing/; the next startup
    # recovers it into errors/ automatically. Nothing is stranded.

## 10. Putting it in git

echo "# quietops-triage" >> README.md
git init
git add README.md
git commit -m "first commit"
git branch -M main
git remote add origin https://github.com/quietops-admin/quietops-triage.git
git push -u origin main



    cd ~/QuietOps_Triage
    git init
    git add inbox_triage.py tests/ scripts/ config.example.json \
            deploy/ .github/ README.md CHANGELOG.md .gitignore
    git commit -m "QuietOps Triage v2.1.1"

    # On GitHub: create an empty repo named quietops-triage, then:
    git remote add origin git@github.com:quietops-admin/quietops-triage.git
    git branch -M main
    git push -u origin main

**`.gitignore` — this is a security control, not housekeeping:**

    data/
    __pycache__/
    *.pyc
    .triage.lock
    *.db
    *.db-wal
    *.db-shm
    config.json

`data/` must never be committed: it contains quarantined malware, and the
logs contain filenames. Committing it would *publish* both. `config.json`
stays out because it will eventually hold credentials (email ingestion).

## 11. Honest limits

- Static analysis only. "Clean" means "no indicators found," never "safe."
- Parser risk: `bash -n`, Python `compile()`, and libmagic run on untrusted
  input by design; keep the OS and packages patched.
- High-risk files stay quarantined until *I* decide. I never open them in
  normal apps; I read the reports.
- One pipeline instance at a time (enforced by lock).

## 12. Roadmap

- **v2.1** — desktop notifications on medium/high routing
  (`notify-send` / macOS `osascript`), config flag, silent fallback.
- **v2.2** — email attachment ingestion (Pro feature).
- **v3.0** — upload gateway + web dashboard (Pro), rules subscription.
