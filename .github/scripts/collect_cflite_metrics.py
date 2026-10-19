#!/usr/bin/env python3
"""Collect ClusterFuzzLite run metrics and independent corpus/coverage snapshots."""
import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from defusedxml import ElementTree as ET

EVENT_PATH = Path(os.environ.get("EVENT_PATH", "event.json"))
LOGS_DIR = Path(os.environ.get("LOGS_DIR", "logs"))
CORPUS_ROOT = Path(os.environ.get("CORPUS_ROOT", "tfw-fuzzing-corpus"))
COVERAGE_ROOT = Path(os.environ.get("COVERAGE_ROOT", "tfw-fuzzing-pages"))
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "metrics"))
NOW = datetime.now(timezone.utc).isoformat()
FUZZER_START = re.compile(r"Running fuzzer:\s*([A-Za-z0-9_$.-]+)\.")
DONE = re.compile(
    r"DONE\s+cov:\s*(\d+)\s+ft:\s*(\d+)\s+corp:\s*(\d+)/(\d+)([KMG]?b)"
)
EXECUTIONS = re.compile(r"stat::number_of_executed_units:\s*(\d+)")
EXEC_RATE = re.compile(r"stat::average_exec_per_sec:\s*(\d+)")
NEW_UNITS = re.compile(r"stat::new_units_added:\s*(\d+)")
BATCH_FIELDS = ["run_id", "run_attempt", "completed_at", "commit_sha", "fuzzer", "cov", "ft", "executions", "average_exec_per_sec", "active_corpus_units", "active_corpus_bytes", "new_units_added"]
CORPUS_FIELDS = ["observed_at", "fuzzing_repo_commit", "fuzzer", "persistent_corpus_files", "persistent_corpus_bytes", "fingerprint"]
COVERAGE_FIELDS = ["observed_at", "gh_pages_commit", "report_path", "report_fingerprint", "line_missed", "line_total", "line_coverage_percent", "branch_missed", "branch_total", "branch_coverage_percent"]


def rows(path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def append_unique(path, fields, row, key_fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = rows(path)
    key = tuple(str(row.get(k, "")) for k in key_fields)
    if any(tuple(str(old.get(k, "")) for k in key_fields) == key for old in existing):
        return False
    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        if not path.stat().st_size:
            writer.writeheader()
        writer.writerow({field: row.get(field, "") for field in fields})
    return True


def parse_batch_logs():
    fuzzers, active = {}, None
    for path in sorted(p for p in LOGS_DIR.rglob("*") if p.is_file()):
        try:
            lines = path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError as exc:
            print(f"WARN: cannot read {path}: {exc}", file=sys.stderr)
            continue
        for line in lines:
            match = FUZZER_START.search(line)
            if match:
                active = match[1]
                fuzzers.setdefault(active, {})
                continue

            if active is None:
                continue

            match = DONE.search(line)
            if match:
                size_units = {
                    "b": 1,
                    "Kb": 1024,
                    "Mb": 1024**2,
                    "Gb": 1024**3,
                }
                corpus_bytes = int(match[4]) * size_units[match[5]]
                fuzzers[active].update(
                    cov=int(match[1]),
                    ft=int(match[2]),
                    active_corpus_units=int(match[3]),
                    active_corpus_bytes=corpus_bytes,
                )
                continue

            for pattern, key in (
                (EXECUTIONS, "executions"),
                (EXEC_RATE, "average_exec_per_sec"),
                (NEW_UNITS, "new_units_added"),
            ):
                match = pattern.search(line)
                if match:
                    fuzzers[active][key] = int(match[1])

    return {
        name: stats
        for name, stats in fuzzers.items()
        if "cov" in stats and "ft" in stats
    }


def file_fingerprint(directory):
    digest = hashlib.sha256()
    for path in sorted(p for p in directory.rglob("*") if p.is_file() and ".git" not in p.parts):
        digest.update(path.relative_to(directory).as_posix().encode())
        digest.update(b"\0")
        try:
            digest.update(str(path.stat().st_size).encode())
            digest.update(b"\0")
            with path.open("rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            print(f"WARN: cannot fingerprint {path}: {exc}", file=sys.stderr)
    return digest.hexdigest()


def corpus_snapshot(repo_sha):
    root = CORPUS_ROOT / "corpus"
    if not root.is_dir():
        print(f"WARN: corpus directory not found: {root}", file=sys.stderr)
        return
    output = OUTPUT_DIR / "corpus_snapshots.csv"
    existing = rows(output)
    latest = {r["fuzzer"]: r for r in existing if r.get("fuzzing_repo_commit") == repo_sha}
    for directory in sorted(p for p in root.iterdir() if p.is_dir()):
        files = sorted(p for p in directory.rglob("*") if p.is_file() and ".git" not in p.parts)
        size = 0
        for p in files:
            try:
                size += p.stat().st_size
            except OSError:
                pass
        fp = file_fingerprint(directory)
        if latest.get(directory.name, {}).get("fingerprint") == fp:
            continue
        append_unique(
            output,
            CORPUS_FIELDS,
            {
                "observed_at": NOW,
                "fuzzing_repo_commit": repo_sha,
                "fuzzer": directory.name,
                "persistent_corpus_files": len(files),
                "persistent_corpus_bytes": size,
                "fingerprint": fp,
            },
            ["fuzzing_repo_commit", "fuzzer", "fingerprint"],
        )

class TableParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.rows = []; self.row = None; self.cell = None
    def handle_starttag(self, tag, attrs):
        if tag == "tr": self.row = []
        elif tag in ("td", "th") and self.row is not None: self.cell = ""
    def handle_data(self, data):
        if self.cell is not None: self.cell += data
    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.cell is not None:
            self.row.append(" ".join(self.cell.split())); self.cell = None
        elif tag == "tr" and self.row is not None:
            self.rows.append(self.row); self.row = None


def pct(covered, total):
    return round(100.0 * covered / total, 2) if total else ""


def from_xml(path):
    root = ET.parse(str(path)).getroot()
    counters = {n.attrib.get("type"): n.attrib for n in root.findall("counter")}
    line, branch = counters.get("LINE", {}), counters.get("BRANCH", {})
    lm, lc = int(line.get("missed", 0)), int(line.get("covered", 0))
    bm, bc = int(branch.get("missed", 0)), int(branch.get("covered", 0))
    return {"line_missed": lm, "line_total": lm + lc, "line_coverage_percent": pct(lc, lm + lc), "branch_missed": bm, "branch_total": bm + bc, "branch_coverage_percent": pct(bc, bm + bc)}


def from_html(path):
    parser = TableParser(); parser.feed(path.read_text(encoding="utf-8", errors="replace"))
    total_i = next((i for i, r in enumerate(parser.rows) if r and r[0].lower() == "total"), None)
    if total_i is None: return None
    header = next((r for r in reversed(parser.rows[:total_i]) if any("missed" in c.lower() and "lines" in c.lower() for c in r) or ("Missed" in r and "Lines" in r)), None)
    if not header: return None
    values = parser.rows[total_i]
    def find(labels):
        idx = next((i for i, h in enumerate(header) if h.strip() in labels), None)
        return values[idx] if idx is not None and idx < len(values) else ""
    try:
        # JaCoCo variants either combine the label or split Missed / Lines into separate cells.
        combined = next((i for i, h in enumerate(header) if "Missed Lines" == h.strip()), None)
        if combined is not None:
            lm = int(re.search(r"\d+", values[combined]).group())
            line_cell = find({"Lines"})
            lt = int(re.search(r"\d+", line_cell).group())
        else:
            li = header.index("Lines")
            # In JaCoCo's standard table, the line-missed count is the
            # "Missed" column immediately preceding the "Lines" column.
            mi = li - 1
            lm = int(re.search(r"\d+", values[mi]).group()); lt = int(re.search(r"\d+", values[li]).group())
    except (ValueError, AttributeError, IndexError): return None
    bm = bt = bp = ""
    branch = find({"Missed Branches"})
    m = re.search(r"(\d+)\s+of\s+(\d+)", branch)
    if m: bm, bt = int(m[1]), int(m[2]); bp = pct(bt - bm, bt)
    return {"line_missed": lm, "line_total": lt, "line_coverage_percent": pct(lt - lm, lt), "branch_missed": bm, "branch_total": bt, "branch_coverage_percent": bp}


def coverage_snapshot(pages_sha):
    candidates = [COVERAGE_ROOT / "coverage/latest/report/linux/jacoco.xml"]
    candidates += sorted(COVERAGE_ROOT.rglob("jacoco.xml"))
    candidates += [COVERAGE_ROOT / "coverage/latest/report/linux/index.html"]
    candidates += sorted(COVERAGE_ROOT.rglob("index.html"))
    seen = set()
    for path in candidates:
        if path in seen or not path.is_file(): continue
        seen.add(path)
        try:
            summary = from_xml(path) if path.name == "jacoco.xml" else from_html(path)
        except Exception as exc:
            print(f"WARN: cannot parse coverage report {path}: {exc}", file=sys.stderr); continue
        if not summary: continue
        fp = file_fingerprint(path.parent)
        append_unique(
            OUTPUT_DIR / "coverage_snapshots.csv",
            COVERAGE_FIELDS,
            {
                "observed_at": NOW,
                "gh_pages_commit": pages_sha,
                "report_path": str(path.relative_to(COVERAGE_ROOT)),
                "report_fingerprint": fp,
                **summary,
            },
            ["gh_pages_commit", "report_path", "report_fingerprint"],
        )
        print(f"Coverage snapshot inspected: {path.relative_to(COVERAGE_ROOT)}")
        return
    print("WARN: no readable JaCoCo XML or HTML report found", file=sys.stderr)


def main():
    event = json.loads(EVENT_PATH.read_text(encoding="utf-8")) if EVENT_PATH.exists() else {}
    run = event.get("workflow_run", event)
    if run.get("name") != "ClusterFuzzLite batch fuzzing":
        print(f"Ignoring workflow: {run.get('name', '(snapshot-only invocation)')}")
        return 0
    fuzzers = parse_batch_logs()
    if not fuzzers:
        print("ERROR: no final fuzzer summaries parsed; run remains retryable", file=sys.stderr)
        return 1
    for name, stats in sorted(fuzzers.items()):
        append_unique(OUTPUT_DIR / "batch_fuzzers.csv", BATCH_FIELDS, {"run_id": run.get("id", ""), "run_attempt": run.get("run_attempt", ""), "completed_at": run.get("updated_at", NOW), "commit_sha": run.get("head_sha", ""), "fuzzer": name, **stats}, ["run_id", "run_attempt", "fuzzer"])
    print(f"Recorded or confirmed metrics for {len(fuzzers)} dynamically discovered fuzzers")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
