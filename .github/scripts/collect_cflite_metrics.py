#!/usr/bin/env python3
"""Append dynamically discovered ClusterFuzzLite metrics to CSV history."""

import csv
import json
import os
import re
import sys
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
import xml.etree.ElementTree as ET

EVENT_PATH = Path(os.environ["EVENT_PATH"])
LOGS_DIR = Path(os.environ["LOGS_DIR"])
CORPUS_ROOT = Path(os.environ["CORPUS_ROOT"])
COVERAGE_ROOT = Path(os.environ["COVERAGE_ROOT"])
OUTPUT_DIR = Path(os.environ["OUTPUT_DIR"])

FUZZER_START = re.compile(r"Running fuzzer:\s*([A-Za-z0-9_$.-]+)\.")
DONE = re.compile(r"DONE\s+cov:\s*(\d+)\s+ft:\s*(\d+)\s+corp:\s*(\d+)/(\d+)b")
EXECUTIONS = re.compile(r"stat::number_of_executed_units:\s*(\d+)")
EXEC_RATE = re.compile(r"stat::average_exec_per_sec:\s*(\d+)")
NEW_UNITS = re.compile(r"stat::new_units_added:\s*(\d+)")

BATCH_FIELDS = [
    "run_id", "run_attempt", "completed_at", "commit_sha", "fuzzer",
    "cov", "ft", "executions", "average_exec_per_sec", "active_corpus_units",
    "active_corpus_bytes", "new_units_added", "persistent_corpus_files",
    "persistent_corpus_bytes",
]
COVERAGE_FIELDS = [
    "run_id", "run_attempt", "completed_at", "commit_sha", "line_missed",
    "line_total", "line_coverage_percent", "branch_missed", "branch_total",
    "branch_coverage_percent", "report_path",
]


def append_csv(path, fields, row):
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    with path.open("a", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        if not exists:
            writer.writeheader()
        writer.writerow({field: row.get(field, "") for field in fields})


def parse_batch_logs():
    fuzzers = {}
    active = None
    for path in sorted(p for p in LOGS_DIR.rglob("*") if p.is_file()):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            match = FUZZER_START.search(line)
            if match:
                active = match.group(1)
                fuzzers.setdefault(active, {})
                continue
            if active is None:
                continue
            match = DONE.search(line)
            if match:
                stats = fuzzers[active]
                stats.update(cov=int(match.group(1)), ft=int(match.group(2)),
                             active_corpus_units=int(match.group(3)),
                             active_corpus_bytes=int(match.group(4)))
            for pattern, key in ((EXECUTIONS, "executions"),
                                 (EXEC_RATE, "average_exec_per_sec"),
                                 (NEW_UNITS, "new_units_added")):
                match = pattern.search(line)
                if match:
                    fuzzers[active][key] = int(match.group(1))
    # Keep only targets for which the log contained a final libFuzzer summary.
    return {name: stats for name, stats in fuzzers.items() if "cov" in stats and "ft" in stats}


def corpus_stats(fuzzer):
    candidates = [CORPUS_ROOT / "corpus" / fuzzer, CORPUS_ROOT / fuzzer]
    directory = next((p for p in candidates if p.is_dir()), None)
    if directory is None:
        return "", ""
    files = [p for p in directory.rglob("*") if p.is_file() and ".git" not in p.parts]
    return len(files), sum(p.stat().st_size for p in files)


class JaCoCoHTML(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows = []
        self.row = None
        self.cell = None
        self.in_cell = False

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.row = []
        elif tag in ("td", "th") and self.row is not None:
            self.cell = ""
            self.in_cell = True

    def handle_data(self, data):
        if self.in_cell and self.cell is not None:
            self.cell += data

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.in_cell:
            self.row.append(" ".join(self.cell.split()))
            self.cell = None
            self.in_cell = False
        elif tag == "tr" and self.row is not None:
            self.rows.append(self.row)
            self.row = None


def percent(covered, total):
    return round(100.0 * covered / total, 2) if total else ""


def read_jacoco_xml(path):
    root = ET.parse(path).getroot()
    counters = {node.attrib.get("type"): node.attrib for node in root.findall("counter")}
    line = counters.get("LINE", {})
    branch = counters.get("BRANCH", {})
    lm, lc = int(line.get("missed", 0)), int(line.get("covered", 0))
    bm, bc = int(branch.get("missed", 0)), int(branch.get("covered", 0))
    return {
        "line_missed": lm, "line_total": lm + lc,
        "line_coverage_percent": percent(lc, lm + lc),
        "branch_missed": bm, "branch_total": bm + bc,
        "branch_coverage_percent": percent(bc, bm + bc),
    }


def read_jacoco_html(path):
    parser = JaCoCoHTML()
    parser.feed(path.read_text(encoding="utf-8", errors="replace"))
    rows = parser.rows
    total_index = next((i for i, row in enumerate(rows) if row and row[0].lower() == "total"), None)
    if total_index is None:
        return None
    header = next((row for row in reversed(rows[:total_index])
                   if any("Missed Lines" in cell for cell in row)), None)
    if not header:
        return None
    values = rows[total_index]
    def cell_for(label):
        index = next((i for i, cell in enumerate(header) if cell.strip() == label), None)
        return values[index] if index is not None and index < len(values) else ""
    try:
        line_missed = int(re.search(r"\d+", cell_for("Missed Lines")).group())
        line_total = int(re.search(r"\d+", cell_for("Lines")).group())
    except (AttributeError, TypeError, ValueError):
        return None
    branch_missed, branch_total, branch_pct = "", "", ""
    branch_text = cell_for("Missed Branches")
    fraction = re.search(r"(\d+)\s+of\s+(\d+)", branch_text)
    if fraction:
        branch_missed, branch_total = int(fraction.group(1)), int(fraction.group(2))
        branch_pct = percent(branch_total - branch_missed, branch_total)
    else:
        # The JaCoCo index page exposes branch coverage as a percentage even
        # when it does not expose a precise branch denominator in the cell.
        headers = [cell.strip() for cell in header]
        try:
            cov_indices = [i for i, label in enumerate(headers) if label == "Cov."]
            branch_pct = values[cov_indices[1]].rstrip("% ") if len(cov_indices) > 1 else ""
        except IndexError:
            pass
    covered = line_total - line_missed
    return {
        "line_missed": line_missed, "line_total": line_total,
        "line_coverage_percent": percent(covered, line_total),
        "branch_missed": branch_missed, "branch_total": branch_total,
        "branch_coverage_percent": branch_pct,
    }


def coverage_summary():
    preferred_xml = COVERAGE_ROOT / "coverage/latest/report/linux/jacoco.xml"
    xml_candidates = ([preferred_xml] if preferred_xml.is_file() else [])
    xml_candidates.extend(p for p in sorted(COVERAGE_ROOT.rglob("jacoco.xml")) if p != preferred_xml)
    for path in xml_candidates:
        try:
            return read_jacoco_xml(path), str(path.relative_to(COVERAGE_ROOT))
        except (ET.ParseError, OSError, ValueError):
            continue
    html_candidates = [COVERAGE_ROOT / "coverage/latest/report/linux/index.html"]
    html_candidates.extend(sorted(COVERAGE_ROOT.rglob("index.html")))
    seen = set()
    for path in html_candidates:
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        try:
            summary = read_jacoco_html(path)
        except OSError:
            summary = None
        if summary:
            return summary, str(path.relative_to(COVERAGE_ROOT))
    return None, ""


def main():
    event = json.loads(EVENT_PATH.read_text(encoding="utf-8"))
    # Support both workflow_run event payloads and direct Actions API run objects.
    run = event.get("workflow_run", event)
    run_id = run.get("id", "")
    attempt = run.get("run_attempt", "")
    completed_at = run.get("updated_at") or datetime.now(timezone.utc).isoformat()
    commit_sha = run.get("head_sha", "")
    workflow_name = run.get("name", "")

    if workflow_name == "ClusterFuzzLite batch fuzzing":
        fuzzers = parse_batch_logs()
        if not fuzzers:
            print("ERROR: no final fuzzer summaries were parsed from the completed batch logs", file=sys.stderr)
            return 1
        for fuzzer, stats in sorted(fuzzers.items()):
            files, byte_count = corpus_stats(fuzzer)
            row = {
                "run_id": run_id, "run_attempt": attempt, "completed_at": completed_at,
                "commit_sha": commit_sha, "fuzzer": fuzzer,
                "persistent_corpus_files": files, "persistent_corpus_bytes": byte_count,
                **stats,
            }
            append_csv(OUTPUT_DIR / "batch_fuzzers.csv", BATCH_FIELDS, row)
        print(f"Recorded metrics for {len(fuzzers)} dynamically discovered fuzzers.")
    elif workflow_name == "ClusterFuzzLite coverage":
        summary, report_path = coverage_summary()
        if not summary:
            print("WARNING: no readable JaCoCo XML or HTML summary found; coverage metrics were not recorded.")
            return 0
        append_csv(OUTPUT_DIR / "coverage_runs.csv", COVERAGE_FIELDS, {
            "run_id": run_id, "run_attempt": attempt, "completed_at": completed_at,
            "commit_sha": commit_sha, "report_path": report_path, **summary,
        })
        print(f"Recorded JaCoCo coverage from {report_path}.")
    else:
        print(f"Ignoring unexpected workflow: {workflow_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
