#!/usr/bin/env python3
"""
generate_report.py
--------------------
Generate detection-coverage statistics and charts from the pipeline's
output/results.jsonl file (one JSON object per line, produced by
pipeline/result_store.py).

Each line looks like:
{
  "technique": "T1053.005",
  "test_number": 1,
  "alerts": [{"name": "...", "reason": {...}}, ...],
  "has_rule": true,
  "start_time": "...",
  "end_time": "...",
  "status": "detected" | "undetected" | "no_rule" | "failed",
  "error_message": null
}

Status meaning:
  no_rule    - technique has no detection rule, atomic test was not run
  failed     - atomic test itself failed to run (environment issue),
               excluded from detection-rate calculations
  detected   - atomic test ran and at least 1 alert matched
  undetected - atomic test ran but no alert matched

IMPORTANT - failure detection also reads logs/atomic_stdout.log:
run_atomic.ps1 uses -ErrorAction Continue internally, so an individual
atomic test can fail (print "Exit code: <nonzero>") while the overall
pwsh process still exits 0. That means results.jsonl's "status" field
alone is NOT reliable for detecting these failures - the log file must
be scanned for the real per-test exit code. A test is treated as failed
(and excluded from detection-rate stats) if EITHER its jsonl status is
"failed" OR the log shows a non-zero exit code for that
(technique, test_number).

Technique-level classification uses 4 distinct categories:
  Fully detected      - every (non-failed) test for this technique had alerts
  Partially detected  - some but not all (non-failed) tests had alerts
  Not detected         - technique has a rule, but no test triggered it
  No rule              - technique has no detection rule at all

The technique x test heatmap shows EVERY test, including failed ones, so
each test always sits at its own real test-number slot (failed tests are
not silently dropped, which would otherwise shift/hide slots and make it
harder to tell which specific test failed).

Output (default ./atomic_report/):
  charts/01_overview_donut.png
  charts/02_technique_status_bar.png
  charts/03_top_rules_bar.png
  charts/04_technique_heatmap.png
  tables/technique_detail.csv
  tables/rule_frequency.csv
  tables/failed_tests.csv
  report_summary.md

Usage:
  python3 generate_report.py --results output/results.jsonl \
      --atomic-log logs/atomic_stdout.log --outdir atomic_report
"""

import argparse
import json
import os
import re
from collections import defaultdict, Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


COLOR_GREEN = "#1baf7a"
COLOR_AMBER = "#eda100"
COLOR_RED = "#e34948"
COLOR_MUTEDGRAY = "#898781"
COLOR_PURPLE = "#8a5fbf"   # failed tests in the heatmap


# ----------------------------------------------------------------------
# 1. Load & compute stats
# ----------------------------------------------------------------------
def load_results(path):
    """Read a JSONL file, skip malformed lines instead of crashing."""
    results = []
    with open(path, encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"[generate_report] Skipping malformed line {line_no} in {path}")
    return results


# run_atomic.ps1 prints these markers around each test:
#   START <Technique> Test <TestNumber>
#   ... Invoke-AtomicTest output, including lines like "Exit code: 1" ...
#   END <Technique> Test <TestNumber>
_TEST_START_RE = re.compile(r"^START\s+(?P<technique>\S+)\s+Test\s+(?P<test_number>\d+)\s*$")
_TEST_END_RE = re.compile(r"^END\s+(?P<technique>\S+)\s+Test\s+(?P<test_number>\d+)\s*$")
_EXIT_CODE_RE = re.compile(r"^Exit code:\s*(?P<code>-?\d+)\s*$")
# Invoke-AtomicTest is run with -ErrorAction Continue.  Consequently a
# non-terminating PowerShell error can be written to stdout while the wrapper
# still prints "Exit code: 0".  CategoryInfo/FullyQualifiedErrorId are the
# structured fields PowerShell emits for such an error record; they are much
# less ambiguous than looking for arbitrary words such as "error".
_POWERSHELL_ERROR_RECORD_RE = re.compile(
    r"^\+\s+(?:CategoryInfo|FullyQualifiedErrorId)\s*:", re.IGNORECASE
)
_EXPLICIT_ERROR_RE = re.compile(
    r"^(?:ERROR:|\[SC\].*\bFAILED\b|Exception\s+calling\b|"
    r"Synchronizing\s+password\s+failed\b)",
    re.IGNORECASE,
)
_POWERSHELL_ERROR_MESSAGE_RE = re.compile(
    r"(?:\bException\b|\bis not recognized as the name of a cmdlet\b|"
    r"\bRequested registry access is not allowed\b|\bCannot find path\b|"
    r"\bUnable to find a default server\b)",
    re.IGNORECASE,
)


def parse_atomic_log(path):
    """Scan logs/atomic_stdout.log for the real per-test exit code.

    run_atomic.ps1 uses -ErrorAction Continue, so the overall pwsh
    process can exit 0 even when one specific atomic test's command
    failed internally - results.jsonl's "status" field won't catch that.
    This scans for "Exit code: N" lines inside each test's START/END
    block and records any non-zero ones.  It also records structured
    PowerShell error records, because -ErrorAction Continue can leave an
    Atomic test with an exit code of zero even though its command failed.

    Returns {(technique, test_number): {"exit_code": int | None,
    "error_message": str}} for every test with a non-zero exit code or a
    PowerShell error record.
    The error_message is the last non-empty line seen before "Exit code:",
    which is normally the actual error text printed by the command.
    """
    failures = {}
    if not os.path.exists(path):
        print(f"[generate_report] Log file not found, skipping exit-code check: {path}")
        return failures

    current = None
    last_nonempty = ""
    last_error_message = ""

    with open(path, encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()

            start_match = _TEST_START_RE.match(line)
            if start_match:
                current = (start_match.group("technique"), int(start_match.group("test_number")))
                last_nonempty = ""
                last_error_message = ""
                continue

            end_match = _TEST_END_RE.match(line)
            if end_match:
                current = None
                last_nonempty = ""
                last_error_message = ""
                continue

            if current is not None and (
                _EXPLICIT_ERROR_RE.search(line)
                or (
                    not _POWERSHELL_ERROR_RECORD_RE.match(line)
                    and _POWERSHELL_ERROR_MESSAGE_RE.search(line)
                )
            ):
                last_error_message = line

            if current is not None and (
                _EXPLICIT_ERROR_RE.search(line)
                or _POWERSHELL_ERROR_RECORD_RE.match(line)
            ):
                # Keep the first error for the test: later PowerShell records
                # are often follow-on failures caused by the same root issue.
                failures.setdefault(current, {
                    "exit_code": None,
                    "error_message": last_error_message or line,
                })

            exit_match = _EXIT_CODE_RE.match(line)
            if exit_match and current is not None:
                code = int(exit_match.group("code"))
                if code != 0:
                    failures[current] = {
                        "exit_code": code,
                        "error_message": last_error_message or last_nonempty,
                    }
                continue

            if line:
                last_nonempty = line

    return failures


def compute_stats(results, log_failures):
    stats = {}

    failed = []              # excluded from stats: failed AND no alerts
    counted_despite_failure = []   # failed but still produced alert(s) - counted, not excluded
    failed_keys = set()      # only the excluded ones (used to color the heatmap)
    considered = []
    for r in results:
        key = (r["technique"], r["test_number"])
        log_info = log_failures.get(key)
        # A test is "failed" if either the pipeline itself recorded it as
        # failed (e.g. subprocess-level crash/timeout), OR the atomic log
        # shows a non-zero exit code for it (the case -ErrorAction
        # Continue hides from the pipeline's own status field).
        is_failed = r["status"] == "failed" or log_info is not None
        has_alerts = bool(r.get("alerts"))

        if is_failed and not has_alerts:
            # Failed AND nothing detected: inconclusive - we can't tell
            # whether it would have been detected if it had run properly,
            # so exclude it from detection-rate stats entirely.
            failed_keys.add(key)
            failed.append({
                "technique": r["technique"],
                "test_number": r["test_number"],
                "exit_code": log_info["exit_code"] if log_info else None,
                "error_message": (
                    (log_info["error_message"] if log_info else None)
                    or r.get("error_message")
                    or ""
                ),
            })
            continue

        if is_failed and has_alerts:
            # Failed but still triggered an alert: the detection clearly
            # worked despite the execution error, so it's still
            # meaningful signal - count it normally instead of excluding.
            counted_despite_failure.append({
                "technique": r["technique"],
                "test_number": r["test_number"],
                "exit_code": log_info["exit_code"] if log_info else None,
                "error_message": (
                    (log_info["error_message"] if log_info else None)
                    or r.get("error_message")
                    or ""
                ),
            })

        considered.append(r)

    stats["total_tests"] = len(results)
    stats["failed_tests"] = failed
    stats["counted_despite_failure"] = counted_despite_failure
    stats["failed_keys"] = failed_keys
    stats["considered"] = considered
    stats["considered_count"] = len(considered)

    # Build technique stats from ALL results, not just "considered" -
    # otherwise a technique whose every single test happened to fail
    # would disappear entirely from technique_detail.csv / the status
    # chart / total_techniques, instead of showing up with 0 usable
    # tests and a distinct "All tests failed" status.
    techniques = sorted({r["technique"] for r in results})
    stats["techniques"] = techniques
    stats["total_techniques"] = len(techniques)

    detected = [r for r in considered if r["status"] == "detected"]
    undetected = [r for r in considered if r["status"] in ("undetected", "no_rule")]

    stats["detected_count"] = len(detected)
    stats["undetected_count"] = len(undetected)
    stats["detection_rate"] = (
        100 * len(detected) / len(considered) if considered else 0
    )

    tech_stats = defaultdict(lambda: {"total": 0, "detected": 0, "has_rule": True, "failed_count": 0})
    for r in results:
        t = r["technique"]
        if not r["has_rule"]:
            tech_stats[t]["has_rule"] = False
        key = (t, r["test_number"])
        if key in failed_keys:
            tech_stats[t]["failed_count"] += 1
            continue
        tech_stats[t]["total"] += 1
        if r["status"] == "detected":
            tech_stats[t]["detected"] += 1
    stats["tech_stats"] = dict(tech_stats)

    # 5 distinct categories - "All tests failed" covers techniques where
    # every attempt errored out, so there's no usable detection data at
    # all (different from "Not detected", which means the rule genuinely
    # never fired on a successfully-run test).
    def classify(s):
        if not s["has_rule"]:
            return "No rule"
        if s["total"] == 0:
            return "All tests failed"
        if s["detected"] == 0:
            return "Not detected"
        if s["detected"] == s["total"]:
            return "Fully detected"
        return "Partially detected"

    status_count = Counter()
    for t, s in tech_stats.items():
        status_count[classify(s)] += 1
    stats["status_count"] = status_count

    # rule trigger frequency
    rule_freq = Counter()
    for r in considered:
        for a in r.get("alerts", []):
            rule_freq[a["name"]] += 1
    stats["rule_freq"] = rule_freq

    return stats


# ----------------------------------------------------------------------
# 2. Charts
# ----------------------------------------------------------------------
def chart_overview_donut(stats, outpath):
    fig, ax = plt.subplots(figsize=(5, 5))
    sizes = [stats["detected_count"], stats["undetected_count"]]
    labels = [f"Detected ({sizes[0]})", f"Undetected ({sizes[1]})"]
    colors = [COLOR_GREEN, "#e1e0d9"]

    wedges, _ = ax.pie(
        sizes, colors=colors, startangle=90,
        wedgeprops=dict(width=0.4, edgecolor="white")
    )
    ax.legend(wedges, labels, loc="center", frameon=False, fontsize=11)
    ax.set_title(
        f"Detection coverage (test-level)\n{stats['detection_rate']:.1f}% detected "
        f"out of {stats['considered_count']} tests"
        + (f"\n({len(stats['failed_tests'])} failed tests excluded)"
           if stats["failed_tests"] else ""),
        fontsize=12
    )
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)


def chart_technique_status(stats, outpath):
    order = ["Fully detected", "Partially detected", "Not detected", "No rule", "All tests failed"]
    colors = {
        "Fully detected": COLOR_GREEN,
        "Partially detected": COLOR_AMBER,
        "Not detected": COLOR_RED,
        "No rule": COLOR_MUTEDGRAY,
        "All tests failed": COLOR_PURPLE,
    }
    values = [stats["status_count"].get(k, 0) for k in order]

    fig, ax = plt.subplots(figsize=(7, 4.5))
    bars = ax.barh(order, values, color=[colors[k] for k in order])
    ax.invert_yaxis()
    ax.set_xlabel("Number of techniques")
    ax.set_title("Technique classification by detection level")
    for bar, v in zip(bars, values):
        ax.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height() / 2,
                str(v), va="center", fontsize=10)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)


def chart_top_rules(stats, outpath, top_n=15):
    top = stats["rule_freq"].most_common(top_n)
    if not top:
        return
    names, counts = zip(*top)

    fig, ax = plt.subplots(figsize=(8, max(4, 0.35 * len(names))))
    y_pos = np.arange(len(names))
    ax.barh(y_pos, counts, color="#378ADD")
    ax.set_yticks(y_pos)
    ax.set_yticklabels(names, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("Times triggered")
    ax.set_title(f"Top {len(names)} most-triggered rules")
    for i, v in enumerate(counts):
        ax.text(v + 0.1, i, str(v), va="center", fontsize=9)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)


# ----------------------------------------------------------------------
# Heatmap: technique x test. Includes ALL tests (detected / undetected /
# no_rule / failed) so every test sits at its own real test-number slot -
# failed tests are shown with their own color instead of being silently
# dropped (which would otherwise shift later slots and hide which exact
# test failed).
# ----------------------------------------------------------------------
def _build_heatmap_matrix(results, failed_keys):
    per_tech_tests = defaultdict(dict)  # {technique: {test_number: value}}

    for r in results:
        t, n = r["technique"], r["test_number"]
        key = (t, n)
        if key in failed_keys:
            value = 3           # failed (execution error)
        elif r["status"] == "no_rule":
            value = 2           # no rule
        elif r["status"] == "detected":
            value = 1           # detected
        else:
            value = 0           # undetected (rule exists but did not fire)
        per_tech_tests[t][n] = value

    # Keep technique rows in a stable, alphabetical ATT&CK-ID order.  This
    # makes it easy to find the same technique in the heatmap and CSV; the
    # cell colours already communicate the detection status.
    techniques = sorted(per_tech_tests)
    # Columns represent real Atomic test numbers, not the ordinal position
    # within the tests that happened to be selected for a technique.  For
    # example, tests [1, 2, 9, 10] must occupy columns [1, 2, 9, 10], with
    # columns 3--8 left empty; packing them into four consecutive columns
    # incorrectly makes test 9 appear in position 3.
    max_slots = max(
        (max(tests) for tests in per_tech_tests.values() if tests), default=1
    )
    max_slots = max(max_slots, 1)

    matrix = np.full((len(techniques), max_slots), -1, dtype=float)
    real_test_no = np.full((len(techniques), max_slots), -1, dtype=int)

    for i, t in enumerate(techniques):
        for test_no, value in per_tech_tests[t].items():
            pos = test_no - 1
            real_test_no[i, pos] = test_no
            matrix[i, pos] = value

    return techniques, matrix, real_test_no


def _sparse_ticks(n, step=5):
    """Return tick positions (0-indexed) for labels 1, step, 2*step, ...
    instead of labelling every single position - keeps the axis readable
    when there are many test slots."""
    if n <= step:
        return list(range(n))
    ticks = sorted(set([0] + list(range(step - 1, n, step))))
    return ticks


def _render_heatmap(techniques, matrix, real_test_no, outpath, rotated=False):
    if matrix.size == 0:
        return

    if rotated:
        matrix = matrix.T
        real_test_no = real_test_no.T

    cmap = matplotlib.colors.ListedColormap(
        ["#f1efe8", COLOR_RED, COLOR_GREEN, COLOR_MUTEDGRAY, COLOR_PURPLE]
    )
    display_matrix = matrix + 1
    bounds = [0, 1, 2, 3, 4, 5]
    norm = matplotlib.colors.BoundaryNorm(bounds, cmap.N)

    n_rows, n_cols = matrix.shape
    cell = 0.32
    fig_w = max(6, min(24, n_cols * cell + 3))
    fig_h = max(5, min(24, n_rows * cell + 1.8))
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    # aspect="auto" (not "equal"): with aspect="equal", matplotlib forces
    # each cell to be a true square in physical inches, so when the data
    # matrix's row/column ratio doesn't match the figure's width/height
    # ratio (e.g. one technique with ~90 tests next to many with <10),
    # it letterboxes - padding the shorter figure dimension with a huge
    # blank gap to preserve that square-cell constraint. "auto" instead
    # stretches cells to fill the whole axes box, eliminating that gap.
    ax.imshow(display_matrix, aspect="auto", cmap=cmap, norm=norm)

    ax.set_xticks(np.arange(-0.5, n_cols, 1), minor=True)
    ax.set_yticks(np.arange(-0.5, n_rows, 1), minor=True)
    ax.grid(which="minor", color="white", linewidth=1.2)
    ax.tick_params(which="minor", bottom=False, left=False)

    if not rotated:
        ax.set_yticks(range(n_rows))
        ax.set_yticklabels(techniques, fontsize=13)
        tick_pos = _sparse_ticks(n_cols)
        ax.set_xticks(tick_pos)
        ax.set_xticklabels([str(i + 1) for i in tick_pos], fontsize=12)
        ax.set_xlabel("Atomic Test Number", fontsize=14)
        ax.set_ylabel("Technique", fontsize=14)
    else:
        ax.set_xticks(range(n_cols))
        ax.set_xticklabels(techniques, fontsize=13, rotation=90, ha="center")
        tick_pos = _sparse_ticks(n_rows)
        ax.set_yticks(tick_pos)
        ax.set_yticklabels([str(i + 1) for i in tick_pos], fontsize=12)
        ax.set_ylabel("Atomic Test Number", fontsize=14)
        ax.set_xlabel("Technique", fontsize=14)

    ax.set_title("Technique x Test detection matrix"
                 + (" (rotated)" if rotated else ""), fontsize=16)

    if n_rows * n_cols <= 800:
        for i in range(n_rows):
            for j in range(n_cols):
                if real_test_no[i, j] >= 0:
                    ax.text(j, i, str(real_test_no[i, j]), ha="center", va="center",
                            fontsize=8, color="white" if matrix[i, j] != -1 else "black")

    for spine in ax.spines.values():
        spine.set_visible(False)

    legend_items = [
        ("Not detected (rule exists but did not fire)", COLOR_RED),
        ("Detected", COLOR_GREEN),
        ("No rule", COLOR_MUTEDGRAY),
        ("Failed (execution error)", COLOR_PURPLE),
    ]
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for _, c in legend_items]
    # fig.legend (figure-fraction coordinates), NOT ax.legend with a
    # negative bbox_to_anchor in axes-fraction coordinates: axes-fraction
    # offsets scale with the axes' own height/width, which varies a lot
    # with matrix shape (e.g. n_rows=90 in the rotated view) - the same
    # fractional offset can mean a tiny gap for a short axes and a huge
    # one for a tall axes. Figure-fraction placement stays a small,
    # consistent gap below the plot regardless of matrix size.
    # Reserve a fixed slice of the figure's bottom for the legend via
    # tight_layout(rect=...), instead of just nudging the legend down by
    # a small offset (which can overlap the xlabel - as it did before
    # this fix). rect=[left, bottom, right, top] in figure fraction.
    fig.tight_layout(rect=[0, 0.08, 1, 1])
    fig.legend(handles, [l for l, _ in legend_items],
               loc="lower center", ncol=4, frameon=False, fontsize=15,
               bbox_to_anchor=(0.5, 0.0))

    fig.savefig(outpath, dpi=150, bbox_inches="tight")
    plt.close(fig)


def chart_technique_heatmap(results, failed_keys, outpath):
    techniques, matrix, real_test_no = _build_heatmap_matrix(results, failed_keys)
    _render_heatmap(techniques, matrix, real_test_no, outpath, rotated=False)


# ----------------------------------------------------------------------
# 3. Tables + markdown summary
# ----------------------------------------------------------------------
def export_tables(stats, outdir):
    tables_dir = os.path.join(outdir, "tables")
    os.makedirs(tables_dir, exist_ok=True)

    rows = []
    for t, s in sorted(stats["tech_stats"].items()):
        rate = 100 * s["detected"] / s["total"] if s["total"] else 0
        if not s["has_rule"]:
            status = "No rule"
        elif s["total"] == 0:
            status = "All tests failed"
        elif s["detected"] == 0:
            status = "Not detected"
        elif s["detected"] == s["total"]:
            status = "Fully detected"
        else:
            status = "Partially detected"
        rows.append({
            "Technique": t,
            "Tests detected": s["detected"],
            "Tests total": s["total"],
            "Failed tests": s["failed_count"],
            "Detection rate (%)": round(rate, 1),
            "Status": status,
            "Has rule": "Yes" if s["has_rule"] else "No",
        })
    # Present the detail table in the same technique order as the heatmap,
    # rather than grouping it by detection rate.
    df_tech = pd.DataFrame(rows).sort_values("Technique")
    df_tech.to_csv(os.path.join(tables_dir, "technique_detail.csv"), index=False)

    rule_rows = [
        {"Rule name": name, "Times triggered": count}
        for name, count in stats["rule_freq"].most_common()
    ]
    pd.DataFrame(rule_rows).to_csv(
        os.path.join(tables_dir, "rule_frequency.csv"), index=False
    )

    failed_rows = [
        {
            "Technique": r["technique"],
            "Test": r["test_number"],
            "Exit code": r.get("exit_code") if r.get("exit_code") is not None else "",
            "Error": r.get("error_message") or "",
        }
        for r in stats["failed_tests"]
    ]
    pd.DataFrame(failed_rows).to_csv(
        os.path.join(tables_dir, "failed_tests.csv"), index=False
    )

    counted_rows = [
        {
            "Technique": r["technique"],
            "Test": r["test_number"],
            "Exit code": r.get("exit_code") if r.get("exit_code") is not None else "",
            "Error": r.get("error_message") or "",
        }
        for r in stats["counted_despite_failure"]
    ]
    pd.DataFrame(counted_rows).to_csv(
        os.path.join(tables_dir, "failed_but_counted.csv"), index=False
    )

    return df_tech


def write_summary_md(stats, df_tech, outdir):
    lines = []
    lines.append("# Detection coverage report — Atomic Red Team vs Elastic Rules\n")
    lines.append("## 1. Overview\n")
    lines.append(f"- Total tests recorded: **{stats['total_tests']}**")
    if stats["failed_tests"]:
        lines.append(f"- Tests excluded (execution failed, no alert produced): "
                     f"**{len(stats['failed_tests'])}** (see `tables/failed_tests.csv`)")
    if stats["counted_despite_failure"]:
        lines.append(f"- Tests that failed to run but still produced an alert - "
                     f"**counted, not excluded**: **{len(stats['counted_despite_failure'])}** "
                     f"(see `tables/failed_but_counted.csv`)")
    lines.append(f"- Tests considered for detection stats: **{stats['considered_count']}**")
    lines.append(f"- Techniques tested: **{stats['total_techniques']}**")
    lines.append(f"- Detected: **{stats['detected_count']}** "
                 f"({stats['detection_rate']:.1f}%)")
    lines.append(f"- Undetected (including techniques with no rule): "
                 f"**{stats['undetected_count']}**")
    lines.append(f"- Distinct rules triggered: **{len(stats['rule_freq'])}**\n")

    lines.append("## 2. Technique classification\n")
    for status, count in stats["status_count"].most_common():
        lines.append(f"- {status}: **{count}** technique(s)")
    lines.append("")

    lines.append("## 3. Top triggered rules\n")
    for name, count in stats["rule_freq"].most_common(10):
        lines.append(f"- {name}: {count} time(s)")
    lines.append("")

    lines.append("## 4. Technique detail\n")
    lines.append(df_tech.to_markdown(index=False))
    lines.append("")

    if stats["failed_tests"]:
        lines.append("## 5. Failed tests, excluded (no alert produced)\n")
        for r in stats["failed_tests"]:
            err = r.get("error_message") or "unknown error"
            code = r.get("exit_code")
            code_str = f" (exit code {code})" if code is not None else ""
            lines.append(f"- {r['technique']} test {r['test_number']}{code_str}: {err}")
        lines.append("")

    if stats["counted_despite_failure"]:
        lines.append("## 5b. Failed tests, still counted (alert was produced)\n")
        for r in stats["counted_despite_failure"]:
            err = r.get("error_message") or "unknown error"
            code = r.get("exit_code")
            code_str = f" (exit code {code})" if code is not None else ""
            lines.append(f"- {r['technique']} test {r['test_number']}{code_str}: {err}")
        lines.append("")

    lines.append("## Attached files\n")
    lines.append("- `charts/01_overview_donut.png`")
    lines.append("- `charts/02_technique_status_bar.png`")
    lines.append("- `charts/03_top_rules_bar.png`")
    lines.append("- `charts/04_technique_heatmap.png`")
    lines.append("- `tables/technique_detail.csv`")
    lines.append("- `tables/rule_frequency.csv`")
    lines.append("- `tables/failed_tests.csv`")
    if stats["counted_despite_failure"]:
        lines.append("- `tables/failed_but_counted.csv`")

    with open(os.path.join(outdir, "report_summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ----------------------------------------------------------------------
# 4. Main
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", default="output/results.jsonl",
                         help="Path to results.jsonl produced by the pipeline")
    parser.add_argument("--atomic-log", default="logs/atomic_stdout.log",
                         help="Path to atomic_stdout.log, scanned for real per-test exit codes")
    parser.add_argument("--outdir", default="atomic_report",
                         help="Output directory for the report")
    parser.add_argument("--top-rules", type=int, default=15,
                         help="Number of rules to show in the top-rules chart")
    args = parser.parse_args()

    charts_dir = os.path.join(args.outdir, "charts")
    os.makedirs(charts_dir, exist_ok=True)

    results = load_results(args.results)
    log_failures = parse_atomic_log(args.atomic_log)
    stats = compute_stats(results, log_failures)

    chart_overview_donut(stats, os.path.join(charts_dir, "01_overview_donut.png"))
    chart_technique_status(stats, os.path.join(charts_dir, "02_technique_status_bar.png"))
    chart_top_rules(stats, os.path.join(charts_dir, "03_top_rules_bar.png"), args.top_rules)
    # Heatmaps use the FULL result set (results, not just stats["considered"])
    # plus failed_keys, so every test - including failed ones - shows up at
    # its own real test-number slot instead of being silently dropped.
    chart_technique_heatmap(
        results, stats["failed_keys"], os.path.join(charts_dir, "04_technique_heatmap.png")
    )

    df_tech = export_tables(stats, args.outdir)
    write_summary_md(stats, df_tech, args.outdir)

    print(f"Report generated at: {os.path.abspath(args.outdir)}")
    print(f"  {stats['considered_count']} tests considered "
          f"({len(stats['failed_tests'])} failed excluded) | "
          f"{stats['total_techniques']} techniques | "
          f"detection rate {stats['detection_rate']:.1f}%")


if __name__ == "__main__":
    main()
