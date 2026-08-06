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
(and excluded from stats) if EITHER its jsonl status is "failed" OR the
log shows a non-zero exit code for that (technique, test_number).

For detection-rate purposes, "no_rule" is counted separately as its own
technique-level category (see below), while "failed" tests are excluded
entirely since they don't tell us anything about detection - they're an
environment/execution problem.

Technique-level classification uses 4 distinct categories:
  Fully detected      - every test for this technique had alerts
  Partially detected  - some but not all tests had alerts
  Not detected         - technique has a rule, but no test triggered it
  No rule              - technique has no detection rule at all

Output (default ./atomic_report/):
  charts/01_overview_donut.png
  charts/02_technique_status_bar.png
  charts/03_top_rules_bar.png
  charts/04_technique_heatmap.png
  charts/04b_technique_heatmap_rotated.png
  tables/technique_detail.csv
  tables/rule_frequency.csv
  tables/failed_tests.csv
  report_summary.md

Usage:
  python3 generate_report.py --results output/results.jsonl --outdir atomic_report
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


def parse_atomic_log(path):
    """Scan logs/atomic_stdout.log for the real per-test exit code.

    run_atomic.ps1 uses -ErrorAction Continue, so the overall pwsh
    process can exit 0 even when one specific atomic test's command
    failed internally - results.jsonl's "status" field won't catch that.
    This scans for "Exit code: N" lines inside each test's
    START/END block and records any non-zero ones.

    Returns {(technique, test_number): {"exit_code": int, "error_message": str}}
    for every test whose block contained at least one non-zero exit code.
    The error_message is the last non-empty line seen before "Exit code:",
    which is normally the actual error text printed by the command.
    """
    failures = {}
    if not os.path.exists(path):
        print(f"[generate_report] Log file not found, skipping exit-code check: {path}")
        return failures

    current = None
    last_nonempty = ""

    with open(path, encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()

            start_match = _TEST_START_RE.match(line)
            if start_match:
                current = (start_match.group("technique"), int(start_match.group("test_number")))
                last_nonempty = ""
                continue

            end_match = _TEST_END_RE.match(line)
            if end_match:
                current = None
                last_nonempty = ""
                continue

            exit_match = _EXIT_CODE_RE.match(line)
            if exit_match and current is not None:
                code = int(exit_match.group("code"))
                if code != 0:
                    failures[current] = {
                        "exit_code": code,
                        "error_message": last_nonempty,
                    }
                continue

            if line:
                last_nonempty = line

    return failures


def compute_stats(results, log_failures):
    stats = {}

    failed = []
    considered = []
    for r in results:
        key = (r["technique"], r["test_number"])
        log_info = log_failures.get(key)
        # A test is "failed" if either the pipeline itself recorded it as
        # failed (e.g. subprocess-level crash/timeout), OR the atomic log
        # shows a non-zero exit code for it (the case -ErrorAction
        # Continue hides from the pipeline's own status field).
        if r["status"] == "failed" or log_info is not None:
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
        else:
            considered.append(r)

    stats["total_tests"] = len(results)
    stats["failed_tests"] = failed
    stats["considered"] = considered
    stats["considered_count"] = len(considered)

    techniques = sorted({r["technique"] for r in considered})
    stats["techniques"] = techniques
    stats["total_techniques"] = len(techniques)

    detected = [r for r in considered if r["status"] == "detected"]
    undetected = [r for r in considered if r["status"] in ("undetected", "no_rule")]

    stats["detected_count"] = len(detected)
    stats["undetected_count"] = len(undetected)
    stats["detection_rate"] = (
        100 * len(detected) / len(considered) if considered else 0
    )

    # per-technique stats (excluding failed tests)
    tech_stats = defaultdict(lambda: {"total": 0, "detected": 0, "has_rule": True})
    for r in considered:
        t = r["technique"]
        tech_stats[t]["total"] += 1
        if r["status"] == "detected":
            tech_stats[t]["detected"] += 1
        if not r["has_rule"]:
            tech_stats[t]["has_rule"] = False
    stats["tech_stats"] = dict(tech_stats)

    # 4 distinct categories, kept separate (no folding "No rule" into
    # "Not detected" - the report needs to show them apart).
    def classify(s):
        if not s["has_rule"]:
            return "No rule"
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
    order = ["Fully detected", "Partially detected", "Not detected", "No rule"]
    colors = {
        "Fully detected": COLOR_GREEN,
        "Partially detected": COLOR_AMBER,
        "Not detected": COLOR_RED,
        "No rule": COLOR_MUTEDGRAY,
    }
    values = [stats["status_count"].get(k, 0) for k in order]

    fig, ax = plt.subplots(figsize=(7, 4))
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


def _build_heatmap_data(considered):
    """Build the technique x test-position matrix used by both heatmap
    variants. Expects the already-filtered 'considered' list (failed
    tests - per jsonl status AND per log exit code - already excluded
    by compute_stats)."""
    per_tech_tests = defaultdict(dict)  # {technique: {test_number: value}}

    for r in considered:
        t, n = r["technique"], r["test_number"]
        if r["status"] == "no_rule":
            value = 2       # no rule
        elif r["status"] == "detected":
            value = 1        # detected
        else:
            value = 0        # undetected (rule exists but did not fire)
        per_tech_tests[t][n] = value

    def status_of(t):
        vals = list(per_tech_tests[t].values())
        if all(v == 2 for v in vals):
            return 0
        if all(v == 0 or v == 2 for v in vals):
            return 1
        if all(v == 1 or v == 2 for v in vals):
            return 3
        return 2

    techniques = sorted(per_tech_tests.keys(), key=lambda t: (status_of(t), t))
    max_slots = max((len(v) for v in per_tech_tests.values()), default=1)
    max_slots = max(max_slots, 1)

    matrix = np.full((len(techniques), max_slots), -1, dtype=float)
    real_test_no = np.full((len(techniques), max_slots), -1, dtype=int)

    for i, t in enumerate(techniques):
        for pos, (test_no, value) in enumerate(sorted(per_tech_tests[t].items())):
            real_test_no[i, pos] = test_no
            matrix[i, pos] = value

    return techniques, matrix, real_test_no


def _render_heatmap(techniques, matrix, real_test_no, outpath, rotated=False):
    if rotated:
        matrix = matrix.T
        real_test_no = real_test_no.T

    cmap = matplotlib.colors.ListedColormap(
        ["#f1efe8", COLOR_RED, COLOR_GREEN, COLOR_MUTEDGRAY]
    )
    display_matrix = matrix + 1
    bounds = [0, 1, 2, 3, 4]
    norm = matplotlib.colors.BoundaryNorm(bounds, cmap.N)

    n_rows, n_cols = matrix.shape
    cell = 0.32
    fig_w = max(6, min(20, n_cols * cell + 3))
    fig_h = max(5, min(20, n_rows * cell + 1.6))
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    ax.imshow(display_matrix, aspect="equal", cmap=cmap, norm=norm)

    ax.set_xticks(np.arange(-0.5, n_cols, 1), minor=True)
    ax.set_yticks(np.arange(-0.5, n_rows, 1), minor=True)
    ax.grid(which="minor", color="white", linewidth=1.2)
    ax.tick_params(which="minor", bottom=False, left=False)

    if not rotated:
        ax.set_yticks(range(n_rows))
        ax.set_yticklabels(techniques, fontsize=8)
        ax.set_xticks(range(n_cols))
        ax.set_xticklabels([f"#{i+1}" for i in range(n_cols)], fontsize=8)
        ax.set_xlabel("Test position within technique (not the real test ID)", fontsize=9)
        ax.set_ylabel("Technique", fontsize=9)
    else:
        ax.set_xticks(range(n_cols))
        ax.set_xticklabels(techniques, fontsize=8, rotation=90, ha="center")
        ax.set_yticks(range(n_rows))
        ax.set_yticklabels([f"#{i+1}" for i in range(n_rows)], fontsize=8)
        ax.set_ylabel("Test position within technique (not the real test ID)", fontsize=9)
        ax.set_xlabel("Technique", fontsize=9)

    ax.set_title("Technique x Test detection matrix"
                 + (" (rotated)" if rotated else ""), fontsize=12)

    if n_rows * n_cols <= 800:
        for i in range(n_rows):
            for j in range(n_cols):
                if real_test_no[i, j] >= 0:
                    ax.text(j, i, str(real_test_no[i, j]), ha="center", va="center",
                            fontsize=6, color="white" if matrix[i, j] != -1 else "black")

    for spine in ax.spines.values():
        spine.set_visible(False)

    legend_items = [
        ("Not detected (rule exists but did not fire)", COLOR_RED),
        ("Detected", COLOR_GREEN),
        ("Not detected (no rule)", COLOR_MUTEDGRAY),
    ]
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for _, c in legend_items]
    ax.legend(handles, [l for l, _ in legend_items],
              loc="upper center", bbox_to_anchor=(0.5, -0.05 - 0.008 * max(n_rows, n_cols)),
              ncol=3, frameon=False, fontsize=9)

    fig.tight_layout()
    fig.savefig(outpath, dpi=150, bbox_inches="tight")
    plt.close(fig)


def chart_technique_heatmap(considered, outpath):
    techniques, matrix, real_test_no = _build_heatmap_data(considered)
    _render_heatmap(techniques, matrix, real_test_no, outpath, rotated=False)


def chart_technique_heatmap_rotated(considered, outpath):
    techniques, matrix, real_test_no = _build_heatmap_data(considered)
    _render_heatmap(techniques, matrix, real_test_no, outpath, rotated=True)


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
            "Detection rate (%)": round(rate, 1),
            "Status": status,
            "Has rule": "Yes" if s["has_rule"] else "No",
        })
    df_tech = pd.DataFrame(rows).sort_values(["Detection rate (%)", "Technique"])
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

    return df_tech


def write_summary_md(stats, df_tech, outdir):
    lines = []
    lines.append("# Detection coverage report — Atomic Red Team vs Elastic Rules\n")
    lines.append("## 1. Overview\n")
    lines.append(f"- Total tests recorded: **{stats['total_tests']}**")
    if stats["failed_tests"]:
        lines.append(f"- Tests excluded due to execution failure: "
                     f"**{len(stats['failed_tests'])}** (see `tables/failed_tests.csv`)")
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
        lines.append("## 5. Failed tests (excluded from stats above)\n")
        for r in stats["failed_tests"]:
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
    lines.append("- `charts/04b_technique_heatmap_rotated.png`")
    lines.append("- `tables/technique_detail.csv`")
    lines.append("- `tables/rule_frequency.csv`")
    lines.append("- `tables/failed_tests.csv`")

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
    chart_technique_heatmap(stats["considered"], os.path.join(charts_dir, "04_technique_heatmap.png"))
    chart_technique_heatmap_rotated(
        stats["considered"], os.path.join(charts_dir, "04b_technique_heatmap_rotated.png")
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
