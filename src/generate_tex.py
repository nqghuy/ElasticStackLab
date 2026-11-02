import csv
import re
import unicodedata
import json
import tomllib
from collections import defaultdict
from pathlib import Path

CSV_FILE = Path("not_detect.csv")
INDEX_FILE = Path("windows-index.md")
OUTPUT_DIR = Path("tables")
RESULTS_FILE = Path("output/results.jsonl")
ATOMIC_LOG = Path("logs/atomic_stdout.log")
PIPELINE_LOG = Path("logs/pipeline.log")
TEX_DIR = Path("tex")
DEFAULT_RULES_DIR = Path("/home/nqghuy/KLTN/detection-rules/rules")
CUSTOM_RULES_DIR = Path("/home/nqghuy/KLTN/detection-rules/custom-rules/rules")
CUSTOM_DETECTIONS_CSV = Path("/home/nqghuy/KLTN/src/not_detect.csv")
DETECTION_SOURCE_CSV = CSV_FILE

REASON_COLUMN = "Reason no alert"
CATEGORY_COLUMN = "Phan loai"
UNCLASSIFIED = "Chưa phân loại"

# Thứ tự các bảng trong đầu ra; nhóm không có trong danh sách này
# sẽ được thêm vào cuối theo thứ tự xuất hiện trong CSV.
CATEGORY_ORDER = [
    "No rule",
    "Không ánh xạ",
    "Rule chưa hoàn thiện",
    "Log không đủ",
    "Không viết được rule",
    "Khác",
    UNCLASSIFIED,
]

# Caption riêng cho từng nhóm (không khai báo thì dùng caption mặc định).
CAPTIONS = {
    "No rule": "Các Atomic Test chưa có Detection Rule",
    "Không ánh xạ": "Các Atomic Test có rule nhưng chưa ánh xạ hết technique",
    "Rule chưa hoàn thiện": "Các Atomic Test có rule nhưng chưa bao phủ đầy đủ hành vi",
    "Log không đủ": "Các Atomic Test không phát hiện được do thiếu dữ liệu log",
    "Không viết được rule": "Các Atomic Test chưa thể viết Detection Rule",
}

TECHNIQUE_RE = re.compile(
    r"^\s*-\s+(?:\[)?(T\d{4}(?:\.\d{3})?)\s+"
    r"(.+?)"
    r"(?:\]\([^)]+\))?\s*$"
)
ATOMIC_RE = re.compile(r"^\s*-\s+Atomic Test #(\d+):\s*(.*?)\s*$")
# "No rule", "No rule (nội dung)" hoặc "No rule (nội dung" bị mất ngoặc đóng.
NO_RULE_RE = re.compile(r"^no rule\b\s*(?:\((.*?)\)?)?\s*$", re.IGNORECASE)


def latex_escape(value):
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(c, c) for c in str(value))


def clean(text):
    return " ".join((text or "").split())


def fold(text):
    return unicodedata.normalize("NFC", clean(text)).casefold()


def slugify(text):
    text = text.replace("đ", "d").replace("Đ", "D")
    text = unicodedata.normalize("NFD", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Mn")
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def load_atomic_index(path):
    techniques = {}
    atomic_tests = defaultdict(dict)
    current_technique = None

    with path.open(encoding="utf-8-sig") as f:
        for line in f:
            match = TECHNIQUE_RE.match(line)
            if match:
                current_technique = match.group(1)
                name = match.group(2).strip()
                name = re.sub(r"\s*\[CONTRIBUTE A TEST\].*$", "", name)
                techniques[current_technique] = name
                continue

            match = ATOMIC_RE.match(line)
            if match and current_technique:
                number = int(match.group(1))
                name = match.group(2).strip()
                name = re.sub(
                    r"\s+\[(?:windows|linux|macos)[^\]]*\]\s*$",
                    "",
                    name,
                    flags=re.IGNORECASE,
                )
                atomic_tests[current_technique][number] = name

    return techniques, atomic_tests


def extract_note(reason, category):
    """Chú thích của một dòng.

    - "No rule (abc)"  -> "abc"
    - "No rule"        -> ""
    - lý do khác       -> giữ nguyên toàn bộ lý do
    - trùng tên nhóm   -> "" (không cần lặp lại)
    """
    reason = clean(reason).strip('" ')
    match = NO_RULE_RE.match(reason)
    note = (match.group(1) or "") if match else reason
    note = clean(note).strip('" ')
    if fold(note) == fold(category):
        return ""
    return note


def canonical_category(raw, seen):
    """Gộp các biến thể hoa/thường của cùng một nhóm ('Khác' và 'khác')."""
    raw = clean(raw)
    if not raw:
        return UNCLASSIFIED
    key = fold(raw)
    for name in CATEGORY_ORDER:
        if fold(name) == key:
            return name
    if key not in seen:
        seen[key] = raw[0].upper() + raw[1:]
    return seen[key]


def load_rows(csv_path, techniques, atomic_tests):
    # data[category][technique_id][test_number] = {"label", "notes"}
    data = defaultdict(lambda: defaultdict(dict))
    unclassified = []
    seen = {}

    with csv_path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f, skipinitialspace=True)

        for row in reader:
            technique_id = (row.get("Technique") or "").strip()
            try:
                number = int(row["Test"])
            except (ValueError, KeyError, TypeError):
                continue

            category = canonical_category(row.get(CATEGORY_COLUMN), seen)
            if category == UNCLASSIFIED:
                unclassified.append((technique_id, number))

            test_name = atomic_tests.get(technique_id, {}).get(number)
            test_label = (
                f"{number}: {test_name}"
                if test_name
                else f"{number}: (chưa tìm thấy tên trong index)"
            )

            entry = data[category][technique_id].setdefault(
                number, {"label": test_label, "notes": set()}
            )
            note = extract_note(row.get(REASON_COLUMN), category)
            if note:
                entry["notes"].add(note)

    return data, unclassified


def build_table(category, techs, techniques):
    slug = slugify(category)
    caption = CAPTIONS.get(category, f"Các Atomic Test thuộc nhóm {category}")
    label = "tab:" + slug.replace("_", "-")
    header = (
        r"\textbf{Technique/Sub-technique} & \textbf{Atomic Test} "
        r"& \textbf{Chú thích} \\"
    )

    test_col_width = "6.2cm" if category == "No rule" else "5.5cm"
    note_col_width = "5.1cm" if category == "No rule" else "5.8cm"
    lines = [
        r"\begingroup",
        r"\small",
        r"\renewcommand{\arraystretch}{1.12}",
        r"\setlength{\LTpre}{0pt}",
        r"\setlength{\LTpost}{0pt}",
        r"\begin{longtable}{|>{\raggedright\arraybackslash}p{3.2cm}|"
        rf">{{\raggedright\arraybackslash}}p{{{test_col_width}}}|"
        rf">{{\raggedright\arraybackslash}}p{{{note_col_width}}}|}}",
        rf"\caption{{{latex_escape(caption)}}}\label{{{label}}}\\",
        r"\hline",
        header,
        r"\hline",
        r"\endfirsthead",
        r"\hline",
        header,
        r"\hline",
        r"\endhead",
        r"\hline",
        r"\endfoot",
        r"\hline",
        r"\endlastfoot",
    ]

    total_tests = 0

    for technique_id in sorted(techs):
        name = techniques.get(technique_id)
        technique_text = latex_escape(
            f"{technique_id} {name}" if name else technique_id
        )

        tests = techs[technique_id]
        rows = [
            (tests[n]["label"], "; ".join(sorted(tests[n]["notes"])))
            for n in sorted(tests)
        ]
        count = len(rows)
        total_tests += count

        for i, (test_label, note) in enumerate(rows):
            left = technique_text if i == 0 else ""

            # Gộp các test liền kề có cùng chú thích: chỉ ghi ở hàng đầu cụm.
            starts_run = i == 0 or note != rows[i - 1][1]
            note_text = latex_escape(note) if starts_run else ""

            cells = f"{left} & {latex_escape(test_label)} & {note_text}"

            if i == count - 1:
                lines.append(cells + r" \\")
                lines.append(r"\hline")
            else:
                # \\* cấm ngắt trang giữa các hàng cùng technique.
                lines.append(cells + r" \\*")
                if rows[i + 1][1] == note:
                    lines.append(r"\cline{2-2}")
                else:
                    lines.append(r"\cline{2-3}")

    lines.extend([r"\end{longtable}", r"\endgroup"])
    return "\n".join(lines) + "\n", total_tests, label


def build_reason_only_table(category, techs):
    """Build a companion table preserving columns but omitting test identifiers."""
    slug = slugify(category)
    caption = f"Nguyên nhân: {CAPTIONS.get(category, category)}"
    label = "tab:" + slug.replace("_", "-") + "-reasons"
    reasons = []
    for technique_id in sorted(techs):
        tests = techs[technique_id]
        for test_number in sorted(tests):
            entry = tests[test_number]
            note = "; ".join(sorted(entry["notes"]))
            reasons.append((technique_id, test_number, note))

    lines = [
        r"\begingroup", r"\small", r"\renewcommand{\arraystretch}{1.12}",
        r"\begin{longtable}{|>{\raggedright\arraybackslash}p{3.2cm}|"
        r">{\centering\arraybackslash}p{2.0cm}|"
        r">{\raggedright\arraybackslash}p{9.1cm}|}",
        rf"\caption{{{latex_escape(caption)}}}\label{{{label}}}\\",
        r"\hline",
        r"\textbf{Technique/Sub-technique} & \textbf{Atomic Test} & \textbf{Chú thích} " + r"\\",
        r"\hline", r"\endfirsthead", r"\hline",
        r"\textbf{Technique/Sub-technique} & \textbf{Atomic Test} & \textbf{Chú thích} " + r"\\",
        r"\hline", r"\endhead", r"\hline", r"\endfoot", r"\hline", r"\endlastfoot",
    ]
    for technique_id, test_number, reason in reasons:
        lines.append(
            f"{latex_escape(technique_id)} & {test_number} & {latex_escape(reason)} "
            + r"\\ \hline"
        )
    if not reasons:
        lines.append(r" &  & Không có chú thích nguyên nhân \\ \hline")
    lines.extend([r"\end{longtable}", r"\endgroup"])
    return "\n".join(lines) + "\n", len(reasons), label


def load_custom_rule_metadata(rules_dir):
    """Index custom TOML rules by display name, including language and ATT&CK IDs."""
    by_name = {}
    for path in Path(rules_dir).rglob("*.toml"):
        try:
            with path.open("rb") as f:
                rule = tomllib.load(f).get("rule", {})
        except (OSError, tomllib.TOMLDecodeError) as exc:
            print(f"Bỏ qua rule TOML không đọc được {path}: {exc}")
            continue
        name = clean(rule.get("name", ""))
        if not name:
            continue
        technique_ids = set()
        for threat in rule.get("threat", []):
            for technique in threat.get("technique", []):
                if technique.get("id"):
                    technique_ids.add(technique["id"])
                technique_ids.update(
                    sub.get("id") for sub in technique.get("subtechnique", [])
                    if sub.get("id")
                )
        by_name[fold(name)] = {
            "name": name,
            "language": clean(rule.get("language", "Không xác định")).upper(),
            "techniques": technique_ids,
        }
    return by_name


def build_custom_rules_per_technique_table(detections_csv, techniques):
    """Count distinct custom rules that actually alerted for each technique."""
    counts = defaultdict(set)
    with Path(detections_csv).open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f, skipinitialspace=True):
            technique_id = clean(row.get("Technique", ""))
            if not technique_id:
                continue
            alerted_rules = clean(row.get("Custom rules that alerted", ""))
            for rule_name in alerted_rules.split(";"):
                rule_name = clean(rule_name)
                if rule_name:
                    counts[technique_id].add(rule_name)

    rows = [
        (technique_id, techniques.get(technique_id, ""), len(rule_names), sorted(rule_names))
        for technique_id, rule_names in sorted(counts.items())
    ]
    header = r"\textbf{Technique/Sub-technique} & \textbf{Tên technique} & \textbf{Số custom rule} \\"
    lines = [
        r"\begingroup", r"\small", r"\renewcommand{\arraystretch}{1.12}",
        r"\begin{longtable}{|>{\raggedright\arraybackslash}p{3.5cm}|"
        r">{\raggedright\arraybackslash}p{8.5cm}|"
        r">{\centering\arraybackslash}p{2.0cm}|}",
        r"\caption{Số lượng custom rule bổ sung theo technique}\label{tab:custom-rules-per-technique}\\",
        r"\hline", header, r"\hline", r"\endfirsthead",
        r"\hline", header, r"\hline", r"\endhead", r"\hline", r"\endfoot",
        r"\hline", r"\endlastfoot",
    ]
    for technique_id, name, count, rule_names in rows:
        lines.append(
            f"{latex_escape(technique_id)} & {latex_escape(name)} & {count} "
            + r"\\ \hline"
        )
    lines.extend([r"\end{longtable}", r"\endgroup"])
    return "\n".join(lines) + "\n", len(rows)


def build_custom_detection_table(results_path, detections_csv, rules_dir):
    """Create compact rows grouped by technique and custom rule."""
    rule_metadata = load_custom_rule_metadata(rules_dir)
    detections = defaultdict(set)
    with Path(detections_csv).open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f, skipinitialspace=True):
            technique_id = clean(row.get("Technique", ""))
            try:
                number = int(row.get("Test", ""))
            except (TypeError, ValueError):
                continue
            # This CSV records the custom rules which alerted for each test.
            for candidate in clean(row.get("Custom rules that alerted", "")).split(";"):
                name = clean(candidate)
                metadata = rule_metadata.get(fold(name))
                if metadata:
                    detections[(technique_id, number)].add(
                        (metadata["name"], metadata["language"])
                    )

    grouped = defaultdict(set)
    for (technique_id, number), rules in detections.items():
        for rule_name, _language in rules:
            grouped[(technique_id, rule_name)].add(number)
    ordered_groups = sorted(
        grouped.items(),
        key=lambda item: (item[0][0], min(item[1]), fold(item[0][1])),
    )
    rows = [
        (f"{technique_id} - " + ", ".join(map(str, sorted(numbers))), rule_name)
        for (technique_id, rule_name), numbers in ordered_groups
    ]

    header = r"\textbf{Technique/Sub-technique -- Test \#} & \textbf{Detection Rule} \\"
    lines = [
        r"\begingroup", r"\small", r"\renewcommand{\arraystretch}{1.12}",
        r"\begin{longtable}{|>{\raggedright\arraybackslash}p{5.2cm}|"
        r">{\raggedright\arraybackslash}p{9.0cm}|}",
        r"\caption{Detection Rules bổ sung cho các Atomic Test chưa được phát hiện}\label{tab:custom-rule-detections}\\",
        r"\hline", header, r"\hline", r"\endfirsthead",
        r"\hline", header, r"\hline", r"\endhead", r"\hline", r"\endfoot",
        r"\hline", r"\endlastfoot",
    ]
    for test_label, rule_name in rows:
        lines.append(
            f"{latex_escape(test_label)} & {latex_escape(rule_name)} " + r"\\ \hline"
        )
    lines.extend([r"\end{longtable}", r"\endgroup"])
    return "\n".join(lines) + "\n", len(rows)


def build_tests_without_custom_detection_table(source_csv, atomic_tests):
    """List analysis CSV rows where no custom rule was written/alerted."""
    rows = []
    with Path(source_csv).open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f, skipinitialspace=True):
            if clean(row.get("Custom rules that alerted", "")):
                continue
            technique_id = clean(row.get("Technique", ""))
            try:
                number = int(row.get("Test", ""))
            except (TypeError, ValueError):
                continue
            test_name = atomic_tests.get(technique_id, {}).get(number)
            rows.append((
                technique_id, number,
                test_name or "(chưa có tên trong Atomic index)",
                clean(row.get("Phan loai", "")),
                clean(row.get("Reason no alert", "")),
            ))

    rows.sort(key=lambda row: (row[0], row[1]))
    header = r"\textbf{Technique} & \textbf{Test} & \textbf{Tên Atomic Test} \\"
    lines = [
        r"\begingroup", r"\small", r"\renewcommand{\arraystretch}{1.12}",
        r"\begin{longtable}{|>{\raggedright\arraybackslash}p{3.5cm}|"
        r">{\centering\arraybackslash}p{1.5cm}|"
        r">{\raggedright\arraybackslash}p{10.5cm}|}",
        r"\caption{Các Atomic Test chưa viết được rule bổ sung}\label{tab:tests-without-custom-detection}\\",
        r"\hline", header, r"\hline", r"\endfirsthead",
        r"\hline", header, r"\hline", r"\endhead", r"\hline", r"\endfoot",
        r"\hline", r"\endlastfoot",
    ]
    for technique_id, number, name, _category, _reason in rows:
        lines.append(
            f"{latex_escape(technique_id)} & {number} & {latex_escape(name)} "
            + r"\\ \hline"
        )
    lines.extend([r"\end{longtable}", r"\endgroup"])
    return "\n".join(lines) + "\n", len(rows)


def build_detection_summary_tex(results_path, atomic_log, pipeline_log):
    """Build LaTeX macros from the same failure policy as generate_report.py."""
    # Import locally so the existing CSV-to-table workflow remains usable
    # even when report dependencies are not needed for its other functions.
    import generate_report as report

    results = report.load_results(str(results_path))
    failures = report.merge_failures(
        report.parse_atomic_log(str(atomic_log)),
        report.parse_pipeline_log(str(pipeline_log)),
    )
    stats = report.compute_stats(results, failures)
    included = [
        result for result in results
        if (result["technique"], result["test_number"]) not in stats["failed_keys"]
    ]
    default_names = report.load_custom_rule_names(str(DEFAULT_RULES_DIR))
    custom_names = report.load_custom_rule_names(str(CUSTOM_RULES_DIR))
    default_techniques = report.load_windows_rule_techniques(str(DEFAULT_RULES_DIR))
    custom_techniques = report.load_windows_rule_techniques(str(CUSTOM_RULES_DIR))
    rows = report.build_detection_source_rows(
        results, custom_names, default_names, stats["failed_keys"]
    )
    custom_only = {
        (row["Technique"], row["Test"])
        for row in rows if row["Classification"] == "Detected with custom rules"
    }
    default_detected_techniques = {
        row["Technique"] for row in rows
        if row["Classification"] == "Detected by default rules"
    }
    custom_detected_techniques = {
        row["Technique"] for row in rows
        if row["Classification"] == "Detected with custom rules"
    }
    default_results = report.results_for_rule_scope(
        included, default_techniques | default_detected_techniques,
        custom_only, default_only=True,
    )
    combined_results = report.results_for_rule_scope(
        included, default_techniques | custom_techniques |
        default_detected_techniques | custom_detected_techniques,
    )
    default_stats = report.compute_stats(default_results, {})
    combined_stats = report.compute_stats(combined_results, {})

    macros = {
        "AtomicTestsTotal": len(results),
        "AtomicTestsFailed": len(stats["failed_tests"]),
        "CustomRulesWritten": len(report.load_custom_rule_names(str(CUSTOM_RULES_DIR))),
    }
    for prefix, scoped in (("Default", default_stats), ("AfterCustom", combined_stats)):
        macros.update({
            f"{prefix}TestsIncluded": scoped["considered_count"],
            f"{prefix}TestsDetected": scoped["detected_count"],
            f"{prefix}TestsUndetected": scoped["undetected_count"],
            f"{prefix}DetectionRate": f"{scoped['detection_rate']:.1f}",
            f"{prefix}TechniquesTotal": len(scoped["tech_stats"]),
            f"{prefix}TechniquesFullyDetected": scoped["status_count"].get("Fully detected", 0),
            f"{prefix}TechniquesPartiallyDetected": scoped["status_count"].get("Partially detected", 0),
            f"{prefix}TechniquesNotDetected": scoped["status_count"].get("Not detected", 0),
            f"{prefix}TechniquesNoRule": scoped["status_count"].get("No rule", 0),
        })
    # TeX consumes ordinary source whitespace after a control word such as
    # \DefaultTestsIncluded. Add an explicit control-space to count macros;
    # rates also include their percent sign and trailing control-space.
    for name, value in list(macros.items()):
        if name.endswith("DetectionRate"):
            macros[name] = rf"{value}\%\ "
        elif isinstance(value, int):
            macros[name] = rf"{value}\ "
    lines = [
        "% Tự sinh bởi generate_tex.py; không chỉnh sửa thủ công.",
        "% Nạp trong luận văn bằng: \\input{.../tex/detection_statistics.tex}",
    ]
    lines.extend(rf"\newcommand{{\{name}}}{{{value}}}" for name, value in macros.items())
    return "\n".join(lines) + "\n", macros


def main():
    techniques, atomic_tests = load_atomic_index(INDEX_FILE)
    data, unclassified = load_rows(CSV_FILE, techniques, atomic_tests)

    OUTPUT_DIR.mkdir(exist_ok=True)
    TEX_DIR.mkdir(exist_ok=True)

    ordered = [c for c in CATEGORY_ORDER if c in data]
    ordered += [c for c in data if c not in CATEGORY_ORDER]

    grand_total = 0
    print(f"{'Nhóm':<28}{'Số test':>8}  File / label")
    for category in ordered:
        text, total, label = build_table(category, data[category], techniques)
        path = OUTPUT_DIR / f"{slugify(category)}_table.tex"
        path.write_text(text, encoding="utf-8")
        grand_total += total
        print(f"{category:<28}{total:>8}  {path}  ({label})")

    for category in ("No rule", "Không ánh xạ", "Rule chưa hoàn thiện", "Log không đủ"):
        if category not in data:
            continue
        reason_tex, reason_count, reason_label = build_reason_only_table(category, data[category])
        reason_path = TEX_DIR / f"{slugify(category)}_reasons.tex"
        reason_path.write_text(reason_tex, encoding="utf-8")
        print(f"Bảng nguyên nhân {category}: {reason_count} nguyên nhân, {reason_path} ({reason_label})")

    print(f"{'Tổng':<28}{grand_total:>8}")

    summary_tex, summary_macros = build_detection_summary_tex(
        RESULTS_FILE, ATOMIC_LOG, PIPELINE_LOG
    )
    summary_path = TEX_DIR / "detection_statistics.tex"
    summary_path.write_text(summary_tex, encoding="utf-8")
    print(f"Đã tạo số liệu LaTeX: {summary_path}")
    print(json.dumps(summary_macros, ensure_ascii=False, indent=2))

    custom_table, custom_rows = build_custom_detection_table(
        RESULTS_FILE, CUSTOM_DETECTIONS_CSV, CUSTOM_RULES_DIR
    )
    custom_table_path = TEX_DIR / "custom_rule_detections.tex"
    custom_table_path.write_text(custom_table, encoding="utf-8")
    print(f"Đã tạo bảng custom rule: {custom_table_path} ({custom_rows} dòng)")

    rules_per_technique, technique_count = build_custom_rules_per_technique_table(
        CSV_FILE, techniques
    )
    rules_per_technique_path = TEX_DIR / "custom_rules_per_technique.tex"
    rules_per_technique_path.write_text(rules_per_technique, encoding="utf-8")
    print(f"Đã tạo bảng số custom rule theo technique: {rules_per_technique_path} ({technique_count} technique)")

    without_custom, without_custom_count = build_tests_without_custom_detection_table(
        DETECTION_SOURCE_CSV, atomic_tests
    )
    without_custom_path = TEX_DIR / "tests_without_custom_detection.tex"
    without_custom_path.write_text(without_custom, encoding="utf-8")
    print(f"Đã tạo bảng test chưa được custom rule phát hiện: {without_custom_path} ({without_custom_count} dòng)")

    if unclassified:
        print("\nCảnh báo: dòng chưa có giá trị ở cột "
              f"'{CATEGORY_COLUMN}':")
        for technique_id, number in unclassified:
            print(f"  {technique_id} test {number}")


if __name__ == "__main__":
    main()
