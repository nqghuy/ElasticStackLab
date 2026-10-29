import csv
import re
import unicodedata
import json
from collections import defaultdict
from pathlib import Path

CSV_FILE = Path("not_detect.csv")
INDEX_FILE = Path("windows-index.md")
OUTPUT_DIR = Path("tables")
RESULTS_FILE = Path("output/results.jsonl")
ATOMIC_LOG = Path("logs/atomic_stdout.log")
PIPELINE_LOG = Path("logs/pipeline.log")
TEX_DIR = Path("tex")

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
    "No rule": "Các Atomic Test chưa có Detection Rule phù hợp",
    "Không ánh xạ": "Các Atomic Test có rule nhưng chưa ánh xạ đúng technique",
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

    lines = [
        r"\begingroup",
        r"\small",
        r"\renewcommand{\arraystretch}{1.12}",
        r"\setlength{\LTpre}{0pt}",
        r"\setlength{\LTpost}{0pt}",
        r"\begin{longtable}{|>{\raggedright\arraybackslash}p{3.2cm}|"
        r">{\raggedright\arraybackslash}p{5.5cm}|"
        r">{\raggedright\arraybackslash}p{5.8cm}|}",
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
    successful = [
        result for result in results
        if (result["technique"], result["test_number"]) not in stats["failed_keys"]
    ]
    clean_stats = report.compute_stats(successful, {})
    total_techniques = len(clean_stats["tech_stats"])
    no_rule = clean_stats["status_count"].get("No rule", 0)
    fully = clean_stats["status_count"].get("Fully detected", 0)
    partial = clean_stats["status_count"].get("Partially detected", 0)
    not_detected = clean_stats["status_count"].get("Not detected", 0)

    macros = {
        "AtomicTestsTotal": len(results),
        "AtomicTestsFailed": len(stats["failed_tests"]),
        "AtomicTestsDetected": clean_stats["detected_count"],
        "AtomicTestsUndetected": clean_stats["undetected_count"],
        "AtomicDetectionRate": f"{clean_stats['detection_rate']:.1f}",
        "TechniquesTotal": total_techniques,
        "TechniquesFullyDetected": fully,
        "TechniquesPartiallyDetected": partial,
        "TechniquesNotDetected": not_detected,
        "TechniquesNoRule": no_rule,
    }
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

    print(f"{'Tổng':<28}{grand_total:>8}")

    summary_tex, summary_macros = build_detection_summary_tex(
        RESULTS_FILE, ATOMIC_LOG, PIPELINE_LOG
    )
    summary_path = TEX_DIR / "detection_statistics.tex"
    summary_path.write_text(summary_tex, encoding="utf-8")
    print(f"Đã tạo số liệu LaTeX: {summary_path}")
    print(json.dumps(summary_macros, ensure_ascii=False, indent=2))

    if unclassified:
        print("\nCảnh báo: dòng chưa có giá trị ở cột "
              f"'{CATEGORY_COLUMN}':")
        for technique_id, number in unclassified:
            print(f"  {technique_id} test {number}")


if __name__ == "__main__":
    main()
