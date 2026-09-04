from __future__ import annotations

import json
import os

from pipeline import result_store
from pipeline.models import AtomicTest


def load_failed_test_keys(path: str) -> set[tuple[str, int]]:
    """Load the failed-test manifest written by generate_report.py.

    A missing or malformed manifest is an error when the caller explicitly
    requested exclusion; silently running known-bad tests would be surprising.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Failed-test manifest not found: {path}. Run generate_report.py first "
            "or pass --failed-tests-file PATH."
        )

    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    entries = data.get("failed_tests") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected an object with a failed_tests list")

    keys = set()
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: failed_tests entry {index} is not an object")
        technique = entry.get("technique")
        test_number = entry.get("test_number")
        if not isinstance(technique, str) or not isinstance(test_number, int) or test_number < 1:
            raise ValueError(f"{path}: invalid failed_tests entry {index}")
        keys.add((technique, test_number))
    return keys

def _validate_entry(technique:str, test_numbers) -> None:
    if not isinstance(technique, str) or not technique.startswith('T'):
        raise ValueError(f'tests_plan.json: invalid technique key {technique}')
    if not isinstance(test_numbers, list) or not test_numbers:
        raise ValueError(f'tests_plan.json: invalid test_numbers: {test_numbers!r}')
    for n in test_numbers:
        if not isinstance (n, int) or n < 1: 
            raise ValueError(f'tests_plan.json: technique {technique} has invalid test numbers {n}')

def load_plan(path: str = 'test_plan.json', technique_filter: set[str] | None = None) -> list[AtomicTest]:
    with open(path) as f:
        plan = json.load(f)

    if not isinstance(plan, dict):
        raise ValueError('test_plan.json must be flat object')

    if technique_filter:
        missing = technique_filter - set(plan.keys())
        if missing:
            print(f"[test_planner] Warning: requested technique(s) not found in "
                  f"{path}: {sorted(missing)}")

    tests = []
    for technique, test_numbers in plan.items():
        if technique_filter and technique not in technique_filter:
            continue
        _validate_entry(technique, test_numbers) 

        seen = set()
        for n in test_numbers:
            if n in seen:
                print(f"[test_planner] Warning: duplicate test number {n} for technique {technique}")
                continue
            seen.add(n)
            tests.append(AtomicTest(technique=technique, test_number=n))
    return tests

def pending_tests(path: str = 'tests_plan.json', technique_filter: set[str] | None = None) -> list[AtomicTest]:
    all_tests = load_plan(path, technique_filter)
    done_keys = result_store.load_done_keys()

    remaining = [
        t for t in all_tests
        if (t.technique, t.test_number) not in done_keys
    ]

    skipped = len(all_tests) - len(done_keys)
    # if skipped:
    #     print(f"[test_planner] Resume: skipping {skipped} already-done test(s), {len(remaining)} remaining")

    return remaining


