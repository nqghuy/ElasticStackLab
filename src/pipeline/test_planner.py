from __future__ import annotations

import json

from pipeline import result_store
from pipeline.models import AtomicTest

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
    if skipped:
        print(f"[test_planner] Resume: skipping {skipped} already-done test(s), {len(remaining)} remaining")

    return remaining



