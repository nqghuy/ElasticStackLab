from __future__ import annotations

import json
import os
from dataclasses import asdict

from pipeline.models import Alert, TestResult

RESULTS_FILE = 'output/results.jsonl'
PIPELINE_LOG = "logs/pipeline.log"
ATOMIC_STDOUT_LOG = 'logs/atomic_stdout.log'

def append(result: TestResult) -> None:
    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    with open(RESULTS_FILE, 'a') as f:
        f.write(json.dumps(asdict(result)))
        f.write('\n')

def _dict_to_result(data: dict) -> TestResult:
    alerts = [Alert(**a) for a in data.get('alerts', [])]
    return TestResult(
        technique=data['technique'],
        test_number=data['test_number'],
        alerts=alerts,
        has_rule=data.get('has_rule', True),
        start_time=data.get('start_time'),
        end_time=data.get('end_time'),
        status=data.get('status', 'pending')
    )

def load_all() -> list[TestResult]:
    if not os.path.exists(RESULTS_FILE):
        return []

    results = []
    with open(RESULTS_FILE, 'r') as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try: 
                data = json.loads(line)
            except json.JSONDecodeError:
                print(f'Error line {line_no}')
            results.append(_dict_to_result(data))
    return results

# This function is used when program continue after crash
def load_done_keys() -> set[tuple[str, int]]:
    return {(r.technique, r.test_number) for r in load_all()}

def _clear_file(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w").close()

def reset() -> None:
    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    open(RESULTS_FILE, "w").close()
    _clear_file(PIPELINE_LOG)
    _clear_file(ATOMIC_STDOUT_LOG)


