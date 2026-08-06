"""
main.py
-------
Entrypoint for the Atomic Red Team + Elastic detection pipeline.
Coordinates: test_planner -> atomic_runner -> elastic_client -> result_store.

Usage:
    python3 main.py                  # run pending tests (resume by default)
    python3 main.py --fresh          # wipe previous results and start over
    python3 main.py --plan other.json
"""
from __future__ import annotations

import argparse
import logging
import sys
import time

from pipeline import atomic_runner, elastic_client, result_store, test_planner
from pipeline.config import load_settings
from pipeline.models import TestResult

logger = logging.getLogger("pipeline")

def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("logs/pipeline.log", encoding="utf-8"),
        ],
    )

def run_single_test(settings, test, rule_map) -> TestResult:
    rule_ids = rule_map.by_technique.get(test.technique, [])
    has_rule = bool(rule_ids)

    if not has_rule:
        logger.info('Skipping %s %s: no detection rules for this technique', 
                    test.technique, test.test_number)
        return TestResult(
            technique=test.technique,
            test_number=test.test_number,
            has_rule=False,
            status="no_rule",
        )

    try: 
        start, end = atomic_runner.run_atomic_tests(settings, [test])
    except Exception as e:
        logger.warning('Skipping %s %s due to run failure: %s', test.technique, test.test_number, e)

        return TestResult(
            technique=test.technique,
            test_number=test.test_number,
            has_rule=has_rule,
            status="failed",
        )
    
    elastic_client.trigger_rules(settings, rule_ids, start, end)
    time.sleep(5)
    remaining = elastic_client.wait_rules_completed(settings, rule_ids, end)
    if remaining:
        logger.warning('Some rules did not finish in time: %s', remaining)

    alerts = elastic_client.fetch_matching_alerts(settings, test.technique, end, start, end)

    return TestResult(
        technique=test.technique,
        test_number=test.test_number,
        has_rule=has_rule,
        start_time=start,
        end_time=end,
        alerts=alerts,
        status="detected" if alerts else "undetected",
    )

def run_pipeline(settings, plan_path: str, fresh: bool) -> None:
    if fresh: 
        logger.info('Fresh run requested, clearing previous results')
        result_store.reset()

    rule_map = elastic_client.get_rule_mapping(settings)
    tests = test_planner.pending_tests(plan_path)

    if not tests:
        logger.info('Nothing to run, all tests already have results')
        return 
    
    logger.info(f'Runnging {len(tests)} tests')
    for i, test in enumerate(tests, start=1):
        logger.info("[%d/%d] %s test %d", i, len(tests), test.technique, test.test_number)
        result = run_single_test(settings, test, rule_map)
        result_store.append(result)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", default="tests_plan.json",
                         help="Path to the test plan JSON file")
    parser.add_argument("--fresh", action="store_true",
                         help="Discard previous results and start from scratch")
    return parser.parse_args()

def main() -> None:
    setup_logging()
    args = parse_args()
    settings = load_settings()
    run_pipeline(settings, args.plan, args.fresh)

if __name__ == '__main__':
    main()


