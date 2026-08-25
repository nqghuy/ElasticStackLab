"""
main.py
-------
Entrypoint for the Atomic Red Team + Elastic detection pipeline.
Coordinates: test_planner -> atomic_runner -> elastic_client -> result_store.
 
Pass -o/--output to override #1 with a single explicit file for the
whole run instead of auto-naming per technique (still also written to
the shared file, unless -o already points at it).
 
Usage:
    python3 main.py                          # run all pending tests (resume by default)
    python3 main.py --fresh                  # wipe previous results and logs, start over
    python3 main.py --plan other.json
    python3 main.py -t T1053.005             # writes output/results_T1053.005.jsonl + results.jsonl
    python3 main.py -t T1053.005 -t T1547.001   # writes results_T1053.005.jsonl AND
                                                 # results_T1547.001.jsonl (each separate)
                                                 # + results.jsonl (combined)
    python3 main.py -t T1053.005 -o output/custom.jsonl   # writes custom.jsonl + results.jsonl
                                                            # (no per-technique file, -o overrides it)
"""

import argparse
import logging
import sys
import time

from pipeline import atomic_runner, elastic_client, result_store, test_planner
from pipeline.config import load_settings
from pipeline.models import TestResult
from datetime import datetime, timezone, timedelta

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
    """
    if not has_rule:
        logger.info('Skipping %s %s: no detection rules for this technique', 
                    test.technique, test.test_number)
        return TestResult(
            technique=test.technique,
            test_number=test.test_number,
            has_rule=False,
            status="no_rule",
        )
    """
    try: 
        start, end = atomic_runner.run_atomic_tests(settings, [test])
    except Exception as e:
        logger.warning('Skipping %s %s due to run failure: %s', test.technique, test.test_number, e)

        return TestResult(
            technique=test.technique,
            test_number=test.test_number,
            has_rule=True,
            status="failed",
        )
    # time.sleep(5) 
    # elastic_client.trigger_rules(settings, rule_ids, start, end)
    # time.sleep(2)
    # remaining = elastic_client.wait_rules_completed(settings, rule_ids, end)
    # if remaining:
    #     logger.warning('Some rules did not finish in time: %s', remaining)

    # alerts = elastic_client.fetch_matching_alerts(settings, test.technique, end, start, end)

    return TestResult(
        technique=test.technique,
        test_number=test.test_number,
        has_rule=True,
        start_time=start,
        end_time=end,
        alerts=[],
        status="undetected",
    )

def run_pipeline(settings, plan_path: str, output_arg, technique_filter: set[str] | None, fresh: bool = False) -> None:
    st = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    if fresh: 
        logger.info('Fresh run requested, clearing previous results')
        result_store.reset(technique_filter)
    
    # all_results = result_store.load_all()
    rule_map = elastic_client.get_rule_mapping(settings)

    tests = test_planner.pending_tests(plan_path, technique_filter)
    
    if not tests:
        logger.info('Nothing to run, all tests already have results')
        return 
    
    logger.info(f'Runnging {len(tests)} tests')
    
    all_tests = []
    for i, test in enumerate(tests, start=1):
        logger.info("[%d/%d] %s test %d", i, len(tests), test.technique, test.test_number)
        result = run_single_test(settings, test, rule_map)
        all_tests.append(result)
        time.sleep(2)
    
    time.sleep(5) 

    # Trigger rules
    if technique_filter is not None:
        trigger_rule_ids = list({
            rule_id
            for t in technique_filter
            for rule_id in rule_map.by_technique.get(t, [])
        })
    else: 
        trigger_rule_ids = elastic_client.get_all_rules(settings)
    
    trigger_time = datetime.now(timezone.utc)
    start_time = (trigger_time - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_time = trigger_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    elastic_client.trigger_rules(settings, trigger_rule_ids, start_time, end_time)

    # Waiting all rules run successfully
    remaining = elastic_client.wait_rules_completed(settings, trigger_rule_ids, end_time)
    if remaining:
        logger.warning('Some rules did not finish in time: %s', remaining)

    # Get results
    all_alerts = elastic_client._fetch_all_alerts_since(settings, st)
    all_tests_results = elastic_client.extract_matching_alert(settings, all_alerts, all_tests)

    # Store result into files
    result_store.replace_all(all_tests_results)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", default="tests_plan.json",
                         help="Path to the test plan JSON file")
    parser.add_argument("--fresh", action="store_true",
                         help="Discard previous results and logs, start from scratch")
    parser.add_argument("-t", "--technique", action="append", metavar="TECHNIQUE_ID",
                         help="Only run this technique (e.g. -t T1053.005). Can be given "
                              "multiple times - each technique still gets its own dedicated "
                              "results file. If omitted, every technique in the plan is run.")
    parser.add_argument("-o", "--output", default=None, metavar="PATH",
                         help="Write every test in this run to this single file (in addition "
                              "to the shared output/results.jsonl), instead of auto-naming a "
                              "separate file per technique.")
    return parser.parse_args()

def main() -> None:
    setup_logging()
    args = parse_args()
    technique_filter = set(args.technique) if args.technique else None

    if technique_filter:
        logger.info("Restricting run to technique(s): %s", sorted(technique_filter))

    settings = load_settings()
    run_pipeline(settings, args.plan, args.output, technique_filter, args.fresh)

if __name__ == '__main__':
    main()


