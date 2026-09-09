from __future__ import annotations

import logging
import time

import requests
import urllib3

from collections import defaultdict
from dateutil.parser import isoparse

from pipeline.config import Settings
from pipeline.models import Alert, RuleMapping
from datetime import datetime

logger = logging.getLogger(__name__)

TARGET_TAG = "OS: Windows"

def _request(settings: Settings, method: str, url: str, **kwargs) -> requests.response:
    if not settings.elastic.verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers = kwargs.pop('headers', {})
    headers.setdefault("kbn-xsrf", "true")
    headers.setdefault("Content-Type", "application/json")

    try:
        response = requests.request(
            method,
            url,
            auth = settings.elastic.auth,
            headers = headers,
            verify = settings.elastic.verify_ssl,
            timeout = 30,
            **kwargs
        )
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        body = getattr(e.response, "text", "")
        logger.error("Request %s %s failed: %s | body=%s", method, url, e, body)
        raise

def get_rule_mapping(settings: Settings) -> RuleMapping:
    url = f"{settings.elastic.kibana_url}/api/detection_engine/rules/_find"
    response = _request(settings, "GET", url, params={"per_page":2000})
    rules_data = response.json()

    enabled_rules: list[str] = []
    by_technique: dict[str, list[str]] = {}

    for rule in rules_data["data"]:
        if not rule.get("enabled", False):
            continue 

        if TARGET_TAG not in rule.get("tags", []):
            continue

        enabled_rules.append(rule["id"])

        for threat in rule.get('threat', []):
            for tech in threat.get('technique', []):
                by_technique.setdefault(tech['id'], []).append(rule['id'])
                for sub in tech.get('subtechnique', []):
                    by_technique.setdefault(sub['id'], []).append(rule['id'])

    logger.info('Find %s enabled rules (tag=%s)', len(enabled_rules), TARGET_TAG)
    if not enabled_rules:
        raise RuntimeError(
            f'No found any rule with tag {TARGET_TAG}.'
        )
    return RuleMapping(by_technique=by_technique)

def get_all_rules(settings: Settings) -> list[str]:
    url = f"{settings.elastic.kibana_url}/api/detection_engine/rules/_find"
    response = _request(settings, "GET", url, params={"per_page":2000})
    rules_data = response.json()

    all_rules_ids = []

    for rule in rules_data["data"]:
        if not rule.get("enabled", False):
            continue 

        if TARGET_TAG not in rule.get("tags", []):
            continue

        all_rules_ids.append(rule["id"])
    return all_rules_ids

# Run rules manually from [start, end]
def trigger_rules(settings: Settings, rule_ids: list[str], start: str, end: str) -> None:
    if not rule_ids:
        logger.info('No rules to trigger')
        return 
    
    batch_size = 50
    url = f'{settings.elastic.kibana_url}/api/detection_engine/rules/_bulk_action'
    for i in range(0, len(rule_ids), batch_size):
        batch = rule_ids[i: i + 100]
        payload = {
            "action": "run",
            "ids": batch,
            "run": {
                "start_date": start,
                "end_date": end
                }
            }
        _request(settings, "POST", url, json=payload)

    logger.info("Triggered %s rules", len(rule_ids))

# Wait all triggered rules complete
def wait_rules_completed(settings: Settings, rule_ids: list[str], since: str) -> list[str]:
    """ 
    Request to .kibana-event-log-* and check 'Rule execution completed successfully'
    End early if some rules has error
    """ 
    if not rule_ids:
        return []

    remaining = set(rule_ids)
    url = f"{settings.elastic.base_url}/.kibana-event-log-*/_search"
    unchanged_count = 0
    previous_count = len(remaining)

    while (remaining):
        payload = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gt": since}}},
                        {"match_phrase": {"message": "Rule execution completed successfully"}},
                        {"terms": {"rule.id": list(remaining)}},
                    ]
                }
            },
            "aggs": {
                "completed_rules": {
                    "terms": {"field": "rule.id", "size": len(remaining)}
                }
            },
        }
        response = _request(settings, 'POST', url, json=payload)
        bucket = response.json()["aggregations"]["completed_rules"]["buckets"]
        completed_rules = {b['key'] for b in bucket}
        remaining -= completed_rules

        logger.info('%d rules not complete', len(remaining))

        current_count = len(remaining)
        if current_count == previous_count:
            unchanged_count += 1
        else:
            unchanged_count = 0
            previous_count = current_count

        if unchanged_count >= settings.rule_wait.unchanged_limit:
            logger.warning(
                '%d rules not change after %d check', current_count, settings.rule_wait.unchanged_limit
            )
            break
        if remaining:
            time.sleep(settings.rule_wait.poll_interval_sec)

    return list(remaining)

# Get value of required fields in alert to be reasons
def _extract_reason(source: dict) -> dict:
    reason = {}
    required = source.get("kibana.alert.rule.parameters", {}).get("required_fields", [])

    for field in required:

        field_name = field["name"]

        value = source

        for part in field_name.split("."):
            if isinstance(value, dict):
                value = value.get(part)
            else:
                value = None
                break

        if value is not None:
            reason[field_name] = value

    return reason

# Check if any alerts generated by the test
def _fetch_all_alerts_since(settings: Settings, since: str) -> list[dict]:
    url = f"{settings.elastic.kibana_url}/api/detection_engine/signals/search"
    payload = {
            "size": 10000,
            "query": {"range": {"@timestamp": {"gte": since, "lte": "now"}}},
        } 
    response = _request(settings, "POST", url, json=payload)
    return response.json()['hits']['hits']

def _fetch_ancestor_timestamps(settings: Settings, ancestors) -> dict[tuple[str, str], datetime]:
    groups = defaultdict(set)
    for ancestor in ancestors:

        if ancestor.get("type") != "event":
            continue

        groups[ancestor["index"]].add(ancestor["id"])

    ancestor_timestamp = {}

    for index, ids in groups.items():
        payload = {
            "_source": ["@timestamp"],
            "size": len(ids),
            "query": {
                "ids": {
                    "values": list(ids)
                }
            }
        }

        url = f"{settings.elastic.base_url}/{index}/_search"

        response = _request(
            settings,
            "POST",
            url,
            json=payload,
        )
        for hit in response.json()["hits"]["hits"]:
            ancestor_timestamp[(hit["_index"], hit["_id"])] = isoparse(hit["_source"]["@timestamp"])

    return ancestor_timestamp

def _validate_ancestors(ancestors, ancestor_timestamp, start, end):
    start_dt = isoparse(start)
    end_dt = isoparse(end)

    for ancestor in ancestors:
        if ancestor.get('type', '') != 'event':
            continue
        ts = ancestor_timestamp.get(
            (
                ancestor["index"],
                ancestor["id"]
            )
        )
        if ts is None:
            logger.warning("Could not resolve timestamp for ancestor %s in index %s, "
                           "skipping this ancestor's validation", ancestor["id"], ancestor["index"])
            continue
        if ts < start_dt or ts > end_dt:
            return False
    return True

def extract_matching_alert(settings: Settings, all_alerts: list, all_tests: list) -> list:
    all_tests_results = all_tests.copy()

    for hit in all_alerts:
        source = hit["_source"]
        ancestors = (source.get('kibana.alert.ancestors', []))
        alert_name = source["kibana.alert.rule.name"]
        if 'High Number of Process and' in alert_name:
            continue
        ancestor_timestamp = _fetch_ancestor_timestamps(settings, ancestors)
        for test in all_tests:
            if test.start_time is None or test.end_time is None:
                continue
            if _validate_ancestors(ancestors, ancestor_timestamp, test.start_time, test.end_time):
                threats = source.get("kibana.alert.rule.threat", [])
                alert_name = source["kibana.alert.rule.name"]
                reason = _extract_reason(source)

                if any(reason == alert.reason for alert in test.alerts): continue

                for threat in threats:
                    for tech in threat.get("technique", []):
                        ids_to_check = {tech["id"]}
                        ids_to_check |= {sub["id"] for sub in tech.get("subtechnique", [])}

                        if test.technique in ids_to_check:
                            test.alerts.append(Alert(name=alert_name, reason=reason))
                            test.status = 'detected'
                            break
    return all_tests_results
