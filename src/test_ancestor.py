#!/usr/bin/env python3
"""Kiểm tra timestamp của event ancestors trong các alert của Elastic Security.

Chạy từ thư mục gốc của project:
    python test_ancestor.py

Có thể chỉ định khoảng thời gian khác:
    python test_ancestor.py --start '2026-10-09T17:46:41.000Z' \
        --end '2026-10-09T19:36:09.000Z'

Mặc định, script đọc config.yaml và .env ở thư mục hiện tại, giống load_settings()
trong pipeline.config. Script chỉ đọc dữ liệu, không chạy hoặc thay đổi detection rule.
"""

from __future__ import annotations

import argparse
import logging
from datetime import datetime
from typing import Any

from dateutil.parser import isoparse

from pipeline.config import load_settings
from pipeline.elastic_client import (
    _fetch_all_alerts_since,
    _fetch_ancestor_timestamps,
)


DEFAULT_START = "2026-10-09T17:46:41.000Z"
DEFAULT_END = "2026-10-09T19:36:09.000Z"

logger = logging.getLogger("test_ancestor")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Kiểm tra timestamp của event ancestors trong một khoảng thời gian."
    )
    parser.add_argument(
        "--start",
        default=DEFAULT_START,
        help=f"Thời điểm bắt đầu ISO 8601 (mặc định: {DEFAULT_START})",
    )
    parser.add_argument(
        "--end",
        default=DEFAULT_END,
        help=f"Thời điểm kết thúc ISO 8601 (mặc định: {DEFAULT_END})",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Đường dẫn config YAML (mặc định: config.yaml)",
    )
    parser.add_argument(
        "--env",
        default=".env",
        help="Đường dẫn file môi trường (mặc định: .env)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="Mức log (mặc định: INFO)",
    )
    return parser.parse_args()


def parse_timestamp(value: Any) -> datetime | None:
    """Parse ISO timestamp; trả về None nếu giá trị thiếu hoặc không hợp lệ."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return isoparse(value)
    except (TypeError, ValueError, OverflowError):
        return None


def get_source(hit: dict[str, Any]) -> dict[str, Any]:
    source = hit.get("_source", {})
    return source if isinstance(source, dict) else {}


def get_event_ancestors(ancestors: Any) -> list[dict[str, Any]]:
    """Chỉ lấy ancestor type=event; bỏ qua metadata sai định dạng."""
    if not isinstance(ancestors, list):
        return []
    return [
        ancestor
        for ancestor in ancestors
        if isinstance(ancestor, dict) and ancestor.get("type") == "event"
    ]


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    start_dt = parse_timestamp(args.start)
    end_dt = parse_timestamp(args.end)
    if start_dt is None or end_dt is None:
        logger.error("START hoặc END không phải timestamp ISO 8601 hợp lệ.")
        return 2
    if start_dt.tzinfo is None or end_dt.tzinfo is None:
        logger.error("START và END cần có timezone, ví dụ hậu tố Z hoặc +07:00.")
        return 2
    if start_dt > end_dt:
        logger.error("START phải nhỏ hơn hoặc bằng END.")
        return 2

    try:
        settings = load_settings(config_path=args.config, env_path=args.env)
    except Exception as exc:
        logger.exception(
            "Không tải được cấu hình. Kiểm tra config.yaml, .env và ELASTIC_PASSWORD: %s",
            exc,
        )
        return 2

    print("=" * 78)
    print("ELASTIC SECURITY - EVENT ANCESTOR TIMESTAMP CHECK")
    print(f"Time range : {args.start} -> {args.end}")
    print(f"Kibana URL : {settings.elastic.kibana_url}")
    print("=" * 78)

    try:
        # API này lấy alert từ START đến hiện tại; lọc END chính xác ở Python.
        fetched_alerts = _fetch_all_alerts_since(settings, args.start)
    except Exception as exc:
        logger.exception("Không lấy được alert từ Kibana: %s", exc)
        return 1

    alerts_in_range: list[dict[str, Any]] = []
    invalid_alert_timestamps = 0

    for hit in fetched_alerts:
        source = get_source(hit)
        alert_dt = parse_timestamp(source.get("@timestamp"))
        if alert_dt is None:
            invalid_alert_timestamps += 1
            continue
        if start_dt <= alert_dt <= end_dt:
            alerts_in_range.append(hit)

    # Sắp xếp theo thời gian tăng dần để output dễ đối chiếu với lần chạy test.
    alerts_in_range.sort(
        key=lambda hit: parse_timestamp(get_source(hit).get("@timestamp"))
        or start_dt
    )

    # Gom ancestor của mọi alert lại để hạn chế số lần gọi Elasticsearch.
    event_ancestors_by_alert: list[list[dict[str, Any]]] = []
    all_event_ancestors: list[dict[str, Any]] = []
    for hit in alerts_in_range:
        source = get_source(hit)
        event_ancestors = get_event_ancestors(
            source.get("kibana.alert.ancestors", [])
        )
        event_ancestors_by_alert.append(event_ancestors)
        all_event_ancestors.extend(event_ancestors)

    try:
        ancestor_timestamps = _fetch_ancestor_timestamps(
            settings, all_event_ancestors
        )
    except Exception as exc:
        logger.exception("Không truy vấn được timestamp của ancestor: %s", exc)
        return 1

    # Bộ đếm theo từng ancestor occurrence trong alert.
    resolved_count = 0
    unresolved_count = 0
    invalid_count = 0
    in_range_count = 0
    out_of_range_count = 0
    no_event_ancestor_alerts = 0
    verified_alerts = 0
    unverified_alerts = 0
    out_of_range_alerts = 0

    print(f"Alerts fetched from Kibana : {len(fetched_alerts)}")
    print(f"Alerts in requested range  : {len(alerts_in_range)}")
    if invalid_alert_timestamps:
        print(f"Alerts with invalid/missing timestamp (skipped): {invalid_alert_timestamps}")

    for index, hit in enumerate(alerts_in_range, start=1):
        source = get_source(hit)
        alert_name = source.get("kibana.alert.rule.name", "Unknown rule")
        alert_timestamp = source.get("@timestamp", "<missing>")
        ancestors = event_ancestors_by_alert[index - 1]

        print("\n" + "-" * 78)
        print(f"Alert #{index}: {alert_name}")
        print(f"Alert timestamp: {alert_timestamp}")
        print(f"Alert ID/index : {hit.get('_id', '<unknown>')} / {hit.get('_index', '<unknown>')}")

        if not ancestors:
            no_event_ancestor_alerts += 1
            unverified_alerts += 1
            print("  STATUS: UNVERIFIED - alert không có event ancestor để xác minh timestamp.")
            continue

        alert_has_unresolved = False
        alert_has_out_of_range = False
        alert_all_resolved_in_range = True

        for ancestor_number, ancestor in enumerate(ancestors, start=1):
            ancestor_index = ancestor.get("index")
            ancestor_id = ancestor.get("id")

            if not isinstance(ancestor_index, str) or not ancestor_index.strip():
                invalid_count += 1
                alert_has_unresolved = True
                alert_all_resolved_in_range = False
                print(
                    f"  Ancestor #{ancestor_number}: INVALID - empty/invalid index; "
                    f"index={ancestor_index!r}, id={ancestor_id!r}"
                )
                continue

            if not isinstance(ancestor_id, str) or not ancestor_id.strip():
                invalid_count += 1
                alert_has_unresolved = True
                alert_all_resolved_in_range = False
                print(
                    f"  Ancestor #{ancestor_number}: INVALID - empty/invalid id; "
                    f"index={ancestor_index!r}, id={ancestor_id!r}"
                )
                continue

            ancestor_dt = ancestor_timestamps.get((ancestor_index, ancestor_id))
            if ancestor_dt is None:
                unresolved_count += 1
                alert_has_unresolved = True
                alert_all_resolved_in_range = False
                print(
                    f"  Ancestor #{ancestor_number}: UNRESOLVED - "
                    f"index={ancestor_index}, id={ancestor_id}"
                )
                continue

            resolved_count += 1
            is_in_range = start_dt <= ancestor_dt <= end_dt
            if is_in_range:
                in_range_count += 1
            else:
                out_of_range_count += 1
                alert_has_out_of_range = True
                alert_all_resolved_in_range = False

            print(
                f"  Ancestor #{ancestor_number}: RESOLVED - "
                f"timestamp={ancestor_dt.isoformat()}, in_range={is_in_range}, "
                f"index={ancestor_index}, id={ancestor_id}"
            )

        # Không coi ancestor thiếu timestamp là đạt; chỉ VERIFIED nếu tất cả
        # event ancestors đều tra được và đều nằm trong khoảng đã chỉ định.
        if alert_has_out_of_range:
            out_of_range_alerts += 1
            print("  STATUS: OUT_OF_RANGE - có ít nhất một event ancestor nằm ngoài khoảng.")
        elif alert_all_resolved_in_range and not alert_has_unresolved:
            verified_alerts += 1
            print("  STATUS: VERIFIED_IN_RANGE - mọi event ancestor đều đã xác minh và nằm trong khoảng.")
        else:
            unverified_alerts += 1
            print("  STATUS: UNVERIFIED - có event ancestor không thể xác minh đầy đủ.")

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    print(f"Alerts queried from Kibana             : {len(fetched_alerts)}")
    print(f"Alerts within requested range          : {len(alerts_in_range)}")
    print(f"Resolved event ancestor occurrences    : {resolved_count}")
    print(f"  - Resolved inside requested range    : {in_range_count}")
    print(f"  - Resolved outside requested range    : {out_of_range_count}")
    print(f"Unresolved valid ancestors             : {unresolved_count}")
    print(f"Invalid ancestors (empty index/id)     : {invalid_count}")
    print(f"Alerts VERIFIED_IN_RANGE               : {verified_alerts}")
    print(f"Alerts OUT_OF_RANGE                    : {out_of_range_alerts}")
    print(f"Alerts UNVERIFIED                      : {unverified_alerts}")
    print(f"Alerts without event ancestors         : {no_event_ancestor_alerts}")
    print("=" * 78)
    print(
        "Lưu ý: UNVERIFIED không đồng nghĩa với không phát hiện. "
        "Nó chỉ có nghĩa là metadata ancestor không đủ để xác minh thời điểm event gốc."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
