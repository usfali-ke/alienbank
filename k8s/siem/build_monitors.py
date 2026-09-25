#!/usr/bin/env python3
"""Emit OpenSearch Alerting monitors for AlienBank — the Sigma rules from
SECURITY_LOGGING_PLAN.md §3.5 as concrete per-bucket / query-level monitors.

Prints a JSON array of monitor bodies (one per rule). A companion shell loop
POSTs each to _plugins/_alerting/monitors. All run on `alienbank-security-*`.

Detection strategy:
  * Bucket-level monitors group by a correlation key (target_ref, source.ip,
    actor.ref) over a rolling window and alert when a bucket crosses a count.
  * Query-level monitors fire on the presence of a single high-signal event
    (compromise, canary leak, throttle-critical).
Severity: 1=highest .. 5=lowest (OpenSearch convention).
"""
from __future__ import annotations

import json

INDEX = "alienbank-security-*"
WINDOW_MIN = 10          # rolling detection window
SCHEDULE_MIN = 1         # how often the monitor runs


def _schedule():
    return {"period": {"interval": SCHEDULE_MIN, "unit": "MINUTES"}}


def _time_filter():
    return {"range": {"@timestamp": {"gte": f"now-{WINDOW_MIN}m", "lte": "now",
                                     "format": "epoch_millis||strict_date_optional_time"}}}


def bucket_monitor(name, severity, extra_filters, group_field, count_threshold,
                   cardinality_field=None, cardinality_threshold=None):
    """Group by `group_field`; alert on buckets with count >= threshold, or
    (if cardinality_* given) distinct(cardinality_field) >= threshold."""
    filters = [_time_filter()] + extra_filters
    aggs = {}
    condition_script = f"params.bucket_count >= {count_threshold}"
    composite_sources = [{"grp": {"terms": {"field": group_field}}}]
    if cardinality_field:
        aggs["distinct"] = {"cardinality": {"field": cardinality_field}}
        condition_script = f"params.distinct >= {cardinality_threshold}"

    return {
        "type": "monitor", "monitor_type": "bucket_level_monitor",
        "name": name, "enabled": True, "schedule": _schedule(),
        "inputs": [{
            "search": {
                "indices": [INDEX],
                "query": {
                    "size": 0,
                    "query": {"bool": {"filter": filters}},
                    "aggregations": {
                        "composite_agg": {
                            "composite": {"sources": composite_sources, "size": 50},
                            "aggregations": aggs,
                        }
                    },
                },
            }
        }],
        "triggers": [{
            "bucket_level_trigger": {
                "name": f"{name} — threshold",
                "severity": str(severity),
                "condition": {
                    "buckets_path": ({"bucket_count": "_count"} if not cardinality_field
                                     else {"distinct": "distinct"}),
                    "parent_bucket_path": "composite_agg",
                    "script": {"source": condition_script, "lang": "painless"},
                },
                "actions": [],
            }
        }],
    }


def query_monitor(name, severity, extra_filters, count_threshold=1):
    filters = [_time_filter()] + extra_filters
    return {
        "type": "monitor", "monitor_type": "query_level_monitor",
        "name": name, "enabled": True, "schedule": _schedule(),
        "inputs": [{
            "search": {
                "indices": [INDEX],
                "query": {"size": 0, "query": {"bool": {"filter": filters}}},
            }
        }],
        "triggers": [{
            "query_level_trigger": {
                "name": f"{name} — present",
                "severity": str(severity),
                "condition": {"script": {
                    "source": f"ctx.results[0].hits.total.value >= {count_threshold}",
                    "lang": "painless"}},
                "actions": [],
            }
        }],
    }


def term(field, value):
    return {"term": {field: value}}


monitors = [
    # Brute force: N failed logins sharing ONE target_ref (any source.ip).
    bucket_monitor(
        "AlienBank — Brute force (single account)", 2,
        [term("event.action.keyword", "login"), term("event.outcome.keyword", "failure")],
        group_field="target_ref.keyword", count_threshold=5),

    # Credential spraying: one source.ip failing against MANY distinct target_ref.
    bucket_monitor(
        "AlienBank — Credential spraying (one source, many accounts)", 2,
        [term("event.action.keyword", "login"), term("event.outcome.keyword", "failure")],
        group_field="source.ip.keyword", count_threshold=0,
        cardinality_field="target_ref.keyword", cardinality_threshold=5),

    # Auth throttle tripped (app-side marker) — critical when it fires at all.
    query_monitor(
        "AlienBank — Auth throttle tripped", 1,
        [term("event.action.keyword", "login_throttle")]),

    # IDOR / BOLA probing: cross_tenant true OR blocked data_access.
    query_monitor(
        "AlienBank — IDOR/BOLA probing", 2,
        [{"bool": {"should": [
            term("security.cross_tenant", True),
            {"bool": {"filter": [term("event.category.keyword", "data_access"),
                                 term("event.outcome.keyword", "blocked")]}},
        ], "minimum_should_match": 1}}],
        count_threshold=1),

    # Guardrail evasion: attack=true with a non-empty bypassed_layers.
    query_monitor(
        "AlienBank — Guardrail evasion (bypassed layers)", 2,
        [term("security.attack", True),
         {"exists": {"field": "security.bypassed_layers"}}]),

    # Compromise: agent_turn outcome=compromise (money moved / cross-tenant exec).
    query_monitor(
        "AlienBank — Agent compromise", 1,
        [term("event.category.keyword", "agent_turn"),
         term("event.outcome.keyword", "compromise")]),

    # Prompt/canary leakage.
    query_monitor(
        "AlienBank — Prompt/canary leak", 1,
        [term("security.canary_leak", True)]),

    # Privilege escalation: a teller-only action performed by a non-teller.
    query_monitor(
        "AlienBank — Privilege escalation (non-teller on teller endpoint)", 2,
        [term("event.action.keyword", "teller_customer_accounts"),
         term("event.outcome.keyword", "blocked")]),
]

print(json.dumps(monitors, indent=2))
