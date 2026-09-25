#!/usr/bin/env python3
"""Generate the OpenSearch Dashboards saved-objects NDJSON for AlienBank.

Emits an index-pattern + a set of visualizations + one dashboard, all wired to
the `alienbank-security-*` index. Import with:

    curl -s -X POST 'http://siem.localtest.me/api/saved_objects/_import?overwrite=true' \
      -H 'osd-xsrf: true' --form file=@dashboards-objects.ndjson

The panels follow SECURITY_LOGGING_PLAN.md §3.5:
  - auth outcomes over time      - top actors by activity
  - action breakdown             - outcome breakdown
  - severity timeline (compromise/critical)
All fields are PII-free (actor.ref pseudonym, verdict flags), never usernames.
"""
from __future__ import annotations

import json

IDX = "alienbank-security-*"          # index-pattern id (already created)
IDX_REF = "kibanaSavedObjectMeta.searchSourceJSON.index"


def _search_source(query_filters=None):
    """searchSourceJSON referencing the index pattern by ref name."""
    src = {"query": {"query": "", "language": "kuery"},
           "filter": query_filters or [],
           "indexRefName": IDX_REF}
    return json.dumps(src)


def viz(vid, title, vis_state, query_filters=None):
    return {
        "id": vid,
        "type": "visualization",
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": _search_source(query_filters)
            },
        },
        "references": [
            {"name": IDX_REF, "type": "index-pattern", "id": IDX}
        ],
    }


def date_hist_split(vid, title, split_field, query_filters=None):
    """Vertical stacked bar: date_histogram X, split series by a keyword field."""
    return viz(vid, title, {
        "title": title,
        "type": "histogram",
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                              "position": "bottom", "show": True, "scale": {"type": "linear"},
                              "labels": {"show": True, "filter": True, "truncate": 100},
                              "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                           "position": "left", "show": True, "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                           "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                              "data": {"label": "Count", "id": "1"},
                              "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                              "showCircles": True}],
            "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [],
            "addTimeMarker": False, "labels": {}, "thresholdLine": {"show": False},
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
             "params": {"field": "@timestamp", "timeRange": {"from": "now-24h", "to": "now"},
                        "useNormalizedOpenSearchInterval": True, "interval": "auto",
                        "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}},
            {"id": "3", "enabled": True, "type": "terms", "schema": "group",
             "params": {"field": split_field, "orderBy": "1", "order": "desc", "size": 8,
                        "otherBucket": False, "missingBucket": False}},
        ],
    }, query_filters)


def pie(vid, title, field, size=10):
    return viz(vid, title, {
        "title": title, "type": "pie",
        "params": {"type": "pie", "addTooltip": True, "addLegend": True,
                   "legendPosition": "right", "isDonut": True, "labels": {"show": False}},
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                        "otherBucket": True, "otherBucketLabel": "Other",
                        "missingBucket": False}},
        ],
    })


def data_table(vid, title, field, size=10):
    return viz(vid, title, {
        "title": title, "type": "table",
        "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
                   "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                        "otherBucket": False, "missingBucket": False}},
        ],
    })


def metric(vid, title, query_filters, subtext=""):
    # A single-count KPI shown as one big number (the OSD `metric` viz type).
    # The earlier "Error" cards were a malformed params block, NOT a broken
    # renderer: the metric renderer needs the full nested `params.metric`
    # object (colorSchema/colorsRange/style/labels). With it, the panel
    # renders a clean big count — verified in-browser.
    return viz(vid, title, {
        "title": title, "type": "metric",
        "params": {
            "addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {
                "percentageMode": False, "useRanges": False,
                "colorSchema": "Green to Red", "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 10000}],
                "labels": {"show": True}, "invertColors": False,
                "style": {"bgFill": "#000", "bgColor": False,
                          "labelColor": False, "subText": subtext,
                          "fontSize": 60},
            },
        },
        "aggs": [{"id": "1", "enabled": True, "type": "count",
                  "schema": "metric", "params": {}}],
    }, query_filters)


def _filter(field, value):
    """A DQL phrase filter on a keyword field."""
    return {"meta": {"index": IDX, "type": "phrase", "key": field,
                     "params": {"query": value}, "negate": False, "disabled": False,
                     "alias": None},
            "query": {"match_phrase": {field: value}}}


def discover_url(kuery, when="now-24h"):
    """A Discover deep-link (OSD 2.13 data-explorer) pre-filtered by `kuery`,
    e.g. `event.outcome.keyword:"blocked"`. The metric viz type has no native
    drilldown, so the KPI cards pair with a markdown "View events" link that
    opens exactly the events behind the count."""
    # The double-quotes in the kuery must be percent-encoded so the rison URL
    # stays intact; the rest of the URL is literal rison the app parses on load.
    q = kuery.replace('"', "%22")
    return (f"/app/data-explorer/discover#?_g=(time:(from:{when},to:now))"
            "&_a=(discover:(columns:!(_source),sort:!()),"
            f"metadata:(indexPattern:'{IDX}',view:discover))"
            f"&_q=(filters:!(),query:(language:kuery,query:'{q}'))")


def link_panel(vid, title, label, kuery):
    """A tiny markdown panel whose sole content is a click-through link into
    Discover, filtered to the same events the neighbouring KPI counts."""
    md = f"#### 🔍 [{label} →]({discover_url(kuery)})"
    return viz(vid, title, {
        "title": title, "type": "markdown",
        "params": {"fontSize": 14, "openLinksInNewTab": False, "markdown": md},
        "aggs": [],
    })


# ---------------------------------------------------------------------------
objects = []

# Panels
objects.append(date_hist_split(
    "ab-auth-outcomes", "AlienBank — Auth outcomes over time",
    "event.outcome.keyword",
    query_filters=[_filter("event.category.keyword", "authentication")]))

objects.append(date_hist_split(
    "ab-severity-timeline", "AlienBank — Event severity over time",
    "event.severity.keyword"))

objects.append(pie("ab-action-breakdown", "AlienBank — Action breakdown",
                   "event.action.keyword", size=12))

objects.append(pie("ab-outcome-breakdown", "AlienBank — Outcome breakdown",
                   "event.outcome.keyword"))

objects.append(data_table("ab-top-actors", "AlienBank — Top actors (actor.ref)",
                          "actor.ref.keyword", size=10))

objects.append(data_table("ab-top-source-ips", "AlienBank — Top source IPs",
                          "source.ip.keyword", size=10))

objects.append(metric("ab-blocked-count", "Blocked (IDOR/BOLA/priv) — 24h",
                      query_filters=[_filter("event.outcome.keyword", "blocked")]))

objects.append(metric("ab-critical-count", "Critical events — 24h",
                      query_filters=[_filter("event.severity.keyword", "critical")]))

# Click-through links: the metric viz has no drilldown, so each KPI pairs with
# a markdown link that opens the exact events behind the count in Discover.
objects.append(link_panel(
    "ab-blocked-link", "Blocked — view events",
    "View the 32 blocked events", 'event.outcome.keyword:"blocked"'))

objects.append(link_panel(
    "ab-critical-link", "Critical — view events",
    "View the critical events", 'event.severity.keyword:"critical"'))

# Dashboard laying the panels out on a grid.  Each KPI (h=6) sits above a thin
# link strip (h=3) that drills into the underlying events.
panels = [
    ("ab-blocked-count", 0, 0, 12, 6),
    ("ab-blocked-link", 0, 6, 12, 3),
    ("ab-critical-count", 12, 0, 12, 6),
    ("ab-critical-link", 12, 6, 12, 3),
    ("ab-outcome-breakdown", 24, 0, 24, 9),
    ("ab-auth-outcomes", 0, 9, 24, 15),
    ("ab-severity-timeline", 24, 9, 24, 15),
    ("ab-action-breakdown", 0, 24, 24, 15),
    ("ab-top-actors", 24, 24, 12, 15),
    ("ab-top-source-ips", 36, 24, 12, 15),
]
panels_json, refs = [], []
for i, (pid, x, y, w, h) in enumerate(panels):
    ref = f"panel_{i}"
    panels_json.append({
        "version": "2.13.0",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
        "panelIndex": str(i), "embeddableConfig": {}, "panelRefName": ref,
    })
    refs.append({"name": ref, "type": "visualization", "id": pid})

objects.append({
    "id": "ab-security-overview",
    "type": "dashboard",
    "attributes": {
        "title": "AlienBank — Security Overview",
        "hits": 0,
        "description": "PII-free security monitoring: auth, IDOR/BOLA, severity, top actors.",
        "panelsJSON": json.dumps(panels_json),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "version": 1,
        "timeRestore": True,
        "timeTo": "now",
        "timeFrom": "now-24h",
        "refreshInterval": {"pause": False, "value": 10000},
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"},
                                            "filter": []})
        },
    },
    "references": refs,
})

for o in objects:
    print(json.dumps(o))
