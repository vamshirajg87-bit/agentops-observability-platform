"""
trace-viewer/tests/unit/test_anomalies_ui.py

Static checks for the Anomalies tab and RCA panel in trace-viewer/static/.

The frontend has no JavaScript test runner, so these tests read the three
static files as text and check the contracts that matter without a browser:
every element the script looks up exists, only the B3J-127 API is called,
filters match the API, and database-sourced text is never inserted as HTML.

Coverage
    1  Every getElementById() id used by app.js exists in index.html
    2  HTML ids are unique
    3  Tabs, filters and views present, with accessible names
    4  Severity filter values equal the API's allowed values
    5  Only the four documented anomaly/RCA endpoints are called
    6  Page size does not exceed the API maximum
    7  No HTML-injection sink anywhere in app.js
    8  Anomaly and RCA text is written with textContent
    9  Loading, empty, 404 and error states exist
    10 Navigation to the existing trace viewer and back
    11 Existing trace viewer elements and behaviour are preserved
    12 CSS covers the new classes; hidden views stay hidden
    13 Static files are still served
    14 app.js parses (skipped when node is unavailable)
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

from app import app

_STATIC = os.path.join(os.path.dirname(__file__), "..", "..", "static")


def _read(name: str) -> str:
    with open(os.path.join(_STATIC, name), encoding="utf-8") as f:
        return f.read()


HTML = _read("index.html")
JS = _read("app.js")
CSS = _read("styles.css")

client = TestClient(app, base_url="http://127.0.0.1")


def _js_code() -> str:
    """app.js without // comments, so a comment cannot hide or fake a match."""
    return "\n".join(re.sub(r"^\s*//.*$", "", line) for line in JS.splitlines())


def test_every_element_id_used_by_js_exists_in_html():
    used = set(re.findall(r"getElementById\('([^']+)'\)", JS))
    declared = set(re.findall(r'\bid="([^"]+)"', HTML))
    assert used - declared == set()


def test_html_ids_are_unique():
    ids = re.findall(r'\bid="([^"]+)"', HTML)
    assert len(ids) == len(set(ids))


def test_tabs_filters_and_views_present_with_accessible_names():
    for element_id in ("tab-traces", "tab-anomalies", "anomalies-view", "anomaly-detail-view",
                       "anomalies-table", "anomaly-filter-form", "anomaly-severity-select",
                       "anomaly-service-input", "anomaly-trace-input", "anomaly-prev-btn",
                       "anomaly-next-btn", "rca-summary", "rca-confidence", "rca-limitations",
                       "rca-evidence", "anomaly-trace-btn"):
        assert f'id="{element_id}"' in HTML, element_id
    assert 'aria-label="Sections"' in HTML
    assert re.search(r'id="anomalies-table"[^>]*aria-label="[^"]+"', HTML)
    assert re.search(r'id="anomaly-severity-select"[^>]*aria-label="[^"]+"', HTML)
    # every <th> in the anomaly table has a scope
    table = HTML[HTML.index('id="anomalies-table"'):HTML.index("</table>", HTML.index('id="anomalies-table"'))]
    assert len(re.findall(r"<th[ >]", table)) == table.count('<th scope="col"') == 7
    # status and error regions are announced
    assert re.search(r'id="anomaly-status"[^>]*role="status"[^>]*aria-live="polite"', HTML)
    assert re.search(r'id="anomaly-error-banner"[^>]*role="alert"', HTML)
    assert re.search(r'id="rca-error-banner"[^>]*role="alert"', HTML)
    # both new views start hidden
    assert re.search(r'id="anomalies-view"[^>]*class="[^"]*\bhidden\b', HTML)
    assert re.search(r'id="anomaly-detail-view"[^>]*class="[^"]*\bhidden\b', HTML)


def test_severity_filter_options_match_the_api():
    select = HTML[HTML.index('id="anomaly-severity-select"'):]
    select = select[:select.index("</select>")]
    values = set(re.findall(r'<option value="([^"]*)"', select))
    assert values == {"", "INFO", "WARNING", "CRITICAL"}


def test_only_documented_anomaly_endpoints_are_called():
    code = _js_code()
    assert set(re.findall(r"'(/api/(?:anomalies|rca)[^']*)'", code)) == {
        "/api/anomalies?", "/api/anomalies/"}
    assert "'/api/anomalies/' + currentAnomalyId + '/rca'" in code
    assert "'/api/anomalies/' + currentAnomalyId)" in code
    # no write verbs
    assert not re.search(r"method\s*:\s*'(POST|PUT|PATCH|DELETE)'", code, re.I)


def test_query_parameters_are_only_those_the_api_supports():
    block = JS[JS.index("function buildAnomalyUrl"):JS.index("async function fetchAnomalies")]
    assert set(re.findall(r"params\.set\('([a-z_]+)'", block)) == {
        "limit", "offset", "severity", "service_name", "trace_id"}


def test_page_size_within_api_maximum():
    size = int(re.search(r"const ANOMALY_PAGE_SIZE = (\d+);", JS).group(1))
    assert 1 <= size <= 200


def test_no_html_injection_sinks():
    code = _js_code()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                 "createContextualFragment", "eval(", "new Function"):
        assert sink not in code, sink


def test_anomaly_and_rca_text_uses_textcontent():
    section = JS[JS.index("// Anomalies tab"):JS.index("// Init")]
    assert "textContent" in section
    # the single element factory writes text only through textContent
    helper = section[section.index("function anomEl"):section.index("function anomText")]
    assert "e.textContent = text" in helper
    # database fields are rendered via these helpers/assignments
    for needle in ("'rca-evidence-expl', e.explanation",
                   "getElementById('rca-summary').textContent = r.summary",
                   "getElementById('anomaly-explanation').textContent = a.explanation",
                   "anomEl('li', null, l)",
                   "anomEl('span', 'op-name', e.span_name)"):
        assert needle in section, needle


def test_loading_empty_not_found_and_error_states_exist():
    section = JS[JS.index("// Anomalies tab"):JS.index("// Init")]
    for needle in ("Loading anomalies", "Loading anomaly", "Loading root cause analysis",
                   "No anomalies found.", "No anomalies match the current filters.",
                   "No root cause analysis has been recorded", "Anomaly not found.",
                   "Could not load anomalies", "Could not load anomaly",
                   "Could not load root cause analysis", "resp.status === 404"):
        assert needle in section, needle


def test_stale_responses_are_discarded():
    section = JS[JS.index("// Anomalies tab"):JS.index("// Init")]
    assert section.count("token !== anomalyListToken") >= 2
    assert section.count("token !== anomalyDetailToken") >= 4


def test_trace_id_validated_before_navigation_and_filtering():
    section = JS[JS.index("// Anomalies tab"):JS.index("// Init")]
    assert "const TRACE_ID_RE   = /^[0-9a-f]{32}$/;" in section
    assert "const ANOMALY_ID_RE = /^[0-9a-f]{64}$/;" in section
    assert "TRACE_ID_RE.test(a.trace_id)" in section
    assert "ANOMALY_ID_RE.test(currentAnomalyId)" in section


def test_navigation_to_existing_trace_viewer_and_back():
    section = JS[JS.index("// Anomalies tab"):JS.index("// Init")]
    assert "openTraceDetail(currentAnomalyTraceId)" in section
    assert "function anomalyBackFromTrace" in section
    assert "if (anomalyBackFromTrace()) return;" in JS


def test_existing_trace_viewer_preserved():
    for element_id in ("list-view", "detail-view", "traces-table", "filter-form",
                       "filter-all", "filter-errors", "filter-healthy", "back-btn",
                       "roots-container", "span-fields"):
        assert f'id="{element_id}"' in HTML, element_id
    assert "'/api/traces?'" in JS and "'/api/traces/' + currentTraceId" in JS
    assert "function openTraceDetail" in JS and "function showListView" in JS
    # initial view is still the trace list
    assert re.search(r'id="list-view"(?![^>]*hidden)', HTML)
    assert re.search(r'id="tab-traces"[^>]*aria-pressed="true"', HTML)
    assert JS.rstrip().endswith("fetchTraces();")


def test_css_covers_new_classes_and_hides_hidden_views():
    for selector in (".anom-view.hidden", ".anom-badge", ".anom-critical", ".rca-evidence-item",
                     ".anom-detail-grid", "body.anomalies-mode .filter-nav", ":focus-visible"):
        assert selector in CSS, selector
    assert "@media (max-width: 900px)" in CSS


def test_static_files_served():
    assert client.get("/").status_code == 200
    body = client.get("/static/index.html").text
    assert 'id="tab-anomalies"' in body
    assert "anomalyBackFromTrace" in client.get("/static/app.js").text
    assert ".anom-badge" in client.get("/static/styles.css").text


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_app_js_parses():
    result = subprocess.run(["node", "--check", os.path.join(_STATIC, "app.js")],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
