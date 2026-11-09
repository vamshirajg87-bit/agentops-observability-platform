"""
trace-viewer/tests/unit/test_rca_panel_states.py

Behavioural tests of the RCA panel in trace-viewer/static/app.js, run in Node with a fake DOM and a fake fetch.

Nothing here touches a network, a database, Docker or any file but the three static files, which are only read.
app.js runs inside a node:vm context that holds nothing but a fake document, a scripted fetch and a few inert
globals (no require, no process, no real fetch).  Visibility is modelled on the real stylesheet: an element is
hidden by the `hidden` attribute, or by the `hidden` class only where styles.css has a rule for it.

    A  No investigation (404): the message shows; confidence, limitations and evidence are hidden
    B  An investigation exists: confidence, summary, limitations and ranked evidence are shown
    C  RCA present -> absent -> present: no stale content, correct visibility at every step
    D  An unexpected failure (500, 503, network error) is an error, never "no investigation"
    E  A late response of a superseded request does not change the panel
    F  Control: with the `hidden` attribute ignored, the old class-only behaviour is visible (CSS has no rule)
    G  Static structure: the investigation-only content is one block, hidden through one helper
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

import pytest

_STATIC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "static"))
APP_JS = os.path.join(_STATIC, "app.js")
STYLES = os.path.join(_STATIC, "styles.css")
INDEX = os.path.join(_STATIC, "index.html")
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node not installed")

A, B = "a" * 64, "b" * 64
MISSING_MESSAGE = "No root cause analysis has been recorded for this anomaly."

HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const [appPath, cssPath, htmlPath, scenarioJson] = process.argv.slice(-4);
const scenario = JSON.parse(scenarioJson);
const problems = [];
process.on('unhandledRejection', e => problems.push('unhandledRejection: ' + String(e && e.message || e)));

// ---- fake DOM ---------------------------------------------------------------------------------------------
class ClassList {
  constructor(el) { this.el = el; }
  add(...c) { c.forEach(x => this.el.classes.add(x)); }
  remove(...c) { c.forEach(x => this.el.classes.delete(x)); }
  contains(c) { return this.el.classes.has(c); }
  toggle(c, force) {
    const on = force === undefined ? !this.el.classes.has(c) : !!force;
    if (on) this.el.classes.add(c); else this.el.classes.delete(c);
    return on;
  }
}
class El {
  constructor(tag, id) {
    this.tagName = tag; this.id = id || ''; this._text = ''; this.children = []; this.classes = new Set();
    this.attrs = {}; this.listeners = {}; this.hidden = false; this.value = ''; this.dataset = {}; this.style = {};
    this.classList = new ClassList(this);
  }
  get className() { return Array.from(this.classes).join(' '); }
  set className(v) { this.classes = new Set(String(v).split(/\s+/).filter(Boolean)); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set textContent(v) { this._text = String(v); this.children = []; }
  appendChild(c) { return this._add(c); }
  append(...cs) { cs.forEach(c => this._add(c)); }
  _add(c) {
    if (c && c.tagName === '#fragment') { this.children.push(...c.children); c.children = []; }
    else if (c && typeof c === 'object') { this.children.push(c); }
    else { this._text += String(c); }
    return c;
  }
  replaceChildren(...cs) { this.children = []; this._text = ''; cs.forEach(c => this._add(c)); }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; }
  removeAttribute(k) { delete this.attrs[k]; }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  closest() { return null; }
  contains() { return false; }
}
const elProxy = el => new Proxy(el, {
  get(t, p) { if (p in t) return t[p]; return typeof p === 'string' ? function () {} : undefined; },
  set(t, p, v) { t[p] = v; return true; },
});

const html = fs.readFileSync(htmlPath, 'utf8');
const byId = {};
for (const m of html.matchAll(/<([a-zA-Z0-9]+)([^>]*)>/g)) {
  const attrs = m[2];
  const id = (attrs.match(/\bid="([^"]+)"/) || [])[1];
  if (!id) continue;
  const el = new El(m[1].toLowerCase(), id);
  el.className = (attrs.match(/\bclass="([^"]*)"/) || [, ''])[1];
  el.hidden = /\bhidden\b/.test(attrs.replace(/"[^"]*"/g, ''));
  byId[id] = elProxy(el);
}
const document = {
  body: elProxy(new El('body')),
  getElementById(id) { if (!byId[id]) throw new Error('app.js asked for an element missing from index.html: ' + id); return byId[id]; },
  createElement(tag) { return elProxy(new El(String(tag).toLowerCase())); },
  createDocumentFragment() { return elProxy(new El('#fragment')); },
  querySelectorAll() { return []; },
  addEventListener() {},
};

// ---- stylesheet model --------------------------------------------------------------------------------------
const css = fs.readFileSync(cssPath, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
const rules = [];
for (const m of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
  const disp = (m[2].match(/(?:^|;|\s)display\s*:\s*([^;]+)/) || [])[1];
  if (!disp) continue;
  for (const sel of m[1].split(',').map(s => s.trim())) rules.push({ sel, display: disp.trim() });
}
function matches(sel, el) {
  const m = sel.match(/^([a-zA-Z0-9]*)((?:[#.][-_a-zA-Z0-9]+)*)$/);
  if (!m) return false;                                   // combinators, pseudo-classes: not modelled
  if (m[1] && m[1].toLowerCase() !== el.tagName) return false;
  for (const part of m[2].match(/[#.][-_a-zA-Z0-9]+/g) || []) {
    if (part[0] === '#' && el.id !== part.slice(1)) return false;
    if (part[0] === '.' && !el.classes.has(part.slice(1))) return false;
  }
  return true;
}
function authorDisplays(el) { return rules.filter(r => matches(r.sel, el)).map(r => r.display); }
function displayed(el) {
  const own = authorDisplays(el);
  if (own.includes('none')) return false;
  if (el.hidden && !scenario.ignoreHiddenAttribute && own.length === 0) return false;
  return true;
}

// ---- scripted fetch ----------------------------------------------------------------------------------------
const requests = [];
const pending = {};
const anomaly = id => ({
  anomaly_id: id, anomaly_type: 'latency', signal_name: 'duration_ms', detector_name: 'd', detector_version: '1',
  trace_id: 'c'.repeat(32), span_id: 'd'.repeat(16), service_name: 's', operation_name: 'o', observed_value: 1234.5,
  event_time: '2026-10-26T18:00:00Z', baseline_median: null, baseline_mad: null, baseline_n: null,
  baseline_window_start: null, baseline_window_end: null, anomaly_score: 3.2, severity: 'INFO',
  explanation: 'Synthetic anomaly.', detected_at: '2026-10-26T18:01:00Z', truncated_fields: [],
});
const respond = (status, body) => ({
  status, ok: status >= 200 && status < 300, statusText: '',
  json: async () => { if (body === undefined) throw new Error('no body'); return body; },
});
async function fetchMock(url, init) {
  const u = String(url);
  requests.push({ url: u, method: (init && init.method) || 'GET' });
  let m;
  if ((m = u.match(/^\/api\/anomalies\/([0-9a-f]{64})\/rca$/))) {
    const def = scenario.rca[m[1]];
    if (def.throw) throw new Error('network down');
    if (def.hold) await new Promise(res => { (pending[m[1]] = pending[m[1]] || []).push(res); });
    return respond(def.status, def.body);
  }
  if ((m = u.match(/^\/api\/anomalies\/([0-9a-f]{64})$/))) return respond(200, anomaly(m[1]));
  if (u.startsWith('/api/traces')) return respond(200, { total: 0, limit: 50, offset: 0, traces: [] });
  if (u.startsWith('/api/anomalies?')) return respond(200, { total: 0, limit: 50, offset: 0, anomalies: [] });
  return respond(404, { detail: 'unexpected request' });
}

// ---- run ---------------------------------------------------------------------------------------------------
const sandbox = {
  document, fetch: fetchMock, URLSearchParams,
  navigator: { clipboard: { writeText: async () => {} } },
  setTimeout: () => 0, clearTimeout: () => {}, console: { log() {}, error() {}, warn() {} },
};
const ctx = vm.createContext(sandbox);
const settle = async () => { for (let i = 0; i < 12; i++) await new Promise(r => setImmediate(r)); };

const rcaContent = byId['rca-content'];
function snapshot(label) {
  const shown = displayed(rcaContent);
  const conf = byId['rca-confidence'], sum = byId['rca-summary'], lim = byId['rca-limitations'], ev = byId['rca-evidence'];
  return {
    label,
    status: byId['rca-status'].textContent,
    errorBannerShown: displayed(byId['rca-error-banner']),
    errorMessage: byId['rca-error-message'].textContent,
    contentShown: shown,
    confidenceShown: shown && displayed(conf), limitationsShown: shown && displayed(lim), evidenceShown: shown && displayed(ev),
    confidenceText: conf.textContent, summaryText: sum.textContent,
    limitationsCount: lim.children.length, evidenceCount: ev.children.length,
    evidenceRanks: ev.children.map(li => li.children[0].children[0].textContent),
    metaCount: byId['rca-meta'].children.length,
  };
}

(async () => {
  vm.runInContext(fs.readFileSync(appPath, 'utf8'), ctx, { filename: 'app.js' });
  await settle();
  const snapshots = [];
  for (const step of scenario.steps) {
    if (step.open) { vm.runInContext('openAnomalyDetail(' + JSON.stringify(step.open) + ')', ctx); }
    if (step.release) { (pending[step.release] || []).forEach(r => r()); pending[step.release] = []; }
    await settle();
    snapshots.push(snapshot(step.label || step.open || step.release));
  }
  process.stdout.write(JSON.stringify({ snapshots, requests, problems }));
})().catch(e => { process.stderr.write('HARNESS FAILURE: ' + (e && e.stack || e)); process.exit(2); });
"""


def run(scenario: dict) -> dict:
    result = subprocess.run(
        [NODE, "-", APP_JS, STYLES, INDEX, json.dumps(scenario)],
        input=HARNESS, capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert result.returncode == 0, result.stderr[-1500:]
    out = json.loads(result.stdout)
    # app.js may only ever read: GET requests, and only the documented routes
    assert all(r["method"] == "GET" for r in out["requests"])
    assert all(re.match(r"^/api/(traces|anomalies)", r["url"]) for r in out["requests"]), out["requests"]
    return out


def rca_ok(n_limitations: int = 1, n_evidence: int = 3) -> dict:
    evidence = [{
        "rank_position": i + 1, "span_id": "e" * 16, "parent_span_id": None, "span_name": f"span-{i}",
        "service_name": "s", "duration_ms": 12.5, "status_code": "OK", "error_type": None, "error_message": None,
        "tool_name": None, "tool_status": None, "agent_name": None, "agent_operation": None,
        "retrieval_result_count": None, "retrieval_top_relevance_score": None, "is_root_span": i == 0,
        "is_error_span": False, "is_direct_subject": i == 0, "depth": i, "trace_duration_fraction": 0.5,
        "evidence_type": "direct_subject", "evidence_score": 0.9 - i * 0.1, "evidence_score_breakdown": "x=1",
        "explanation": f"Synthetic evidence {i}.", "truncated_fields": [],
    } for i in range(n_evidence)]
    return {
        "investigation_id": "f" * 64, "anomaly_id": A, "analyzer_version": "1", "investigated_at": "2026-10-26T18:02:00Z",
        "trace_id": "c" * 32, "subject_span_id": None, "service_name": "s", "operation_name": "o",
        "event_time": "2026-10-26T18:00:00Z", "trace_span_count": 5, "anomaly_type": "latency", "observed_value": 1.0,
        "baseline_median": None, "anomaly_score": 3.0, "severity": "INFO", "confidence": "HIGH",
        "summary": "Synthetic summary.", "limitations": [f"Synthetic limitation {i}." for i in range(n_limitations)],
        "evidence": evidence, "truncated_fields": [], "omitted_evidence": 0,
    }


PRESENT = {"status": 200, "body": rca_ok()}
ABSENT = {"status": 404, "body": {"detail": "No RCA investigation recorded"}}


def assert_investigation_hidden_and_empty(s: dict) -> None:
    assert s["contentShown"] is False
    assert s["confidenceShown"] is False and s["limitationsShown"] is False and s["evidenceShown"] is False
    assert s["confidenceText"] == "" and s["summaryText"] == ""
    assert s["limitationsCount"] == 0 and s["evidenceCount"] == 0 and s["metaCount"] == 0


def assert_investigation_shown(s: dict) -> None:
    assert s["contentShown"] and s["confidenceShown"] and s["limitationsShown"] and s["evidenceShown"]
    assert s["confidenceText"] == "HIGH" and s["summaryText"] == "Synthetic summary."
    assert s["limitationsCount"] == 1 and s["evidenceCount"] == 3
    assert s["evidenceRanks"] == ["#1", "#2", "#3"]
    assert s["status"] == "" and s["errorBannerShown"] is False


def test_a_no_investigation_shows_the_message_and_hides_the_investigation_only_content():
    (s,) = run({"rca": {A: ABSENT}, "steps": [{"open": A}]})["snapshots"]
    assert s["status"] == MISSING_MESSAGE
    assert s["errorBannerShown"] is False
    assert_investigation_hidden_and_empty(s)


def test_b_an_existing_investigation_shows_confidence_summary_limitations_and_ranked_evidence():
    (s,) = run({"rca": {A: PRESENT}, "steps": [{"open": A}]})["snapshots"]
    assert_investigation_shown(s)


def test_c_present_then_absent_then_present_leaves_no_stale_content():
    first, second, third = run({"rca": {A: PRESENT, B: ABSENT}, "steps": [{"open": A}, {"open": B}, {"open": A}]})["snapshots"]
    assert_investigation_shown(first)
    assert second["status"] == MISSING_MESSAGE and second["errorBannerShown"] is False
    assert_investigation_hidden_and_empty(second)
    assert_investigation_shown(third)


def test_c_absent_then_present_then_absent_also_restores_each_state():
    first, second, third = run({"rca": {A: PRESENT, B: ABSENT}, "steps": [{"open": B}, {"open": A}, {"open": B}]})["snapshots"]
    assert first["status"] == MISSING_MESSAGE
    assert_investigation_hidden_and_empty(first)
    assert_investigation_shown(second)
    assert third["status"] == MISSING_MESSAGE
    assert_investigation_hidden_and_empty(third)


@pytest.mark.parametrize("failure", [
    {"status": 500, "body": {"detail": "boom"}},
    {"status": 503, "body": {"detail": "unavailable"}},
    {"throw": True},
])
def test_d_an_unexpected_failure_is_an_error_and_never_no_investigation(failure):
    (s,) = run({"rca": {A: failure}, "steps": [{"open": A}]})["snapshots"]
    assert s["status"] == ""
    assert MISSING_MESSAGE not in s["status"] + s["errorMessage"]
    assert s["errorBannerShown"] is True and "Could not load root cause analysis" in s["errorMessage"]
    assert_investigation_hidden_and_empty(s)


def test_d_a_failure_after_a_successful_investigation_shows_no_stale_content():
    first, second = run({"rca": {A: PRESENT, B: {"status": 500, "body": {"detail": "boom"}}},
                         "steps": [{"open": A}, {"open": B}]})["snapshots"]
    assert_investigation_shown(first)
    assert second["errorBannerShown"] is True
    assert_investigation_hidden_and_empty(second)


def test_e_a_late_response_of_a_superseded_request_does_not_change_the_panel():
    held = {"status": 200, "body": rca_ok(), "hold": True}
    opened_a, opened_b, released_a = run({
        "rca": {A: held, B: ABSENT},
        "steps": [{"open": A, "label": "open-a"}, {"open": B, "label": "open-b"}, {"release": A, "label": "late-a"}],
    })["snapshots"]
    assert opened_a["status"] == "Loading root cause analysis…"
    assert_investigation_hidden_and_empty(opened_a)
    assert opened_b["status"] == MISSING_MESSAGE
    assert released_a == {**opened_b, "label": "late-a"}


def test_f_control_the_stylesheet_has_no_class_rule_for_the_investigation_block():
    # Models the behaviour before the fix: when only the `hidden` class is honoured, #rca-content stays displayed.
    (s,) = run({"rca": {A: ABSENT}, "steps": [{"open": A}], "ignoreHiddenAttribute": True})["snapshots"]
    assert s["contentShown"] is True


def test_g_the_investigation_only_content_is_one_block_hidden_through_one_helper():
    with open(INDEX, encoding="utf-8") as handle:
        html = handle.read()
    with open(APP_JS, encoding="utf-8") as handle:
        js = handle.read()
    block = html[html.index('id="rca-content"'):html.index("</section>", html.index('id="rca-content"'))]
    for needle in ("Confidence:", 'id="rca-confidence"', 'id="rca-summary"', 'id="rca-meta"', "Limitations",
                   'id="rca-limitations"', "Ranked evidence", 'id="rca-evidence"'):
        assert needle in block, needle
    assert js.count("rcaContentEl.hidden") == 1 and js.count("rcaContentEl.classList") == 1      # only in the helper
    assert js.count("resetRcaContent()") >= 3 and js.count("setRcaContentVisible(true)") == 1
