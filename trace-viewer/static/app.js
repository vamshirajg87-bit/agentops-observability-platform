'use strict';

const PAGE_SIZE = 50;
const MAX_TREE_DEPTH = 50; // safety guard against unexpected deep nesting

// ---------- List-view state ----------
let pageIndex = 0;
let hasErrorFilter = null; // null | true | false
let currentTotal = 0;
let searchFilter    = '';
let serviceFilter   = '';
let minDurFilter    = '';
let maxDurFilter    = '';

// ---------- Detail-view state ----------
let currentTraceId = null;

// ---------- DOM refs — list view ----------
const tracesBody    = document.getElementById('traces-body');
const statusRegion  = document.getElementById('status-region');
const errorBanner   = document.getElementById('error-banner');
const errorMessage  = document.getElementById('error-message');
const retryBtn      = document.getElementById('retry-btn');
const prevBtn       = document.getElementById('prev-btn');
const nextBtn       = document.getElementById('next-btn');
const pageIndicator = document.getElementById('page-indicator');
const countDisplay  = document.getElementById('count-display');

// ---------- DOM refs — detail view ----------
const listViewEl        = document.getElementById('list-view');
const detailViewEl      = document.getElementById('detail-view');
const backBtn           = document.getElementById('back-btn');
const detailTraceIdEl   = document.getElementById('detail-trace-id-display');
const detailCopyBtn     = document.getElementById('detail-copy-btn');
const detailSpanCount   = document.getElementById('detail-span-count');
const detailDemoBadge   = document.getElementById('detail-demo-badge');
const detailHealthEl    = document.getElementById('detail-health');
const cycleWarningEl    = document.getElementById('cycle-warning');
const detailStatusEl    = document.getElementById('detail-status');
const detailErrBanner   = document.getElementById('detail-error-banner');
const detailErrMsg      = document.getElementById('detail-error-message');
const detailRetryBtn    = document.getElementById('detail-retry-btn');
const rootsContainer    = document.getElementById('roots-container');
const orphansSection    = document.getElementById('orphans-section');
const orphansContainer  = document.getElementById('orphans-container');
const cycleMembersSection   = document.getElementById('cycle-members-section');
const cycleMembersContainer = document.getElementById('cycle-members-container');
const spanPanelEmpty    = document.getElementById('span-panel-empty');
const spanPanelContent  = document.getElementById('span-panel-content');
const spanFieldsDl      = document.getElementById('span-fields');

// ==========================================================================
// Shared formatting
// ==========================================================================

function formatTimestamp(iso) {
  const d = new Date(iso);
  const pad = n => String(n).padStart(2, '0');
  return (
    d.getUTCFullYear()          + '-' +
    pad(d.getUTCMonth() + 1)    + '-' +
    pad(d.getUTCDate())         + ' ' +
    pad(d.getUTCHours())        + ':' +
    pad(d.getUTCMinutes())      + ':' +
    pad(d.getUTCSeconds())      + ' UTC'
  );
}

// Same as formatTimestamp, with milliseconds: 2026-10-15 09:00:00.123 UTC.
function formatTimestampMs(iso) {
  const d = new Date(iso);
  const pad = (n, w) => String(n).padStart(w || 2, '0');
  return (
    d.getUTCFullYear()          + '-' +
    pad(d.getUTCMonth() + 1)    + '-' +
    pad(d.getUTCDate())         + ' ' +
    pad(d.getUTCHours())        + ':' +
    pad(d.getUTCMinutes())      + ':' +
    pad(d.getUTCSeconds())      + '.' +
    pad(d.getUTCMilliseconds(), 3) + ' UTC'
  );
}

// The marker shown on seeded demonstration data.  The API derives is_demo_data from
// the demo_seed span attribute; real telemetry never carries it.
const DEMO_BADGE_TEXT = 'Synthetic Demo Data';

function makeDemoBadge() {
  const b = document.createElement('span');
  b.className = 'demo-badge';
  b.textContent = DEMO_BADGE_TEXT;
  return b;
}

function formatDuration(ms) {
  if (ms < 1)      return '< 1 ms';
  if (ms < 1000)   return Math.round(ms) + ' ms';
  if (ms < 60000)  return (ms / 1000).toFixed(2) + ' s';
  const m = Math.floor(ms / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  return m + ' m ' + s + ' s';
}

// ==========================================================================
// Span classification helpers
// ==========================================================================

function isErrorSpan(span) {
  return span.status_code === 'ERROR' || span.error_type !== null;
}

function getSpanType(span) {
  if (span.agent_name !== null || span.agent_operation !== null) return 'agent';
  if (span.tool_name !== null || span.tool_status !== null)      return 'tool';
  if (span.retrieval_result_count !== null || span.retrieval_top_relevance_score !== null) return 'retrieval';
  if (span.gen_ai_operation !== null) return 'llm';
  return 'generic';
}

function spanTypeLetter(type) {
  return { agent: 'A', tool: 'T', retrieval: 'R', llm: 'L' }[type] || '';
}

// Walk a list of TraceNodeResponse objects (and their children) looking for any error span.
// Children arrays from Phase 9.2 reconstruction are already acyclic, so this is safe.
function anySpanHasError(nodes) {
  for (const node of nodes) {
    if (isErrorSpan(node.span)) return true;
    if (anySpanHasError(node.children)) return true;
  }
  return false;
}

// Return the deepest originating error span via depth-first children-first traversal.
// Prefers the most specific (leaf) ERROR span over a parent that propagated it,
// so the failure summary names the source of the failure rather than its ancestor.
function findDeepestErrorSpan(nodes) {
  for (const node of nodes) {
    const found = findDeepestErrorSpan(node.children);
    if (found) return found;
    if (isErrorSpan(node.span)) return node.span;
  }
  return null;
}

// ==========================================================================
// List view — API & rendering
// ==========================================================================

function buildApiUrl() {
  const params = new URLSearchParams();
  params.set('limit', String(PAGE_SIZE));
  params.set('offset', String(pageIndex * PAGE_SIZE));
  if (hasErrorFilter !== null) params.set('has_error', String(hasErrorFilter));
  if (searchFilter)            params.set('search', searchFilter);
  if (serviceFilter)           params.set('service_name', serviceFilter);
  if (minDurFilter !== '')     params.set('min_duration_ms', minDurFilter);
  if (maxDurFilter !== '')     params.set('max_duration_ms', maxDurFilter);
  return '/api/traces?' + params.toString();
}

function hasAnySearchFilter() {
  return searchFilter || serviceFilter || minDurFilter !== '' || maxDurFilter !== '';
}

async function fetchTraces() {
  setLoading(true);
  clearError();

  try {
    const resp = await fetch(buildApiUrl());
    if (!resp.ok) {
      let detail = resp.statusText || String(resp.status);
      try {
        const body = await resp.json();
        if (body && body.detail) detail = body.detail;
      } catch (_) { /* keep statusText */ }
      throw new Error('HTTP ' + resp.status + ' — ' + detail);
    }
    const data = await resp.json();
    currentTotal = data.total;
    renderTable(data.traces);
    renderPagination();
    renderCount(data.traces.length);
  } catch (err) {
    showError(err.message);
  } finally {
    setLoading(false);
  }
}

function setLoading(loading) {
  if (loading) {
    statusRegion.textContent = 'Loading traces…';
    prevBtn.setAttribute('aria-disabled', 'true');
    nextBtn.setAttribute('aria-disabled', 'true');
  } else {
    statusRegion.textContent = '';
  }
}

function showError(msg) {
  errorMessage.textContent =
    'Could not load traces — ' + msg + '. Check that the API is running.';
  errorBanner.classList.remove('hidden');
  tracesBody.replaceChildren();
  countDisplay.textContent = '';
  pageIndicator.textContent = '';
}

function clearError() {
  errorBanner.classList.add('hidden');
  errorMessage.textContent = '';
}

function renderTable(traces) {
  if (traces.length === 0) {
    renderEmpty();
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const t of traces) {
    fragment.appendChild(makeRow(t));
  }
  tracesBody.replaceChildren(fragment);
}

function renderEmpty() {
  const tr = document.createElement('tr');
  tr.className = 'empty-row';
  const td = document.createElement('td');
  td.setAttribute('colspan', '8');
  const hasAnyFilter = hasErrorFilter !== null || hasAnySearchFilter();
  td.textContent = hasAnyFilter
    ? 'No traces match the current filters.'
    : 'No traces found.';
  tr.appendChild(td);
  tracesBody.replaceChildren(tr);
}

function makeRow(t) {
  const tr = document.createElement('tr');

  // Navigate to detail view when the row is clicked.
  tr.addEventListener('click', () => openTraceDetail(t.trace_id));

  // Status
  const statusTd = document.createElement('td');
  const dot       = document.createElement('span');
  dot.className   = 'status-dot ' + (t.has_error ? 'error' : 'ok');
  dot.setAttribute('aria-label', t.has_error ? 'Error' : 'OK');
  dot.setAttribute('role', 'img');
  statusTd.appendChild(dot);
  tr.appendChild(statusTd);

  // Started
  tr.appendChild(makeTextCell(formatTimestamp(t.trace_start_time)));

  // Duration
  tr.appendChild(makeTextCell(formatDuration(t.trace_duration_ms)));

  // Root operation
  const opTd    = document.createElement('td');
  const opSpan  = document.createElement('span');
  opSpan.className   = 'op-name';
  opSpan.textContent = t.root_span_name || '—';
  if (t.root_span_name) opSpan.title = t.root_span_name;
  opTd.appendChild(opSpan);
  if (t.is_demo_data === true) opTd.appendChild(makeDemoBadge());
  tr.appendChild(opTd);

  // Service
  tr.appendChild(makeTextCell(t.root_service_name || '—'));

  // Spans
  const spansTd = makeTextCell(String(t.span_count));
  spansTd.className = 'align-right';
  tr.appendChild(spansTd);

  // Breakdown
  const bkTd = document.createElement('td');
  bkTd.appendChild(makeBreakdown(t));
  tr.appendChild(bkTd);

  // Trace ID + copy (copy button stops propagation so it does not trigger row nav)
  const idTd   = document.createElement('td');
  const idCell = document.createElement('div');
  idCell.className = 'trace-id-cell';
  const idDisplay = document.createElement('span');
  idDisplay.className   = 'trace-id-display';
  idDisplay.textContent = t.trace_id.slice(0, 8);
  idDisplay.title       = t.trace_id;
  idCell.appendChild(idDisplay);
  idCell.appendChild(makeCopyButton(t.trace_id));
  idTd.appendChild(idCell);
  tr.appendChild(idTd);

  return tr;
}

function makeTextCell(text) {
  const td = document.createElement('td');
  td.textContent = text;
  return td;
}

function makeBreakdown(t) {
  const container = document.createElement('div');
  container.className = 'breakdown';

  const defs = [
    { label: 'A', title: 'Agent spans',     count: t.agent_span_count,     isError: false },
    { label: 'T', title: 'Tool spans',      count: t.tool_span_count,      isError: false },
    { label: 'R', title: 'Retrieval spans', count: t.retrieval_span_count, isError: false },
    { label: 'E', title: 'Error spans',     count: t.error_span_count,     isError: true  },
  ];

  const anyNonZero = defs.some(d => d.count > 0);
  if (!anyNonZero) return container;

  for (const d of defs) {
    const span       = document.createElement('span');
    span.className   = 'badge' + (d.isError && d.count > 0 ? ' error-badge' : '');
    span.title       = d.title;
    span.textContent = d.label + ' ' + d.count;
    container.appendChild(span);
  }

  return container;
}

function makeCopyButton(fullId) {
  const btn = document.createElement('button');
  btn.className = 'copy-btn';
  btn.textContent = 'copy';
  btn.type = 'button';
  btn.setAttribute('aria-label', 'Copy full trace ID');

  btn.addEventListener('click', e => {
    e.stopPropagation(); // do not bubble to the row click handler
    if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') {
      showCopyFeedback(btn, false);
      return;
    }
    navigator.clipboard.writeText(fullId).then(
      ()  => showCopyFeedback(btn, true),
      ()  => showCopyFeedback(btn, false)
    );
  });

  return btn;
}

function showCopyFeedback(btn, success) {
  const prev = btn.textContent;
  btn.textContent = success ? '✓' : '✗';
  btn.classList.add(success ? 'copied' : 'failed');
  setTimeout(() => {
    btn.textContent = prev;
    btn.classList.remove('copied', 'failed');
  }, 1500);
}

function renderPagination() {
  const totalPages = Math.max(1, Math.ceil(currentTotal / PAGE_SIZE));
  pageIndicator.textContent = 'Page ' + (pageIndex + 1) + ' of ' + totalPages;

  prevBtn.setAttribute('aria-disabled', pageIndex === 0             ? 'true' : 'false');
  nextBtn.setAttribute('aria-disabled', pageIndex >= totalPages - 1 ? 'true' : 'false');
}

function renderCount(rowCount) {
  if (currentTotal === 0) {
    countDisplay.textContent = '';
    return;
  }
  const start = pageIndex * PAGE_SIZE + 1;
  const end   = pageIndex * PAGE_SIZE + rowCount;
  countDisplay.textContent =
    'Showing ' + start + '–' + end + ' of ' + currentTotal + ' traces';
}

function applyFilter(value) {
  hasErrorFilter = value;
  pageIndex = 0;

  document.getElementById('filter-all')
    .setAttribute('aria-pressed', value === null  ? 'true' : 'false');
  document.getElementById('filter-errors')
    .setAttribute('aria-pressed', value === true  ? 'true' : 'false');
  document.getElementById('filter-healthy')
    .setAttribute('aria-pressed', value === false ? 'true' : 'false');

  fetchTraces();
}

// ==========================================================================
// View switching
// ==========================================================================

function showListView() {
  document.body.classList.remove('detail-mode');
  listViewEl.classList.remove('hidden');
  detailViewEl.classList.add('hidden');
  currentTraceId = null;
}

function showDetailView() {
  document.body.classList.add('detail-mode');
  listViewEl.classList.add('hidden');
  detailViewEl.classList.remove('hidden');
}

// ==========================================================================
// Detail view — navigation & fetch
// ==========================================================================

async function openTraceDetail(traceId) {
  currentTraceId = traceId;
  showDetailView();

  // Immediately populate partial info so the toolbar is not blank during load
  detailTraceIdEl.textContent = traceId.slice(0, 8) + '…' + traceId.slice(-8);
  detailTraceIdEl.title = traceId;
  detailCopyBtn.dataset.traceId = traceId;
  detailSpanCount.textContent = '';
  detailHealthEl.textContent = '';
  detailHealthEl.className = 'detail-meta-item';

  // Clear previous content
  clearFailureSummary();
  cycleWarningEl.classList.add('hidden');
  rootsContainer.replaceChildren();
  orphansSection.classList.add('hidden');
  orphansContainer.replaceChildren();
  cycleMembersSection.classList.add('hidden');
  cycleMembersContainer.replaceChildren();
  clearSpanPanel();

  await fetchDetail();
}

async function fetchDetail() {
  if (!currentTraceId) return;
  showDetailLoading();
  clearDetailError();

  try {
    const resp = await fetch('/api/traces/' + currentTraceId);
    if (resp.status === 404) {
      detailStatusEl.textContent = 'Trace not found.';
      return;
    }
    if (!resp.ok) {
      let detail = resp.statusText || String(resp.status);
      try {
        const body = await resp.json();
        if (body && body.detail) detail = body.detail;
      } catch (_) { /* keep statusText */ }
      showDetailError('HTTP ' + resp.status + ' — ' + detail);
      return;
    }
    const data = await resp.json();
    detailStatusEl.textContent = '';
    renderDetail(data);
  } catch (err) {
    showDetailError(err.message);
  }
}

function showDetailLoading() {
  detailStatusEl.textContent = 'Loading trace…';
}

function showDetailError(msg) {
  detailStatusEl.textContent = '';
  detailErrMsg.textContent = 'Could not load trace — ' + msg;
  detailErrBanner.classList.remove('hidden');
}

function clearDetailError() {
  detailErrBanner.classList.add('hidden');
  detailErrMsg.textContent = '';
}

// ==========================================================================
// Detail view — rendering
// ==========================================================================

function renderDetail(data) {
  // Trace-level header
  detailTraceIdEl.textContent = data.trace_id.slice(0, 8) + '…' + data.trace_id.slice(-8);
  detailTraceIdEl.title = data.trace_id;
  detailCopyBtn.dataset.traceId = data.trace_id;

  detailDemoBadge.classList.toggle('hidden', data.is_demo_data !== true);

  detailSpanCount.textContent = data.span_count + ' span' + (data.span_count === 1 ? '' : 's');

  const hasErr = anySpanHasError(data.roots) ||
                 anySpanHasError(data.orphans) ||
                 anySpanHasError(data.cycle_members);
  detailHealthEl.textContent = hasErr ? 'Error' : 'Healthy';
  detailHealthEl.className   = 'detail-meta-item ' + (hasErr ? 'health-error' : 'health-ok');

  if (hasErr) {
    const errSpan = findDeepestErrorSpan(data.roots) ||
                    findDeepestErrorSpan(data.orphans) ||
                    findDeepestErrorSpan(data.cycle_members);
    renderFailureSummary(errSpan);
  } else {
    clearFailureSummary();
  }

  cycleWarningEl.classList.toggle('hidden', !data.has_cycle);

  // Execution tree (roots — always shown even when empty)
  renderTreeSection(data.roots, rootsContainer, 'No root spans found.');

  // Orphans section (only when present)
  orphansSection.classList.toggle('hidden', data.orphans.length === 0);
  if (data.orphans.length > 0) {
    renderTreeSection(data.orphans, orphansContainer, 'No orphan spans.');
  }

  // Cycle members section (only when present)
  cycleMembersSection.classList.toggle('hidden', data.cycle_members.length === 0);
  if (data.cycle_members.length > 0) {
    renderTreeSection(data.cycle_members, cycleMembersContainer, 'No cycle members.');
  }

  clearSpanPanel();
}

function renderTreeSection(nodes, container, emptyMsg) {
  container.replaceChildren();
  if (nodes.length === 0) {
    const p = document.createElement('p');
    p.className = 'tree-empty';
    p.textContent = emptyMsg;
    container.appendChild(p);
    return;
  }
  const frag = document.createDocumentFragment();
  for (const node of nodes) {
    const el = renderTreeNode(node, 0);
    if (el) frag.appendChild(el);
  }
  container.appendChild(frag);
}

function renderTreeNode(node, depth) {
  // Safety guard: Phase 9.2 reconstruction removes back-edges, so cycles
  // cannot appear in children[]. The depth cap defends against unexpected data.
  if (depth > MAX_TREE_DEPTH) return null;

  const span   = node.span;
  const isErr  = isErrorSpan(span);
  const isCycle = node.is_cycle_member;
  const type   = getSpanType(span);

  const item = document.createElement('div');
  item.setAttribute('role', 'treeitem');
  if (node.children.length > 0) item.setAttribute('aria-expanded', 'true');

  const row = document.createElement('div');
  row.className = 'tree-node-row' + (isErr ? ' error-row' : '');
  row.setAttribute('tabindex', '0');
  row.setAttribute('aria-selected', 'false');

  // Span-type badge (A / T / R / L), omitted for generic spans
  if (type !== 'generic') {
    const badge = document.createElement('span');
    badge.className = 'span-type-badge span-type-' + type;
    badge.textContent = spanTypeLetter(type);
    badge.title = type;
    badge.setAttribute('aria-hidden', 'true');
    row.appendChild(badge);
  }

  // Span name
  const nameEl = document.createElement('span');
  nameEl.className = 'span-name';
  nameEl.textContent = span.span_name;
  nameEl.title = span.span_name;
  row.appendChild(nameEl);

  // Duration
  const durEl = document.createElement('span');
  durEl.className = 'span-duration';
  durEl.textContent = formatDuration(span.duration_ms);
  row.appendChild(durEl);

  // Error pill
  if (isErr) {
    const pill = document.createElement('span');
    pill.className = 'span-error-pill';
    pill.textContent = 'error';
    pill.setAttribute('aria-label', 'error span');
    row.appendChild(pill);
  }

  // Cycle member pill
  if (isCycle) {
    const pill = document.createElement('span');
    pill.className = 'span-cycle-pill';
    pill.textContent = 'cycle';
    pill.setAttribute('aria-label', 'cycle member');
    row.appendChild(pill);
  }

  // Select span on click
  row.addEventListener('click', () => {
    document.querySelectorAll('.tree-node-row.selected').forEach(r => {
      r.classList.remove('selected');
      r.setAttribute('aria-selected', 'false');
    });
    row.classList.add('selected');
    row.setAttribute('aria-selected', 'true');
    selectSpan(span);
  });

  // Keyboard: Enter/Space activates
  row.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      row.click();
    }
  });

  item.appendChild(row);

  // Recurse into children
  if (node.children.length > 0) {
    const group = document.createElement('div');
    group.className = 'tree-children';
    group.setAttribute('role', 'group');
    for (const child of node.children) {
      const childEl = renderTreeNode(child, depth + 1);
      if (childEl) group.appendChild(childEl);
    }
    item.appendChild(group);
  }

  return item;
}

// ==========================================================================
// Failure summary banner
// ==========================================================================

function renderFailureSummary(errSpan) {
  const el = document.getElementById('failure-summary');
  if (!el || !errSpan) return;
  let text = 'Failed at: ' + errSpan.span_name;
  const errMsg = errSpan.error_message || errSpan.status_message;
  if (errMsg) text += ' — ' + errMsg;
  el.textContent = text;
  el.classList.remove('hidden');
}

function clearFailureSummary() {
  const el = document.getElementById('failure-summary');
  if (!el) return;
  el.textContent = '';
  el.classList.add('hidden');
}

// ==========================================================================
// Span detail panel
// ==========================================================================

function clearSpanPanel() {
  spanPanelEmpty.classList.remove('hidden');
  spanPanelContent.classList.add('hidden');
  spanFieldsDl.replaceChildren();
}

function selectSpan(span) {
  renderSpanPanel(span);
}

function renderSpanPanel(span) {
  spanFieldsDl.replaceChildren();

  function addDt(label, className) {
    const dt = document.createElement('dt');
    dt.textContent = label;
    if (className) dt.className = className;
    spanFieldsDl.appendChild(dt);
  }

  function addDd(value, opts = {}) {
    const dd = document.createElement('dd');
    const classes = [];
    if (opts.mono) classes.push('mono');
    if (opts.error) classes.push('error-value');
    if (classes.length) dd.className = classes.join(' ');
    dd.textContent = (value === null || value === undefined || value === '') ? '—' : String(value);
    spanFieldsDl.appendChild(dd);
  }

  function addSep() {
    const hr = document.createElement('hr');
    hr.className = 'field-sep';
    hr.setAttribute('aria-hidden', 'true');
    spanFieldsDl.appendChild(hr);
  }

  function addField(label, value, opts = {}) {
    addDt(label);
    addDd(value, opts);
  }

  function addOptional(label, value, opts = {}) {
    if (value === null || value === undefined || value === '') return;
    addField(label, value, opts);
  }

  // --- Core identity (always shown) ---
  addField('Span ID',       span.span_id,        { mono: true });
  addField('Parent Span',   span.parent_span_id, { mono: true });

  // --- Timing ---
  addSep();
  addField('Start',    formatTimestampMs(span.start_time));
  addField('End',      formatTimestampMs(span.end_time));
  addField('Duration', formatDuration(span.duration_ms));

  // --- Classification ---
  addSep();
  addField('Name',        span.span_name);
  addOptional('Trace ID', span.trace_id,        { mono: true });
  addOptional('Service',  span.service_name);
  addOptional('Kind',     span.span_kind);
  addOptional('GenAI Op', span.gen_ai_operation);

  // --- Status ---
  addSep();
  addField('Status', span.status_code);
  addOptional('Status Msg', span.status_message);

  // --- Request / session context ---
  const hasCtx = span.request_id || span.session_id;
  if (hasCtx) {
    addSep();
    addOptional('Request ID', span.request_id, { mono: true });
    addOptional('Session ID', span.session_id, { mono: true });
  }

  // --- Agent-specific ---
  const hasAgent = span.agent_name || span.agent_operation;
  if (hasAgent) {
    addSep();
    addOptional('Agent Name', span.agent_name);
    addOptional('Agent Op',   span.agent_operation);
  }

  // --- Tool-specific ---
  const hasTool = span.tool_name || span.tool_status;
  if (hasTool) {
    addSep();
    addOptional('Tool Name',   span.tool_name);
    addOptional('Tool Status', span.tool_status);
  }

  // --- Retrieval-specific ---
  const hasRetrieval = span.retrieval_result_count !== null ||
                       span.retrieval_top_relevance_score !== null;
  if (hasRetrieval) {
    addSep();
    if (span.retrieval_result_count !== null) {
      addField('Results', String(span.retrieval_result_count));
    }
    if (span.retrieval_top_relevance_score !== null) {
      addField('Top Score', span.retrieval_top_relevance_score.toFixed(4));
    }
  }

  // --- Error details ---
  const hasError = span.error_type || span.error_message;
  if (hasError) {
    addSep();
    addOptional('Error Type', span.error_type,    { error: true });
    addOptional('Error Msg',  span.error_message, { error: true });
  }

  spanPanelEmpty.classList.add('hidden');
  spanPanelContent.classList.remove('hidden');
}

// ==========================================================================
// Event listeners — list view
// ==========================================================================

document.getElementById('filter-all')
  .addEventListener('click', () => applyFilter(null));
document.getElementById('filter-errors')
  .addEventListener('click', () => applyFilter(true));
document.getElementById('filter-healthy')
  .addEventListener('click', () => applyFilter(false));

document.getElementById('filter-form').addEventListener('submit', e => {
  e.preventDefault();
  searchFilter  = document.getElementById('search-input').value.trim();
  serviceFilter = document.getElementById('service-input').value.trim();
  minDurFilter  = document.getElementById('min-dur-input').value.trim();
  maxDurFilter  = document.getElementById('max-dur-input').value.trim();
  pageIndex = 0;
  fetchTraces();
});

document.getElementById('clear-filters-btn').addEventListener('click', () => {
  searchFilter  = '';
  serviceFilter = '';
  minDurFilter  = '';
  maxDurFilter  = '';
  document.getElementById('search-input').value  = '';
  document.getElementById('service-input').value = '';
  document.getElementById('min-dur-input').value = '';
  document.getElementById('max-dur-input').value = '';
  hasErrorFilter = null;
  pageIndex = 0;
  document.getElementById('filter-all').setAttribute('aria-pressed', 'true');
  document.getElementById('filter-errors').setAttribute('aria-pressed', 'false');
  document.getElementById('filter-healthy').setAttribute('aria-pressed', 'false');
  fetchTraces();
});

retryBtn.addEventListener('click', fetchTraces);

prevBtn.addEventListener('click', () => {
  if (prevBtn.getAttribute('aria-disabled') === 'true') return;
  pageIndex -= 1;
  fetchTraces();
});

nextBtn.addEventListener('click', () => {
  if (nextBtn.getAttribute('aria-disabled') === 'true') return;
  pageIndex += 1;
  fetchTraces();
});

// ==========================================================================
// Event listeners — detail view
// ==========================================================================

backBtn.addEventListener('click', () => {
  if (anomalyBackFromTrace()) return;   // opened from an anomaly: return there
  showListView();
});

detailCopyBtn.addEventListener('click', () => {
  const traceId = detailCopyBtn.dataset.traceId;
  if (!traceId) return;
  if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') {
    showCopyFeedback(detailCopyBtn, false);
    return;
  }
  navigator.clipboard.writeText(traceId).then(
    () => showCopyFeedback(detailCopyBtn, true),
    () => showCopyFeedback(detailCopyBtn, false)
  );
});

detailRetryBtn.addEventListener('click', fetchDetail);

// ==========================================================================
// Anomalies tab — list, detail and RCA panel (read-only)
//
// Every database-sourced string is written with textContent (via anomEl or an
// explicit textContent assignment).  innerHTML is never used in this section.
// ==========================================================================

const ANOMALY_PAGE_SIZE = 50;
const TRACE_ID_RE   = /^[0-9a-f]{32}$/;
const ANOMALY_ID_RE = /^[0-9a-f]{64}$/;

let anomalyPageIndex = 0;
let anomalyTotal = 0;
let anomalySeverity = '';
let anomalyService  = '';
let anomalyTraceFilter = '';
let anomalyListLoaded = false;
let anomalyListToken = 0;     // discards responses from superseded requests
let anomalyDetailToken = 0;
let currentAnomalyId = null;
let currentAnomalyTraceId = null;
let traceOpenedFromAnomaly = false;

const anomaliesViewEl      = document.getElementById('anomalies-view');
const anomalyDetailViewEl  = document.getElementById('anomaly-detail-view');
const anomaliesBody        = document.getElementById('anomalies-body');
const anomalyStatusEl      = document.getElementById('anomaly-status');
const anomalyErrBanner     = document.getElementById('anomaly-error-banner');
const anomalyErrMsg        = document.getElementById('anomaly-error-message');
const anomalyPrevBtn       = document.getElementById('anomaly-prev-btn');
const anomalyNextBtn       = document.getElementById('anomaly-next-btn');
const anomalyPageIndicator = document.getElementById('anomaly-page-indicator');
const anomalyCountEl       = document.getElementById('anomaly-count');
const anomalyDetailStatus  = document.getElementById('anomaly-detail-status');
const anomalyDetailErr     = document.getElementById('anomaly-detail-error');
const anomalyDetailErrMsg  = document.getElementById('anomaly-detail-error-message');
const anomalyTraceBtn      = document.getElementById('anomaly-trace-btn');
const rcaStatusEl          = document.getElementById('rca-status');
const rcaErrBanner         = document.getElementById('rca-error-banner');
const rcaErrMsg            = document.getElementById('rca-error-message');
const rcaContentEl         = document.getElementById('rca-content');

// ---------- helpers ----------

function anomEl(tag, className, text) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}

function anomText(v) {
  return v === null || v === undefined || v === '' ? '—' : String(v);
}

function anomNumber(v) {
  if (v === null || v === undefined) return '—';
  return Number.isInteger(v) ? String(v) : String(Math.round(v * 1000) / 1000);
}

// Observed value with its unit.  The raw value is never altered, only labelled:
// latency anomalies are durations in milliseconds, tool-failure anomalies carry a
// tool error rate (the detector emits 1.0 for a failed tool call).
function formatObserved(a) {
  const v = a.observed_value;
  if (v === null || v === undefined) return '—';
  if (a.signal_name === 'duration_ms' || a.anomaly_type === 'latency') return anomNumber(v) + ' ms';
  if (typeof a.signal_name === 'string' && a.signal_name.endsWith('error_rate')) {
    return anomNumber(v) + ' (error rate)';
  }
  return anomNumber(v);
}

function anomTime(v) {
  return v ? formatTimestamp(v) : '—';
}

// Severity and confidence are shown as text with a class for colour, so the
// meaning never depends on colour alone.
function anomBadge(text, kind) {
  return anomEl('span', 'anom-badge anom-' + String(kind).toLowerCase(), text);
}

function anomFetchError(resp) {
  return resp.json().then(
    body => 'HTTP ' + resp.status + ' — ' + ((body && body.detail) || resp.statusText || resp.status),
    () => 'HTTP ' + resp.status + ' — ' + (resp.statusText || resp.status)
  );
}

function addField(dl, label, value, mono) {
  dl.appendChild(anomEl('dt', null, label));
  const dd = anomEl('dd', mono ? 'mono' : null, value);
  dl.appendChild(dd);
  return dd;
}

// ---------- tab switching ----------

function hideAnomalyViews() {
  anomaliesViewEl.classList.add('hidden');
  anomalyDetailViewEl.classList.add('hidden');
}

function selectTab(name) {
  document.getElementById('tab-traces')
    .setAttribute('aria-pressed', name === 'traces' ? 'true' : 'false');
  document.getElementById('tab-anomalies')
    .setAttribute('aria-pressed', name === 'anomalies' ? 'true' : 'false');
  document.body.classList.toggle('anomalies-mode', name === 'anomalies');
}

function showTracesTab() {
  traceOpenedFromAnomaly = false;
  hideAnomalyViews();
  selectTab('traces');
  showListView();
}

function showAnomaliesTab() {
  traceOpenedFromAnomaly = false;
  // leave any trace list / trace detail
  document.body.classList.remove('detail-mode');
  listViewEl.classList.add('hidden');
  detailViewEl.classList.add('hidden');
  currentTraceId = null;
  anomalyDetailViewEl.classList.add('hidden');
  anomaliesViewEl.classList.remove('hidden');
  selectTab('anomalies');
  if (!anomalyListLoaded) fetchAnomalies();
}

// ---------- list ----------

function buildAnomalyUrl() {
  const params = new URLSearchParams();
  params.set('limit', String(ANOMALY_PAGE_SIZE));
  params.set('offset', String(anomalyPageIndex * ANOMALY_PAGE_SIZE));
  if (anomalySeverity)    params.set('severity', anomalySeverity);
  if (anomalyService)     params.set('service_name', anomalyService);
  if (anomalyTraceFilter) params.set('trace_id', anomalyTraceFilter);
  return '/api/anomalies?' + params.toString();
}

async function fetchAnomalies() {
  const token = ++anomalyListToken;
  anomalyStatusEl.textContent = 'Loading anomalies…';
  anomalyErrBanner.classList.add('hidden');
  anomalyPrevBtn.setAttribute('aria-disabled', 'true');
  anomalyNextBtn.setAttribute('aria-disabled', 'true');
  try {
    const resp = await fetch(buildAnomalyUrl());
    if (!resp.ok) throw new Error(await anomFetchError(resp));
    const data = await resp.json();
    if (token !== anomalyListToken) return;
    anomalyListLoaded = true;
    anomalyTotal = data.total;
    renderAnomalyTable(data.anomalies);
    renderAnomalyPagination(data.anomalies.length);
    anomalyStatusEl.textContent = '';
  } catch (err) {
    if (token !== anomalyListToken) return;
    anomalyStatusEl.textContent = '';
    anomalyErrMsg.textContent =
      'Could not load anomalies — ' + err.message + '. Check that the API is running.';
    anomalyErrBanner.classList.remove('hidden');
    anomaliesBody.replaceChildren();
    anomalyCountEl.textContent = '';
    anomalyPageIndicator.textContent = '';
  }
}

function renderAnomalyTable(rows) {
  if (rows.length === 0) {
    const tr = anomEl('tr', 'empty-row');
    const td = anomEl('td', null,
      (anomalySeverity || anomalyService || anomalyTraceFilter)
        ? 'No anomalies match the current filters.'
        : 'No anomalies found.');
    td.setAttribute('colspan', '7');
    tr.appendChild(td);
    anomaliesBody.replaceChildren(tr);
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const a of rows) fragment.appendChild(makeAnomalyRow(a));
  anomaliesBody.replaceChildren(fragment);
}

function makeAnomalyRow(a) {
  const tr = anomEl('tr');
  tr.setAttribute('tabindex', '0');
  tr.setAttribute('role', 'link');
  tr.setAttribute('aria-label', 'Open ' + a.severity + ' anomaly, service ' + anomText(a.service_name));
  const open = () => openAnomalyDetail(a.anomaly_id);
  tr.addEventListener('click', open);
  tr.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); }
  });

  const sevTd = anomEl('td');
  sevTd.appendChild(anomBadge(a.severity, a.severity));
  tr.appendChild(sevTd);
  tr.appendChild(makeTextCell(anomTime(a.event_time)));
  tr.appendChild(makeTextCell(anomText(a.anomaly_type)));
  tr.appendChild(makeTextCell(anomText(a.service_name)));
  tr.appendChild(makeTextCell(anomText(a.operation_name)));
  const obs = makeTextCell(formatObserved(a));
  obs.className = 'align-right';
  tr.appendChild(obs);
  const idTd = makeTextCell(a.trace_id ? a.trace_id.slice(0, 8) + '…' + a.trace_id.slice(-8) : '—');
  idTd.className = 'trace-id-display';
  if (a.trace_id) idTd.title = a.trace_id;
  tr.appendChild(idTd);
  return tr;
}

function renderAnomalyPagination(pageCount) {
  const first = anomalyTotal === 0 ? 0 : anomalyPageIndex * ANOMALY_PAGE_SIZE + 1;
  const last  = anomalyPageIndex * ANOMALY_PAGE_SIZE + pageCount;
  anomalyCountEl.textContent = anomalyTotal === 0
    ? '0 anomalies'
    : 'Showing ' + first + '–' + last + ' of ' + anomalyTotal;
  const pages = Math.max(1, Math.ceil(anomalyTotal / ANOMALY_PAGE_SIZE));
  anomalyPageIndicator.textContent = 'Page ' + (anomalyPageIndex + 1) + ' of ' + pages;
  anomalyPrevBtn.setAttribute('aria-disabled', anomalyPageIndex === 0 ? 'true' : 'false');
  anomalyNextBtn.setAttribute('aria-disabled',
    (anomalyPageIndex + 1) * ANOMALY_PAGE_SIZE >= anomalyTotal ? 'true' : 'false');
}

// ---------- detail ----------

function openAnomalyDetail(anomalyId) {
  currentAnomalyId = anomalyId;
  anomaliesViewEl.classList.add('hidden');
  anomalyDetailViewEl.classList.remove('hidden');
  loadAnomalyDetail();
}

function clearAnomalyDetail() {
  document.getElementById('anomaly-explanation').textContent = '';
  document.getElementById('anomaly-fields').replaceChildren();
  document.getElementById('anomaly-baseline').replaceChildren();
  anomalyTraceBtn.classList.add('hidden');
  currentAnomalyTraceId = null;
  resetRcaContent();
  rcaErrBanner.classList.add('hidden');
  rcaStatusEl.textContent = '';
}

function loadAnomalyDetail() {
  if (!currentAnomalyId || !ANOMALY_ID_RE.test(currentAnomalyId)) return;
  const token = ++anomalyDetailToken;
  clearAnomalyDetail();
  anomalyDetailErr.classList.add('hidden');
  anomalyDetailStatus.textContent = 'Loading anomaly…';
  fetchAnomalyDetail(token);
  fetchRca(token);
}

async function fetchAnomalyDetail(token) {
  try {
    const resp = await fetch('/api/anomalies/' + currentAnomalyId);
    if (resp.status === 404) {
      if (token !== anomalyDetailToken) return;
      anomalyDetailStatus.textContent = 'Anomaly not found.';
      return;
    }
    if (!resp.ok) throw new Error(await anomFetchError(resp));
    const a = await resp.json();
    if (token !== anomalyDetailToken) return;
    anomalyDetailStatus.textContent = '';
    renderAnomalyDetail(a);
  } catch (err) {
    if (token !== anomalyDetailToken) return;
    anomalyDetailStatus.textContent = '';
    anomalyDetailErrMsg.textContent = 'Could not load anomaly — ' + err.message;
    anomalyDetailErr.classList.remove('hidden');
  }
}

function renderAnomalyDetail(a) {
  document.getElementById('anomaly-explanation').textContent = a.explanation;

  const f = document.getElementById('anomaly-fields');
  f.replaceChildren();
  const sev = addField(f, 'Severity', '');
  sev.appendChild(anomBadge(a.severity, a.severity));
  addField(f, 'Type', anomText(a.anomaly_type));
  addField(f, 'Signal', anomText(a.signal_name));
  addField(f, 'Service', anomText(a.service_name));
  addField(f, 'Operation', anomText(a.operation_name));
  addField(f, 'Observed value', formatObserved(a));
  addField(f, 'Anomaly score', anomNumber(a.anomaly_score));
  addField(f, 'Event time', anomTime(a.event_time));
  addField(f, 'Detected at', anomTime(a.detected_at));
  addField(f, 'Detector', anomText(a.detector_name) + ' v' + anomText(a.detector_version));
  addField(f, 'Trace ID', anomText(a.trace_id), true);
  addField(f, 'Span ID', anomText(a.span_id), true);
  addField(f, 'Anomaly ID', a.anomaly_id, true);

  const b = document.getElementById('anomaly-baseline');
  b.replaceChildren();
  if (a.baseline_median === null && a.baseline_mad === null && a.baseline_n === null) {
    addField(b, 'Baseline', 'Not available for this signal.');
  } else {
    addField(b, 'Median', anomNumber(a.baseline_median));
    addField(b, 'MAD', anomNumber(a.baseline_mad));
    addField(b, 'Samples', anomNumber(a.baseline_n));
    addField(b, 'Window start', anomTime(a.baseline_window_start));
    addField(b, 'Window end', anomTime(a.baseline_window_end));
  }

  currentAnomalyTraceId = a.trace_id && TRACE_ID_RE.test(a.trace_id) ? a.trace_id : null;
  anomalyTraceBtn.classList.toggle('hidden', currentAnomalyTraceId === null);
}

// ---------- RCA panel ----------

// The investigation-only block (confidence, summary, limitations, ranked evidence) is hidden with the
// HTML `hidden` attribute as well as the `hidden` class: no stylesheet rule hides #rca-content by class,
// so the class alone left its headings on screen when no investigation exists.
function setRcaContentVisible(visible) {
  rcaContentEl.hidden = !visible;
  rcaContentEl.classList.toggle('hidden', !visible);
}

// Empties and hides the investigation-only block, so nothing of a previous anomaly's RCA can remain.
function resetRcaContent() {
  document.getElementById('rca-confidence').replaceChildren();
  document.getElementById('rca-summary').textContent = '';
  document.getElementById('rca-meta').replaceChildren();
  document.getElementById('rca-limitations').replaceChildren();
  document.getElementById('rca-evidence').replaceChildren();
  setRcaContentVisible(false);
}

async function fetchRca(token) {
  rcaStatusEl.textContent = 'Loading root cause analysis…';
  rcaErrBanner.classList.add('hidden');
  resetRcaContent();
  try {
    const resp = await fetch('/api/anomalies/' + currentAnomalyId + '/rca');
    if (token !== anomalyDetailToken) return;
    if (resp.status === 404) {
      rcaStatusEl.textContent = 'No root cause analysis has been recorded for this anomaly.';
      return;
    }
    if (!resp.ok) throw new Error(await anomFetchError(resp));
    const rca = await resp.json();
    if (token !== anomalyDetailToken) return;
    rcaStatusEl.textContent = '';
    renderRca(rca);
  } catch (err) {
    if (token !== anomalyDetailToken) return;
    rcaStatusEl.textContent = '';
    rcaErrMsg.textContent = 'Could not load root cause analysis — ' + err.message;
    rcaErrBanner.classList.remove('hidden');
  }
}

function renderRca(r) {
  const conf = document.getElementById('rca-confidence');
  conf.replaceChildren(anomBadge(r.confidence, r.confidence));
  document.getElementById('rca-summary').textContent = r.summary;

  const meta = document.getElementById('rca-meta');
  meta.replaceChildren();
  addField(meta, 'Investigated', anomTime(r.investigated_at));
  addField(meta, 'Analyzer', 'v' + anomText(r.analyzer_version));
  addField(meta, 'Spans in trace', anomNumber(r.trace_span_count));
  addField(meta, 'Investigation ID', r.investigation_id, true);

  const lim = document.getElementById('rca-limitations');
  lim.replaceChildren();
  if (r.limitations.length === 0) {
    lim.appendChild(anomEl('li', null, 'None recorded.'));
  } else {
    for (const l of r.limitations) lim.appendChild(anomEl('li', null, l));
  }

  const ev = document.getElementById('rca-evidence');
  ev.replaceChildren();
  if (r.evidence.length === 0) {
    ev.appendChild(anomEl('li', 'rca-evidence-empty', 'No evidence spans were recorded.'));
  } else {
    // The API returns evidence already ordered by rank_position.
    for (const e of r.evidence) ev.appendChild(makeEvidenceItem(e));
  }
  setRcaContentVisible(true);
}

function makeEvidenceItem(e) {
  const li = anomEl('li', 'rca-evidence-item');
  const head = anomEl('div', 'rca-evidence-head');
  head.appendChild(anomEl('span', 'rca-rank', '#' + e.rank_position));
  head.appendChild(anomEl('span', 'op-name', e.span_name));
  head.appendChild(anomEl('span', 'rca-score', 'score ' + anomNumber(e.evidence_score)));
  li.appendChild(head);
  li.appendChild(anomEl('p', 'rca-evidence-expl', e.explanation));

  const dl = anomEl('dl', 'span-fields');
  addField(dl, 'Service', anomText(e.service_name));
  addField(dl, 'Duration', formatDuration(e.duration_ms));
  addField(dl, 'Status', anomText(e.status_code));
  addField(dl, 'Evidence type', anomText(e.evidence_type));
  if (e.error_type !== null || e.error_message !== null) {
    const dd = addField(dl, 'Error', [e.error_type, e.error_message].filter(x => x).join(': '));
    dd.className = 'error-value';
  }
  if (e.trace_duration_fraction !== null) {
    addField(dl, 'Share of trace', anomNumber(Math.round(e.trace_duration_fraction * 1000) / 10) + '%');
  }
  addField(dl, 'Score breakdown', anomText(e.evidence_score_breakdown));
  addField(dl, 'Span ID', e.span_id, true);
  li.appendChild(dl);
  return li;
}

// ---------- navigation to the existing trace viewer ----------

function openAnomalyTrace() {
  if (!currentAnomalyTraceId) return;
  traceOpenedFromAnomaly = true;
  hideAnomalyViews();
  selectTab('traces');        // the trace filter nav is hidden again by detail-mode
  openTraceDetail(currentAnomalyTraceId);
}

// Called by the trace detail "Back" button.  Returns true when it handled the
// click by returning to the anomaly the trace was opened from.
function anomalyBackFromTrace() {
  if (!traceOpenedFromAnomaly) return false;
  traceOpenedFromAnomaly = false;
  document.body.classList.remove('detail-mode');
  detailViewEl.classList.add('hidden');
  currentTraceId = null;
  selectTab('anomalies');
  anomalyDetailViewEl.classList.remove('hidden');
  return true;
}

// ---------- events ----------

document.getElementById('tab-traces').addEventListener('click', showTracesTab);
document.getElementById('tab-anomalies').addEventListener('click', showAnomaliesTab);

document.getElementById('anomaly-filter-form').addEventListener('submit', e => {
  e.preventDefault();
  const traceInput = document.getElementById('anomaly-trace-input');
  const traceVal = traceInput.value.trim().toLowerCase();
  if (traceVal && !TRACE_ID_RE.test(traceVal)) {
    anomalyStatusEl.textContent = 'Trace ID must be 32 lowercase hex characters.';
    traceInput.focus();
    return;
  }
  anomalySeverity    = document.getElementById('anomaly-severity-select').value;
  anomalyService     = document.getElementById('anomaly-service-input').value.trim();
  anomalyTraceFilter = traceVal;
  anomalyPageIndex = 0;
  fetchAnomalies();
});

document.getElementById('anomaly-clear-btn').addEventListener('click', () => {
  document.getElementById('anomaly-severity-select').value = '';
  document.getElementById('anomaly-service-input').value = '';
  document.getElementById('anomaly-trace-input').value = '';
  anomalySeverity = anomalyService = anomalyTraceFilter = '';
  anomalyPageIndex = 0;
  fetchAnomalies();
});

document.getElementById('anomaly-retry-btn').addEventListener('click', fetchAnomalies);

anomalyPrevBtn.addEventListener('click', () => {
  if (anomalyPrevBtn.getAttribute('aria-disabled') === 'true') return;
  anomalyPageIndex -= 1;
  fetchAnomalies();
});
anomalyNextBtn.addEventListener('click', () => {
  if (anomalyNextBtn.getAttribute('aria-disabled') === 'true') return;
  anomalyPageIndex += 1;
  fetchAnomalies();
});

document.getElementById('anomaly-back-btn').addEventListener('click', () => {
  anomalyDetailToken += 1;    // drop in-flight detail responses
  anomalyDetailViewEl.classList.add('hidden');
  anomaliesViewEl.classList.remove('hidden');
});
anomalyTraceBtn.addEventListener('click', openAnomalyTrace);
document.getElementById('anomaly-detail-retry-btn').addEventListener('click', loadAnomalyDetail);
document.getElementById('rca-retry-btn').addEventListener('click', () => fetchRca(anomalyDetailToken));

// ==========================================================================
// Init
// ==========================================================================

fetchTraces();
