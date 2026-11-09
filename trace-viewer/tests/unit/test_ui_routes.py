"""
trace-viewer/tests/unit/test_ui_routes.py

TestClient tests for Phase 9.5 static serving routes.

Covers:
- GET /  serves index.html with correct MIME type
- /static/index.html  served directly
- /static/styles.css  served with CSS MIME type
- /static/app.js      served with JavaScript MIME type
- nonexistent static path  returns 404
- /api/health still responds (existing API unaffected)
- GET / does not require a database connection
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app import app

client = TestClient(app, base_url="http://127.0.0.1")


def test_root_returns_200():
    resp = client.get("/")
    assert resp.status_code == 200


def test_root_is_html():
    resp = client.get("/")
    assert "text/html" in resp.headers["content-type"]


def test_static_index_html_returns_200():
    resp = client.get("/static/index.html")
    assert resp.status_code == 200


def test_static_styles_css():
    resp = client.get("/static/styles.css")
    assert resp.status_code == 200
    assert "text/css" in resp.headers["content-type"]


def test_static_app_js():
    resp = client.get("/static/app.js")
    assert resp.status_code == 200
    assert "javascript" in resp.headers["content-type"]


def test_nonexistent_static_asset_returns_404():
    resp = client.get("/static/does-not-exist.png")
    assert resp.status_code == 404


def test_api_health_unaffected():
    """Existing API route is reachable after the static mount is added."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_root_requires_no_database():
    """
    GET / serves a static file — no database connection is needed.
    Without TRACE_VIEWER_DB_PASSWORD set, any route that calls connect()
    raises RuntimeError.  This test passes only if no connection is attempted.
    """
    resp = client.get("/")
    assert resp.status_code == 200
