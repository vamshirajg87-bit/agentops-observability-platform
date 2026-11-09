"""
trace-viewer/tests/unit/test_host_header.py

Tests of the Host-header allow-list of the trace viewer (trace-viewer/app.py).

The viewer has no authentication and listens on loopback only.  Serving only
loopback hostnames stops a browser that was steered to it under an attacker's
hostname (DNS rebinding) from reading it.  Nothing here connects to a database:
every request that could reach one runs with app.connect replaced by a function
that fails the test.

    H1  Loopback hostnames, with or without the published ports 8000 and 8001, are served
    H2  Every other Host header, including rebinding-style names, gets 400
    H3  A rejected request still carries the security headers and never reaches the database
    H4  TRACE_VIEWER_ALLOWED_HOSTS only adds plain hostnames; a bad value raises and never relaxes the check
    H5  The middleware is registered with the security-headers middleware outermost
    H6  The container health checks in the Compose files use an allowed hostname
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from starlette.middleware.trustedhost import TrustedHostMiddleware

import app as viewer
from app import (
    CONTENT_SECURITY_POLICY,
    DEFAULT_ALLOWED_HOSTS,
    ENV_ALLOWED_HOSTS,
    SecurityHeadersMiddleware,
    allowed_hosts_from_environment,
)

_REPO = Path(__file__).resolve().parents[3]

client = TestClient(viewer.app, base_url="http://127.0.0.1")


def _no_database(*args, **kwargs):
    raise AssertionError("the database must not be reached")


# ---------------------------------------------------------------------------
# H1  Accepted hosts
# ---------------------------------------------------------------------------

ACCEPTED_HOSTS = ["127.0.0.1", "127.0.0.1:8000", "127.0.0.1:8001", "localhost", "localhost:8000", "localhost:8001"]


@pytest.mark.parametrize("host", ACCEPTED_HOSTS)
@pytest.mark.parametrize("path", ["/api/health", "/", "/static/app.js"])
def test_h1_loopback_hostnames_are_served_with_or_without_the_published_ports(host, path):
    with patch("app.connect", side_effect=_no_database):
        response = client.get(path, headers={"host": host})
    assert response.status_code == 200
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY


def test_h1_the_liveness_route_answers_for_the_container_health_check_host():
    with patch("app.connect", side_effect=_no_database):
        response = client.get("/api/health", headers={"host": "127.0.0.1:8000"})
    assert response.status_code == 200 and response.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# H2 / H3  Rejected hosts
# ---------------------------------------------------------------------------

REJECTED_HOSTS = [
    "evil.example",
    "evil.example:8001",
    "127.0.0.1.evil.example",             # rebinding-style: the allowed name as a prefix
    "localhost.evil.example",
    "evil.localhost:8001",                # a subdomain of localhost is not localhost
    "127.0.0.2",
    "0.0.0.0:8000",
    "[::1]:8000",                         # IPv6 literals are not supported
    "testserver",                         # the TestClient default is no longer served
    "",                                   # a missing or empty Host header
    "127.0.0.1@evil.example",
    "localhost@evil.example:80",
    "127.0.0.1 evil.example",
    "LOCALHOST",                          # matching is case-sensitive; browsers send lower case
]


@pytest.mark.parametrize("host", REJECTED_HOSTS)
@pytest.mark.parametrize("path", ["/api/health", "/", "/static/app.js", "/api/traces"])
def test_h2_every_other_host_header_gets_400(host, path):
    with patch("app.connect", side_effect=_no_database):
        response = client.get(path, headers={"host": host})
    assert response.status_code == 400
    assert response.text == "Invalid host header"


@pytest.mark.parametrize("path", ["/api/health", "/", "/static/app.js", "/api/traces", "/api/nowhere", "/openapi.json"])
def test_h3_a_rejected_request_still_carries_the_security_headers(path):
    with patch("app.connect", side_effect=_no_database):
        response = client.get(path, headers={"host": "evil.example:8001"})
    assert response.status_code == 400
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert response.headers["x-content-type-options"] == "nosniff"
    if path.startswith("/api"):
        assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("path", [
    "/api/health/ready", "/api/traces", "/api/traces/" + "a" * 32, "/api/anomalies",
    "/api/anomalies/" + "a" * 64, "/api/anomalies/" + "a" * 64 + "/rca", "/api/rca/" + "a" * 64,
])
def test_h3_a_rejected_request_never_opens_a_database_connection(path):
    with patch("app.connect", side_effect=_no_database) as connect:
        response = client.get(path, headers={"host": "evil.example"})
    assert response.status_code == 400
    connect.assert_not_called()


def test_h3_the_same_requests_with_an_allowed_host_do_reach_the_database_layer():
    # The control for the test above: the guard, not a broken route, is what stops the request.
    with patch("app.connect", side_effect=RuntimeError("no database")) as connect:
        response = client.get("/api/health/ready", headers={"host": "127.0.0.1:8001"})
    assert response.status_code == 503
    connect.assert_called_once()


# ---------------------------------------------------------------------------
# H4  Environment parsing
# ---------------------------------------------------------------------------

def _hosts(value: str | None) -> list[str]:
    environ = {} if value is None else {ENV_ALLOWED_HOSTS: value}
    return allowed_hosts_from_environment(environ)


def test_h4_unset_gives_exactly_the_two_loopback_names():
    assert _hosts(None) == ["127.0.0.1", "localhost"] == list(DEFAULT_ALLOWED_HOSTS)


def test_h4_configured_names_are_added_to_the_defaults_never_replace_them():
    assert _hosts("viewer.internal") == ["127.0.0.1", "localhost", "viewer.internal"]


def test_h4_names_are_trimmed_lowered_and_deduplicated():
    assert _hosts(" Viewer.Internal , dash-board.example.com,viewer.internal,LOCALHOST ") == [
        "127.0.0.1", "localhost", "viewer.internal", "dash-board.example.com"]


def test_h4_the_parser_reads_only_the_mapping_it_is_given(monkeypatch):
    monkeypatch.setenv(ENV_ALLOWED_HOSTS, "from-the-process-environment.example")
    assert allowed_hosts_from_environment({}) == ["127.0.0.1", "localhost"]


BAD_VALUES = [
    "", "   ", ",", "viewer.internal,", ",viewer.internal", "a.example,,b.example",     # empty value or entry
    "*", "*.example.com", "viewer.*", "a*b.example",                                   # wildcards
    "localhost:8000", "viewer.internal:80", "[::1]", "::1", "127.0.0.1:8001",          # ports, IPv6
    "http://localhost", "https://viewer.internal", "localhost/", "viewer.internal/path",
    "viewer.internal?x=1", "viewer.internal#frag", "user@viewer.internal",             # scheme, path, userinfo
    "a b.example", "viewer.internal evil.example", "a\tb.example",                     # whitespace inside an entry
    "example..com", ".example.com", "example.com.", "-bad.example", "bad-.example",    # malformed labels
    "ex_ample.com", "exämple.com", "K.example", "a" * 64 + ".example",           # characters, label length
    ".".join(["a" * 60] * 5),                                                          # total length > 253
]


@pytest.mark.parametrize("value", BAD_VALUES)
def test_h4_a_bad_setting_raises_and_is_never_relaxed(value):
    with pytest.raises(ValueError) as caught:
        _hosts(value)
    assert ENV_ALLOWED_HOSTS in str(caught.value)


def test_h4_the_error_message_never_repeats_the_configured_text():
    with pytest.raises(ValueError) as caught:
        _hosts("good.example,token-abc123/secret")
    assert "token-abc123" not in str(caught.value) and "secret" not in str(caught.value)
    assert "entry 2" in str(caught.value)


def test_h4_the_running_application_is_never_unrestricted():
    assert set(DEFAULT_ALLOWED_HOSTS) <= set(viewer.ALLOWED_HOSTS)
    assert "*" not in viewer.ALLOWED_HOSTS and not any(h.startswith("*") for h in viewer.ALLOWED_HOSTS)


# ---------------------------------------------------------------------------
# H5  Registration order
# ---------------------------------------------------------------------------

def test_h5_the_security_headers_middleware_is_outermost_so_it_wraps_the_host_check():
    # Starlette keeps the last-added middleware first in user_middleware: the outermost one.
    order = [middleware.cls for middleware in viewer.app.user_middleware]
    assert order.index(SecurityHeadersMiddleware) < order.index(TrustedHostMiddleware)
    assert order.count(TrustedHostMiddleware) == 1


# ---------------------------------------------------------------------------
# H6  The container health checks use an allowed hostname
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("compose", ["docker/mvp/compose.yml", "docker/mvp-workers/compose.yml",
                                     "docker/compose.trace-viewer.yml"])
def test_h6_the_viewer_health_check_calls_an_allowed_hostname(compose):
    text = (_REPO / compose).read_text(encoding="utf-8")
    hosts = re.findall(r"urlopen\('http://([^:/']+)", text)
    assert hosts, compose
    assert set(hosts) <= set(DEFAULT_ALLOWED_HOSTS), (compose, hosts)
