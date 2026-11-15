"""Backend API tests for the v2 Phase 0 surface (health + security guards)."""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.main import app
from backend.security import safe_resolve_path, validate_identifier

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["torch_device"] in {"cpu", "cuda"}


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/api/presets"),
        ("get", "/api/benchmarks"),
        ("get", "/api/runs"),
        ("post", "/api/runs/start"),
        ("post", "/api/runs/attack_badnets_5/audit/simulate-tamper"),
    ],
)
def test_removed_v1_endpoints_are_gone(method, path):
    res = getattr(client, method)(path)
    assert res.status_code in (404, 405)


@pytest.mark.parametrize("bad", ["", "../etc", "a/b", "a\\b", "id with space", "x;rm", "..", "%2e%2e"])
def test_validate_identifier_rejects(bad):
    with pytest.raises(HTTPException):
        validate_identifier(bad)


def test_validate_identifier_accepts():
    assert validate_identifier("scan_ABC-123") == "scan_ABC-123"


@pytest.mark.parametrize("bad", ["../outside.txt", "..\\outside.txt", "sub/../../outside.txt"])
def test_safe_resolve_path_rejects_traversal(tmp_path, bad):
    with pytest.raises(HTTPException):
        safe_resolve_path(tmp_path, bad)


def test_safe_resolve_path_rejects_absolute(tmp_path):
    other = tmp_path.parent / "elsewhere.txt"
    with pytest.raises(HTTPException):
        safe_resolve_path(tmp_path, str(other))


def test_safe_resolve_path_rejects_sibling_prefix(tmp_path):
    # "base_evil" shares a string prefix with "base"; v1's startswith check accepted this.
    base = tmp_path / "base"
    base.mkdir()
    with pytest.raises(HTTPException):
        safe_resolve_path(base, "../base_evil/x.txt")


def test_safe_resolve_path_accepts_inside(tmp_path):
    assert safe_resolve_path(tmp_path, "sub/file.json") == (tmp_path / "sub" / "file.json").resolve()
