"""The dev-only bench harness must never be imported by product code.

Static check (AST) over ``backend/`` and every ``poisonlens`` subpackage except
``poisonlens/bench`` itself, so it also catches lazy imports inside functions.
"""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ("poisonlens.bench", "poisonlens.attacks")


def _product_files():
    files = list((ROOT / "backend").rglob("*.py"))
    for f in (ROOT / "poisonlens").rglob("*.py"):
        if "bench" not in f.relative_to(ROOT / "poisonlens").parts:
            files.append(f)
    return sorted(files)


def _imported_modules(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module
            for alias in node.names:
                yield f"{node.module}.{alias.name}"


def test_product_files_found():
    files = _product_files()
    assert any(f.parent.name == "backend" for f in files)
    assert any("pipeline" in f.parts for f in files)


@pytest.mark.parametrize("path", _product_files(), ids=lambda p: str(p.relative_to(ROOT)))
def test_no_bench_import(path):
    bad = [m for m in _imported_modules(path) if m.startswith(FORBIDDEN) or m == "poisonlens.bench"]
    assert not bad, f"{path.relative_to(ROOT)} imports dev-only modules: {bad}"


def test_detector_catches_violation(tmp_path):
    probe = tmp_path / "probe.py"
    probe.write_text("def f():\n    from poisonlens.bench.attacks import badnets\n", encoding="utf-8")
    assert any(m.startswith(FORBIDDEN) for m in _imported_modules(probe))
