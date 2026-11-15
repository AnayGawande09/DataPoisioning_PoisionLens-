"""docs/CONFIG.md must match the ScanConfig defaults."""

import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_config_doc_is_current():
    render = runpy.run_path(str(ROOT / "scripts" / "gen_config_doc.py"))["render"]
    current = (ROOT / "docs" / "CONFIG.md").read_text(encoding="utf-8")
    assert current.replace("\r\n", "\n") == render(), "docs/CONFIG.md is stale: run scripts/gen_config_doc.py"


def test_every_field_is_documented():
    render = runpy.run_path(str(ROOT / "scripts" / "gen_config_doc.py"))["render"]
    table = [line for line in render().splitlines() if line.startswith("| `")]
    undocumented = [line for line in table if "| - |" in line]
    assert not undocumented, f"fields without a spec/provisional description: {undocumented}"
