"""Schemas round-trip through JSON and reject malformed data."""

from datetime import timedelta

import pytest
from pydantic import ValidationError

from poisonlens.core.config import ScanConfig
from poisonlens.core.schemas import (
    STAGE_ORDER,
    Capabilities,
    ColumnProfile,
    DatasetProfile,
    Finding,
    LabelCandidate,
    Location,
    Modality,
    ScanState,
    ScanStatus,
    Severity,
    SplitInfo,
    StageName,
    StageResult,
    StageStatus,
    Tier,
    Verdict,
    utc_now,
)

SHA = "a" * 64


def _finding(**kw):
    base = dict(
        id="F03-0001",
        check_id="F03",
        severity=Severity.CRITICAL,
        title="Archive member escapes extraction root",
        detail="Member path contains '..'",
        evidence={"member": "../../evil.sh", "count": 1},
        location=Location(file="images/../../evil.sh"),
        owasp_refs=["OWASP File Upload CS"],
        cwe=["CWE-22", "CWE-59"],
        remediation="Rebuild the archive without traversal paths.",
    )
    base.update(kw)
    return Finding(**base)


def _full_state() -> ScanState:
    t0 = utc_now()
    profile = DatasetProfile(
        format="csv",
        modality=Modality.TABULAR,
        n_records=1000,
        columns=[ColumnProfile(name="age", dtype="int64", null_rate=0.0, cardinality=70)],
        label_candidates=[LabelCandidate(column="label", score=0.9, reason="name match + 2 classes")],
        label_chosen="label",
        splits=SplitInfo(column="split", counts={"train": 800, "test": 200}),
        class_hist={"0": 600, "1": 400},
        capabilities=Capabilities(labels=True, probe=True, detect=True),
    )
    return ScanState(
        scan_id="scan_0123abcd",
        status=ScanStatus.RUNNING,
        current_stage=StageName.PROBE,
        profile=profile,
        config=ScanConfig(profile="quick"),
        stage_results={
            StageName.INGEST: StageResult(
                stage=StageName.INGEST,
                status=StageStatus.DONE,
                started_at=t0,
                ended_at=t0 + timedelta(seconds=2),
                artifacts={"upload/original.csv": SHA},
            ),
            StageName.SECURITY: StageResult(stage=StageName.SECURITY, status=StageStatus.SKIPPED, warnings=["x"]),
        },
        verdict=Verdict.SUSPICIOUS,
    )


def test_scan_state_round_trip():
    state = _full_state()
    again = ScanState.model_validate_json(state.model_dump_json())
    assert again == state
    assert again.stage_results[StageName.INGEST].started_at.tzinfo is not None


def test_finding_round_trip():
    f = _finding()
    assert Finding.model_validate_json(f.model_dump_json()) == f


def test_extra_fields_rejected():
    data = _finding().model_dump(mode="json")
    data["surprise"] = 1
    with pytest.raises(ValidationError):
        Finding.model_validate(data)
    state = _full_state().model_dump(mode="json")
    state["config"]["probe"]["typo"] = 1
    with pytest.raises(ValidationError):
        ScanState.model_validate(state)


@pytest.mark.parametrize("check_id", ["f03", "F3", "F003", "XX1", ""])
def test_bad_check_id(check_id):
    with pytest.raises(ValidationError):
        _finding(check_id=check_id)


@pytest.mark.parametrize("cwe", [["22"], ["CWE22"], ["CWE-abc"]])
def test_bad_cwe(cwe):
    with pytest.raises(ValidationError):
        _finding(cwe=cwe)


@pytest.mark.parametrize("digest", ["A" * 64, "a" * 63, "g" * 64, "sha256:" + "a" * 64])
def test_bad_artifact_hash(digest):
    with pytest.raises(ValidationError):
        StageResult(stage=StageName.SEAL, status=StageStatus.DONE, artifacts={"x": digest})


def test_severity_sorting():
    shuffled = [Severity.LOW, Severity.CRITICAL, Severity.INFO, Severity.HIGH, Severity.MEDIUM]
    assert sorted(shuffled, key=lambda s: s.rank) == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]


def test_tier_weights():
    assert [Tier.KEEP.weight, Tier.DOWNWEIGHT.weight, Tier.QUARANTINE.weight] == [1.0, 0.20, 0.0]
    assert [t.value for t in Tier] == [1, 2, 3]


def test_enum_values_match_spec():
    assert [m.value for m in Modality] == ["tabular", "text", "image", "audio", "mixed"]
    assert [s.value for s in Severity] == ["critical", "high", "medium", "low", "info"]
    assert [s.value for s in STAGE_ORDER] == [
        "ingest",
        "inspect",
        "security",
        "quality",
        "probe",
        "detect",
        "sanitize",
        "seal",
    ]


def test_capabilities_reasons():
    caps = Capabilities(labels=False, probe=False, detect=False, reasons={"probe": "no label column"})
    assert caps.security and caps.quality
    assert Capabilities.model_validate_json(caps.model_dump_json()) == caps


@pytest.mark.parametrize("field,value", [("null_rate", 1.5), ("cardinality", -1)])
def test_column_profile_bounds(field, value):
    kw = dict(name="c", dtype="int64", null_rate=0.0, cardinality=1)
    kw[field] = value
    with pytest.raises(ValidationError):
        ColumnProfile(**kw)
