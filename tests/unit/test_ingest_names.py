"""Member-name analysis (F03 unsafe vs F04 hygiene)."""

import pytest

from poisonlens.ingest.names import analyze_member_path, collision_key


@pytest.mark.parametrize(
    "raw",
    ["../x", "a/../../x", "/abs", "\\abs", "C:/x", "c:x", "\\\\srv\\share\\x", "//srv/share", "a\\..\\..\\x"],
)
def test_unsafe(raw):
    check = analyze_member_path(raw)
    assert check.unsafe and check.sanitized is None


@pytest.mark.parametrize(
    "raw,sanitized",
    [
        ("a/b/c.png", "a/b/c.png"),
        ("./a/./b.png", "a/b.png"),
        ("a\\b.png", "a/b.png"),
        ("a//b.png", "a/b.png"),
        ("cafe\u0301.txt", "caf\u00e9.txt"),  # NFC
    ],
)
def test_clean(raw, sanitized):
    check = analyze_member_path(raw)
    assert check.sanitized == sanitized and not check.unsafe and not check.hygiene


def test_dotdot_inside_a_name_is_fine():
    check = analyze_member_path("a/..b/c..d.png")
    assert check.sanitized == "a/..b/c..d.png" and not check.unsafe


@pytest.mark.parametrize("raw", ["", ".", "./", "a\x00b"])
def test_unusable(raw):
    check = analyze_member_path(raw)
    assert check.sanitized is None and not check.unsafe and check.hygiene


def test_max_total_length():
    check = analyze_member_path("/".join(["d" * 100] * 12), max_total_length=1024)
    assert check.sanitized is None and "path longer than limit" in check.hygiene


def test_collision_key():
    assert collision_key("Data/IMG.png") == collision_key("data/img.PNG")
    assert collision_key("Stra\u00dfe") == collision_key("STRASSE")  # casefold, not lower
