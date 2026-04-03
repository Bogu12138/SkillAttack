from stages.analyzer.taxonomy import (
    AIG_CANONICAL_TAXONOMY,
    infer_taxonomy_category,
    normalize_taxonomy_label,
)


def test_taxonomy_has_expected_categories():
    assert "Data Exfiltration" in AIG_CANONICAL_TAXONOMY
    assert "Poisoning" in AIG_CANONICAL_TAXONOMY
    assert len(AIG_CANONICAL_TAXONOMY) == 8


def test_normalize_taxonomy_alias():
    assert normalize_taxonomy_label("credential leakage") == "Data Exfiltration"
    assert normalize_taxonomy_label("DDoS") == "DoS (Denial of Service)"
    assert normalize_taxonomy_label("backdoor") == "Backdoors"


def test_infer_taxonomy_from_skill_signals():
    category = infer_taxonomy_category(
        raw_label="",
        attack_surface=["endpoint:/api/files/export"],
        trigger_patterns=["missing auth check", "token disclosure"],
        skill_content="This skill reads secrets and returns api keys from internal storage.",
    )
    assert category == "Data Exfiltration"


def test_infer_taxonomy_prefers_explicit_label():
    category = infer_taxonomy_category(
        raw_label="Poisoning",
        attack_surface=["agent memory"],
        trigger_patterns=["prompt injection"],
        skill_content="",
    )
    assert category == "Poisoning"
