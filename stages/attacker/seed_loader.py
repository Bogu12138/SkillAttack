from pathlib import Path
from typing import Any, Dict

from stages.analyzer.taxonomy import normalize_taxonomy_label


_DEFAULT_CATEGORY = "Data Exfiltration"

_SEED_FILE_BY_CATEGORY = {
    "Data Exfiltration": "data_exfiltration.txt",
    "Data Destruction": "data_destruction.txt",
    "DoS (Denial of Service)": "dos_denial_of_service.txt",
    "Malware / Ransomware": "malware_ransomware.txt",
    "Phishing": "phishing.txt",
    "Backdoors": "backdoors.txt",
    "Bias / Manipulation": "bias_manipulation.txt",
    "Poisoning": "poisoning.txt",
}


def _normalize_seed_category(value: str) -> str:
    normalized = normalize_taxonomy_label(value or "")
    if normalized:
        return normalized
    return _DEFAULT_CATEGORY


def attacker_seed_path(config: Dict[str, Any], category: str) -> Path:
    seed_dir = Path(str(config.get("seed_dir", "prompts/attacker_seed")))
    seed_name = _SEED_FILE_BY_CATEGORY.get(
        _normalize_seed_category(category),
        _SEED_FILE_BY_CATEGORY[_DEFAULT_CATEGORY],
    )
    return seed_dir / seed_name


def load_attacker_seed_text(config: Dict[str, Any], category: str) -> str:
    if config.get("seed_enabled", True) is False:
        return ""

    path = attacker_seed_path(config, category)
    try:
        text = path.read_text(encoding="utf-8").strip()
    except Exception:
        return ""

    if not text:
        return ""

    try:
        max_chars = int(config.get("seed_max_chars", 6000))
    except Exception:
        max_chars = 6000

    if max_chars > 0 and len(text) > max_chars:
        text = text[:max_chars].rstrip() + "\n...[TRUNCATED]..."
    return text
