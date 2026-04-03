import re
from typing import Dict, Iterable, List, Optional

# Canonical risk taxonomy aligned with the requested experiment categories.
AIG_CANONICAL_TAXONOMY: List[str] = [
    "Data Exfiltration",
    "Data Destruction",
    "DoS (Denial of Service)",
    "Malware / Ransomware",
    "Phishing",
    "Backdoors",
    "Bias / Manipulation",
    "Poisoning",
]

_NORMALIZED_ALIASES: Dict[str, str] = {
    "data exfiltration": "Data Exfiltration",
    "exfiltration": "Data Exfiltration",
    "data leakage": "Data Exfiltration",
    "data leak": "Data Exfiltration",
    "credential leakage": "Data Exfiltration",
    "pii leakage": "Data Exfiltration",
    "information disclosure": "Data Exfiltration",
    "prompt leakage": "Data Exfiltration",
    "unauthorized access": "Data Exfiltration",
    "data theft": "Data Exfiltration",
    "sensitive data exposure": "Data Exfiltration",
    "data destruction": "Data Destruction",
    "destruction": "Data Destruction",
    "tampering": "Data Destruction",
    "sabotage": "Data Destruction",
    "wiper": "Data Destruction",
    "ransom data loss": "Data Destruction",
    "dos": "DoS (Denial of Service)",
    "ddos": "DoS (Denial of Service)",
    "denial of service": "DoS (Denial of Service)",
    "resource exhaustion": "DoS (Denial of Service)",
    "redos": "DoS (Denial of Service)",
    "malware": "Malware / Ransomware",
    "ransomware": "Malware / Ransomware",
    "trojan": "Malware / Ransomware",
    "worm": "Malware / Ransomware",
    "remote code execution": "Malware / Ransomware",
    "rce": "Malware / Ransomware",
    "phishing": "Phishing",
    "social engineering": "Phishing",
    "credential harvesting": "Phishing",
    "prompt scam": "Phishing",
    "backdoor": "Backdoors",
    "backdoors": "Backdoors",
    "persistence": "Backdoors",
    "stealth access": "Backdoors",
    "unauthorized persistent access": "Backdoors",
    "bias": "Bias / Manipulation",
    "manipulation": "Bias / Manipulation",
    "misinformation": "Bias / Manipulation",
    "propaganda": "Bias / Manipulation",
    "goal hijack": "Bias / Manipulation",
    "prompt injection": "Bias / Manipulation",
    "poisoning": "Poisoning",
    "data poisoning": "Poisoning",
    "model poisoning": "Poisoning",
    "context poisoning": "Poisoning",
    "memory poisoning": "Poisoning",
    "supply chain poisoning": "Poisoning",
}

_CATEGORY_KEYWORDS: Dict[str, List[str]] = {
    "Data Exfiltration": [
        "token", "secret", "api key", "credential", "password", "cookie", "session",
        "leak", "exfil", "dump", "download", "read file", "sensitive", "pii",
        "personal data", "private key", "prompt leak", "information disclosure",
        "数据泄露", "凭证", "密钥", "未授权读取",
    ],
    "Data Destruction": [
        "delete", "drop table", "truncate", "rm -rf", "overwrite", "wipe",
        "erase", "destroy", "corrupt", "tamper", "sabotage", "encrypt files",
        "数据删除", "篡改", "破坏", "清空",
    ],
    "DoS (Denial of Service)": [
        "dos", "ddos", "flood", "resource exhaustion", "cpu spike", "oom",
        "out of memory", "hang", "infinite loop", "deadlock", "regex dos", "redos",
        "服务拒绝", "拒绝服务", "资源耗尽",
    ],
    "Malware / Ransomware": [
        "malware", "ransomware", "payload", "trojan", "worm", "botnet",
        "dropper", "shellcode", "c2", "remote code execution", "command execution",
        "execute binary", "恶意代码", "勒索", "木马",
    ],
    "Phishing": [
        "phishing", "spoof", "impersonate", "fake login", "credential harvesting",
        "social engineering", "deceptive email", "sms scam", "reset password link",
        "钓鱼", "伪造登录", "社工",
    ],
    "Backdoors": [
        "backdoor", "persistence", "cron", "startup script", "hidden account",
        "maintain access", "implant", "covert channel", "reverse shell", "webshell",
        "后门", "持久化", "隐蔽通道",
    ],
    "Bias / Manipulation": [
        "bias", "manipulation", "steer output", "narrative control", "misinformation",
        "disinformation", "propaganda", "prompt injection", "goal hijack",
        "jailbreak", "偏见", "操控", "误导",
    ],
    "Poisoning": [
        "poison", "data poisoning", "training data", "knowledge base", "rag injection",
        "memory poisoning", "retrieval poisoning", "supply chain", "dependency poisoning",
        "投毒", "数据污染", "知识库污染",
    ],
}


def _normalize_key(value: str) -> str:
    v = str(value or "").strip().lower()
    v = v.replace("_", " ").replace("-", " ")
    v = re.sub(r"\s+", " ", v)
    return v


def normalize_taxonomy_label(value: str) -> Optional[str]:
    """Map free-form labels to one canonical taxonomy category."""
    key = _normalize_key(value)
    if not key:
        return None
    if key in _NORMALIZED_ALIASES:
        return _NORMALIZED_ALIASES[key]
    for canonical in AIG_CANONICAL_TAXONOMY:
        if _normalize_key(canonical) == key:
            return canonical
    return None


def _iter_text_chunks(items: Iterable[str]) -> Iterable[str]:
    for item in items:
        text = str(item or "").strip().lower()
        if text:
            yield text


def taxonomy_scores(text_chunks: Iterable[str]) -> Dict[str, int]:
    scores = {k: 0 for k in AIG_CANONICAL_TAXONOMY}
    merged = " \n ".join(_iter_text_chunks(text_chunks))
    if not merged:
        return scores

    for category, keywords in _CATEGORY_KEYWORDS.items():
        for kw in keywords:
            needle = kw.lower()
            if not needle:
                continue
            if re.search(r"[a-z0-9]", needle):
                # English-like keyword: bounded match to reduce accidental hits.
                pattern = r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])"
                if re.search(pattern, merged):
                    scores[category] += 1
            elif needle in merged:
                scores[category] += 1
    return scores


def infer_taxonomy_category(
    raw_label: str = "",
    attack_surface: Optional[List[str]] = None,
    trigger_patterns: Optional[List[str]] = None,
    skill_content: str = "",
) -> str:
    """
    Infer canonical category from raw label plus content signals.
    Falls back to Data Exfiltration as a conservative default for attacker coupling.
    """
    normalized = normalize_taxonomy_label(raw_label)
    if normalized:
        return normalized

    chunks: List[str] = [raw_label or "", skill_content or ""]
    chunks.extend(attack_surface or [])
    chunks.extend(trigger_patterns or [])
    scores = taxonomy_scores(chunks)

    # Stable tie-break order equals canonical taxonomy declaration order.
    best = "Data Exfiltration"
    best_score = -1
    for category in AIG_CANONICAL_TAXONOMY:
        s = scores.get(category, 0)
        if s > best_score:
            best = category
            best_score = s
    return best

