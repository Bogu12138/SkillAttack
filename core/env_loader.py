from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Optional

_LOADED_ENV_PATHS: set[str] = set()


def _default_project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _candidate_env_paths(project_root: Path, cwd: Path) -> List[Path]:
    candidates: List[Path] = [project_root / ".env"]

    if cwd == project_root or project_root in cwd.parents:
        local_env = cwd / ".env"
        if local_env != candidates[0]:
            candidates.append(local_env)

    unique: List[Path] = []
    seen = set()
    for path in candidates:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _strip_inline_comment(value: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\" and in_double:
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            continue
        if char == "#" and not in_single and not in_double:
            if index == 0 or value[index - 1].isspace():
                return value[:index].rstrip()
    return value.strip()


def _parse_env_line(line: str) -> Optional[tuple[str, str]]:
    text = line.strip()
    if not text or text.startswith("#"):
        return None

    if text.startswith("export "):
        text = text[len("export ") :].lstrip()

    if "=" not in text:
        return None

    key, raw_value = text.split("=", 1)
    key = key.strip()
    if not key:
        return None

    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        quote = value[0]
        value = value[1:-1]
        if quote == '"':
            value = bytes(value, "utf-8").decode("unicode_escape")
        return key, value

    return key, _strip_inline_comment(value)


def load_env_file(path: Path, *, override: bool = True) -> bool:
    env_path = path.expanduser().resolve()
    if not env_path.exists() or not env_path.is_file():
        return False

    with env_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            parsed = _parse_env_line(raw_line.lstrip("\ufeff"))
            if not parsed:
                continue
            key, value = parsed
            if override or key not in os.environ:
                os.environ[key] = value
    return True


def load_dotenv_if_present(
    *,
    project_root: Optional[Path] = None,
    cwd: Optional[Path] = None,
    override: bool = True,
) -> List[Path]:
    resolved_project_root = Path(project_root or _default_project_root()).expanduser().resolve()
    resolved_cwd = Path(cwd or Path.cwd()).expanduser().resolve()

    loaded: List[Path] = []
    for path in _candidate_env_paths(resolved_project_root, resolved_cwd):
        resolved_path = path.expanduser().resolve()
        path_key = str(resolved_path)
        if path_key in _LOADED_ENV_PATHS:
            continue
        if load_env_file(resolved_path, override=override):
            _LOADED_ENV_PATHS.add(path_key)
            loaded.append(resolved_path)
    return loaded
