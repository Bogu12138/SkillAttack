#!/usr/bin/env python3
"""
Upload experiment results to SkillAtlas.

Usage:
    python3 scripts/upload_results.py result/runs_organize/batch_cached/qwen3.5-plus
    python3 scripts/upload_results.py --list-keys
    python3 scripts/upload_results.py --check cmxxxxxx
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import requests

ROOT = Path(__file__).resolve().parents[1]
UPLOAD_URL = "https://skillatlas.org/api/uploads"
SUBMISSIONS_URL = "https://skillatlas.org/api/submissions"
KEYS_FILE = ROOT / "result" / ".upload_keys.json"
MAX_UPLOAD_SIZE_MB = 25


def _count_completed_skills(run_root: Path) -> int:
    return sum(1 for _ in run_root.rglob("*_global_report.json"))


def _create_zip(run_root: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tmp_dir = Path(tempfile.mkdtemp(prefix="skillattack_upload_"))
    archive_base = tmp_dir / f"upload_{run_root.name}_{timestamp}"
    archive_path = Path(shutil.make_archive(
        str(archive_base), "zip",
        root_dir=str(run_root.parent),
        base_dir=run_root.name,
    ))
    return archive_path


def _upload(zip_path: Path) -> Dict[str, Any]:
    size_mb = zip_path.stat().st_size / (1024 * 1024)
    if size_mb > MAX_UPLOAD_SIZE_MB:
        print(f"WARNING: zip size is {size_mb:.1f}MB, exceeds {MAX_UPLOAD_SIZE_MB}MB limit.")
        print("The upload may be rejected by the server.")
        print()

    print(f"Uploading {zip_path.name} ({size_mb:.1f}MB) ...")

    with zip_path.open("rb") as f:
        resp = requests.post(
            UPLOAD_URL,
            files={"bundle": (zip_path.name, f, "application/zip")},
            data={"source": "api"},
            timeout=300,
        )

    if resp.status_code not in (200, 201):
        try:
            err = resp.json()
        except Exception:
            err = resp.text[:500]
        raise RuntimeError(f"Upload failed (HTTP {resp.status_code}): {err}")

    return resp.json()


def _save_key(submission_id: str, run_root: str, skills_count: int) -> None:
    records: List[Dict[str, Any]] = []
    if KEYS_FILE.exists():
        try:
            records = json.loads(KEYS_FILE.read_text(encoding="utf-8"))
        except Exception:
            records = []

    records.append({
        "submissionId": submission_id,
        "run_root": run_root,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "skills_count": skills_count,
    })

    KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
    KEYS_FILE.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")


def _list_keys() -> None:
    if not KEYS_FILE.exists():
        print("No upload records found.")
        return

    try:
        records = json.loads(KEYS_FILE.read_text(encoding="utf-8"))
    except Exception:
        print("Failed to read upload records.")
        return

    if not records:
        print("No upload records found.")
        return

    print(f"Upload history ({len(records)} records):\n")
    for i, rec in enumerate(records, 1):
        sid = rec.get("submissionId", "?")
        root = rec.get("run_root", "?")
        at = rec.get("uploaded_at", "?")
        skills = rec.get("skills_count", "?")
        print(f"  [{i}] {sid}")
        print(f"      run_root:    {root}")
        print(f"      uploaded_at: {at}")
        print(f"      skills:      {skills}")
        print(f"      view:        {SUBMISSIONS_URL}/{sid}")
        print()


def _check_submission(submission_id: str) -> None:
    url = f"{SUBMISSIONS_URL}/{submission_id}"
    print(f"Querying {url} ...")

    try:
        resp = requests.get(url, timeout=30)
    except Exception as e:
        print(f"Request failed: {e}")
        return

    if resp.status_code != 200:
        print(f"HTTP {resp.status_code}: {resp.text[:500]}")
        return

    data = resp.json()
    print(json.dumps(data, ensure_ascii=False, indent=2))


def cmd_upload(run_root_str: str) -> int:
    run_root = Path(run_root_str).resolve()
    if not run_root.is_dir():
        print(f"ERROR: directory not found: {run_root}")
        return 1

    completed = _count_completed_skills(run_root)
    if completed == 0:
        print(f"ERROR: no completed skills found in {run_root}")
        print("A skill is considered complete when it has a *_global_report.json file.")
        return 1

    print(f"Directory:        {run_root}")
    print(f"Completed skills: {completed}")
    print()

    zip_path = _create_zip(run_root)
    try:
        result = _upload(zip_path)
    finally:
        shutil.rmtree(str(zip_path.parent), ignore_errors=True)

    submission_id = result.get("submissionId", "")
    status = result.get("status", "")

    print()
    print("Upload successful!")
    print(f"  submissionId: {submission_id}")
    print(f"  status:       {status}")
    print(f"  view:         {SUBMISSIONS_URL}/{submission_id}")

    if submission_id:
        _save_key(submission_id, str(run_root), completed)
        print(f"\nKey saved to {KEYS_FILE}")

    return 0


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Upload experiment results to SkillAtlas.")
    parser.add_argument("run_root", nargs="?", help="Path to the result directory to upload")
    parser.add_argument("--list-keys", action="store_true", help="List all previous upload records")
    parser.add_argument("--check", type=str, metavar="SUBMISSION_ID", help="Check submission status")
    args = parser.parse_args()

    if args.list_keys:
        _list_keys()
        return 0

    if args.check:
        _check_submission(args.check)
        return 0

    if not args.run_root:
        parser.print_help()
        return 1

    return cmd_upload(args.run_root)


if __name__ == "__main__":
    raise SystemExit(main())
