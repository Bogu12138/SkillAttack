#!/usr/bin/env python3
from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGET_DIR = REPO_ROOT / "data" / "hot100skills"
DEFAULT_CONVEX_URL = "https://wry-manatee-359.convex.cloud/api/query"
DEFAULT_SITE_URL = "https://clawhub.ai"
DEFAULT_REGISTRY_URL = "https://clawhub.ai"
DEFAULT_LIMIT = 100
DOWNLOAD_REQUEST_GAP_SECONDS = 2.2
_LAST_DOWNLOAD_REQUEST_AT = 0.0
def _slugify(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(text or "").strip()).strip("-")


def _ranking_dir_name(rank: int, owner_handle: str, slug: str) -> str:
    owner = _slugify(owner_handle) or "unknown"
    skill_slug = _slugify(slug) or f"skill-{rank:03d}"
    return f"{rank:03d}_{owner}_{skill_slug}"


def _parse_retry_after(stderr_text: str) -> float:
    text = str(stderr_text or "")
    match = re.search(r"retry-after[:=]?\s*(\d+)", text, flags=re.IGNORECASE)
    if match:
        return max(1.0, float(match.group(1)))
    match = re.search(r"retry in\s+(\d+)s", text, flags=re.IGNORECASE)
    if match:
        return max(1.0, float(match.group(1)))
    return 2.0


def _parse_header_file(header_text: str) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for raw_line in str(header_text or "").splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key and value:
            headers[key] = value
    return headers


def _download_skill_zip(
    *,
    slug: str,
    version: str,
    registry_url: str,
    retries: int = 30,
) -> bytes:
    global _LAST_DOWNLOAD_REQUEST_AT
    url = f"{registry_url.rstrip('/')}/api/v1/download?slug={slug}&version={version}"
    last_error: Optional[str] = None

    for attempt in range(1, retries + 1):
        now = time.time()
        since_last = now - _LAST_DOWNLOAD_REQUEST_AT
        if since_last < DOWNLOAD_REQUEST_GAP_SECONDS:
            time.sleep(DOWNLOAD_REQUEST_GAP_SECONDS - since_last)
        with tempfile.TemporaryDirectory(prefix="clawhub_zip_") as tmpdir:
            zip_path = Path(tmpdir) / "skill.zip"
            header_path = Path(tmpdir) / "headers.txt"
            cmd = [
                "curl",
                "--silent",
                "--show-error",
                "--location",
                "--max-time",
                "60",
                "-D",
                str(header_path),
                "-o",
                str(zip_path),
                "--write-out",
                "%{http_code}",
                url,
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                timeout=90,
            )
            _LAST_DOWNLOAD_REQUEST_AT = time.time()
            if proc.returncode != 0:
                last_error = proc.stderr or proc.stdout or "curl failed"
                if attempt < retries:
                    time.sleep(min(8.0, float(attempt)))
                    continue
                break

            status = int((proc.stdout or "0").strip())
            headers = _parse_header_file(header_path.read_text(encoding="utf-8", errors="replace"))
            if 200 <= status < 300:
                zip_bytes = zip_path.read_bytes()
                if not zip_bytes:
                    last_error = "download returned an empty file"
                else:
                    return zip_bytes
            else:
                body_text = ""
                if zip_path.exists():
                    try:
                        body_text = zip_path.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        body_text = ""
                retry_after = headers.get("retry-after") or headers.get("ratelimit-reset") or ""
                last_error = f"HTTP {status}: {body_text}".strip()
                if retry_after:
                    last_error = f"{last_error} (retry-after: {retry_after})".strip()
                if status == 429 and attempt < retries:
                    time.sleep(_parse_retry_after(last_error))
                    continue
                if status >= 500 and attempt < retries:
                    time.sleep(min(8.0, float(attempt)))
                    continue
                break

    raise RuntimeError(f"Failed to download {slug}@{version} after {retries} attempts. {last_error or ''}".strip())


def _extract_zip_to_dir(zip_bytes: bytes, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        for member in archive.infolist():
            member_name = member.filename
            if not member_name or member_name.endswith("/"):
                continue
            parts = Path(member_name).parts
            if any(part in ("", ".", "..") for part in parts):
                raise RuntimeError(f"Unsafe zip entry: {member_name}")
            dest_path = target_dir.joinpath(*parts)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member, "r") as src, dest_path.open("wb") as dst:
                shutil.copyfileobj(src, dst)


def _write_skill_origin(target_dir: Path, *, registry_url: str, slug: str, version: str) -> None:
    origin_dir = target_dir / ".clawhub"
    origin_dir.mkdir(parents=True, exist_ok=True)
    origin = {
        "version": 1,
        "registry": registry_url,
        "slug": slug,
        "installedVersion": version,
        "installedAt": int(time.time() * 1000),
    }
    (origin_dir / "origin.json").write_text(
        json.dumps(origin, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _fetch_skill_page(
    *,
    convex_query_url: str,
    cursor: Optional[str],
    page_size: int,
) -> Dict[str, Any]:
    args = {
        "numItems": page_size,
        "sort": "downloads",
        "dir": "desc",
        "highlightedOnly": False,
        "nonSuspiciousOnly": True,
    }
    if cursor:
        args["cursor"] = cursor
    payload = {
        "path": "skills:listPublicPageV4",
        "args": args,
        "format": "json",
    }
    cmd = [
        "curl",
        "-sS",
        convex_query_url,
        "-H",
        "Content-Type: application/json",
        "-d",
        json.dumps(payload, separators=(",", ":")),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"curl failed for Convex query: {proc.stderr or proc.stdout}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Convex query returned non-JSON data: {proc.stdout[:500]}") from exc
    if data.get("status") != "success" or not isinstance(data.get("value"), dict):
        raise RuntimeError(f"Unexpected Convex response: {data}")
    return data["value"]


def fetch_top_skills(*, convex_query_url: str, limit: int) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    cursor: Optional[str] = None
    seen: set[Tuple[str, str]] = set()
    page_size = min(100, max(1, limit))

    while len(results) < limit:
        page = None
        last_error: Optional[Exception] = None
        for attempt in range(1, 9):
            try:
                page = _fetch_skill_page(convex_query_url=convex_query_url, cursor=cursor, page_size=page_size)
                last_error = None
                break
            except RuntimeError as exc:
                last_error = exc
                text = str(exc)
                if "Rate limit exceeded" in text:
                    time.sleep(_parse_retry_after(text))
                    continue
                if "Server Error" in text:
                    time.sleep(min(8.0, float(attempt)))
                    continue
                raise
        if page is None:
            raise RuntimeError(f"Failed to fetch skill page after retries: {last_error}")

        items = list(page.get("page") or [])
        for item in items:
            skill = item.get("skill") or {}
            owner_handle = str(item.get("ownerHandle") or "").strip()
            slug = str(skill.get("slug") or "").strip()
            if not owner_handle or not slug:
                continue
            key = (owner_handle, slug)
            if key in seen:
                continue
            seen.add(key)
            results.append(item)
            if len(results) >= limit:
                break

        if len(results) >= limit:
            break
        if not page.get("hasMore"):
            break
        cursor = page.get("nextCursor")
        if not cursor:
            break

    return results[:limit]


def _install_skill(
    *,
    slug: str,
    version: str,
    stage_root: Path,
    registry_url: str,
    retries: int = 30,
) -> Path:
    stage_root.mkdir(parents=True, exist_ok=True)
    install_dir = stage_root / "skills"
    install_dir.mkdir(parents=True, exist_ok=True)
    skill_path = install_dir / slug
    if skill_path.exists():
        shutil.rmtree(skill_path)
    skill_path.mkdir(parents=True, exist_ok=True)
    zip_bytes = _download_skill_zip(
        slug=slug,
        version=version,
        registry_url=registry_url,
        retries=retries,
    )
    try:
        _extract_zip_to_dir(zip_bytes, skill_path)
    except zipfile.BadZipFile as exc:
        raise RuntimeError(f"Downloaded payload for {slug}@{version} is not a zip file") from exc
    _write_skill_origin(
        skill_path,
        registry_url=registry_url,
        slug=slug,
        version=version,
    )
    return skill_path


def _backup_target_dir(target_dir: Path) -> Optional[Path]:
    if not target_dir.exists():
        return None
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = target_dir.with_name(f"{target_dir.name}_backup_{timestamp}")
    target_dir.rename(backup_dir)
    return backup_dir


def _write_manifest(target_dir: Path, manifest: Dict[str, Any]) -> Path:
    manifest_path = target_dir / "_clawhub_hot100_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Download the current top downloaded non-suspicious ClawHub skills into a local directory.",
    )
    parser.add_argument(
        "--target-dir",
        default=str(DEFAULT_TARGET_DIR),
        help="Directory to populate with the downloaded skills.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="How many skills to download.",
    )
    parser.add_argument(
        "--convex-query-url",
        default=DEFAULT_CONVEX_URL,
        help="Convex query endpoint used by clawhub.ai.",
    )
    parser.add_argument(
        "--site-url",
        default=DEFAULT_SITE_URL,
        help="ClawHub site URL passed to the CLI.",
    )
    parser.add_argument(
        "--registry-url",
        default=DEFAULT_REGISTRY_URL,
        help="ClawHub registry URL passed to the CLI.",
    )
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help="Do not rename the existing target directory before downloading.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit <= 0:
        raise SystemExit("--limit must be > 0")

    target_dir = Path(args.target_dir).expanduser().resolve()
    parent_dir = target_dir.parent
    parent_dir.mkdir(parents=True, exist_ok=True)

    print(f"[hot100] Fetching current top {args.limit} skills from {DEFAULT_SITE_URL} ...")
    skills = fetch_top_skills(convex_query_url=args.convex_query_url, limit=args.limit)
    if len(skills) < args.limit:
        raise RuntimeError(f"Only fetched {len(skills)} skills, expected {args.limit}.")

    backup_dir = None
    if target_dir.exists() and not args.keep_existing:
        backup_dir = _backup_target_dir(target_dir)
        print(f"[hot100] Existing directory backed up to: {backup_dir}")

    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    manifest_entries: List[Dict[str, Any]] = []
    download_started_at = datetime.now(timezone.utc).isoformat()
    for rank, item in enumerate(skills, start=1):
        skill = item["skill"]
        owner_handle = str(item.get("ownerHandle") or "").strip()
        slug = str(skill.get("slug") or "").strip()
        version = str((item.get("latestVersion") or {}).get("version") or "").strip()
        downloads = skill.get("stats", {}).get("downloads")
        if not slug or not version:
            raise RuntimeError(f"Missing slug/version in skill payload: {item}")

        print(f"[hot100] ({rank:03d}/{len(skills):03d}) {owner_handle}/{slug}@{version}")
        with tempfile.TemporaryDirectory(prefix=f"clawhub_stage_{rank:03d}_") as tmpdir:
            staged_root = Path(tmpdir)
            staged_skill = _install_skill(
                slug=slug,
                version=version,
                stage_root=staged_root,
                registry_url=args.registry_url,
            )
            dest_name = _ranking_dir_name(rank, owner_handle, slug)
            dest_path = target_dir / dest_name
            shutil.move(str(staged_skill), str(dest_path))

        manifest_entries.append(
            {
                "rank": rank,
                "ownerHandle": owner_handle,
                "slug": slug,
                "displayName": skill.get("displayName"),
                "version": version,
                "downloads": downloads,
                "installsAllTime": skill.get("stats", {}).get("installsAllTime"),
                "stars": skill.get("stats", {}).get("stars"),
                "sourceUrl": f"{args.site_url}/{owner_handle}/{slug}",
                "directory": dest_name,
            }
        )

    manifest = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "downloadStartedAt": download_started_at,
        "siteUrl": args.site_url,
        "sourceListingUrl": f"{args.site_url}/skills?sort=downloads&nonSuspicious=true",
        "convexQueryUrl": args.convex_query_url,
        "limit": args.limit,
        "backupDir": str(backup_dir) if backup_dir else "",
        "entries": manifest_entries,
    }
    manifest_path = _write_manifest(target_dir, manifest)

    print(f"[hot100] Done. Downloaded {len(manifest_entries)} skills into {target_dir}")
    print(f"[hot100] Manifest: {manifest_path}")
    if backup_dir:
        print(f"[hot100] Backup preserved at: {backup_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
