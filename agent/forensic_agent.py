#!/usr/bin/env python3
"""
forensic_agent.py — Lightweight CLI agent for the Digital Forensics Platform.

Runs on the *investigator's* machine (macOS or Windows). Its job is to:

  1. Take a path to a disk image or a directory on the local machine.
  2. Optionally compress a directory into a single archive.
  3. Compute local MD5 / SHA-256 hashes (chain of custody).
  4. Upload the evidence to the backend over HTTPS, authenticated with an
     API key.
  5. Poll the job status and show a live progress bar in the terminal.
  6. Optionally download the finished PDF report.

Cross-platform
--------------
The agent is pure Python and depends only on ``click``, ``requests`` and
``tqdm`` — all of which are maintained and ship wheels for both macOS and
Windows, so a single codebase works on both.

Usage
-----
    python forensic_agent.py upload PATH [options]
    python forensic_agent.py status CASE_ID
    python forensic_agent.py report CASE_ID --output report.pdf
    python forensic_agent.py watch CASE_ID

Environment variables
---------------------
    FORENSIC_API_URL      Backend URL                (default: http://localhost:8000)
    FORENSIC_API_KEY      Agent API key              (required for upload)
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import time
import zipfile
from pathlib import Path
from typing import Optional, Tuple

# Local scanner module (sits next to this file). Imported lazily inside the
# scan command to keep other subcommands usable even if scanner.py is absent.
try:
    from . import scanner as _scanner_pkg  # when installed as a package
except ImportError:
    _scanner_pkg = None

try:
    import click
    import requests
    from tqdm import tqdm
except ImportError as e:  # pragma: no cover
    sys.stderr.write(
        f"Missing dependency: {e}\n"
        "Install agent dependencies first:\n"
        "    pip install -r agent/requirements.txt\n"
    )
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Configuration helpers
# ─────────────────────────────────────────────────────────────────────────────


DEFAULT_API_URL = "http://localhost:8000"
CHUNK_SIZE = 1024 * 1024  # 1 MiB


def _api_url(override: Optional[str]) -> str:
    url = (override or os.getenv("FORENSIC_API_URL") or DEFAULT_API_URL).rstrip("/")
    return url


def _api_key(override: Optional[str]) -> str:
    key = override or os.getenv("FORENSIC_API_KEY") or ""
    if not key:
        raise click.ClickException(
            "No API key supplied. Pass --api-key or set FORENSIC_API_KEY "
            "(the server's AGENT_API_KEY)."
        )
    return key


def _headers(key: str) -> dict:
    return {
        "X-API-Key": key,
        "User-Agent": f"forensic-agent/1.0 ({platform.system()}-{platform.machine()})",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Local-side prep: archive directories, compute hashes
# ─────────────────────────────────────────────────────────────────────────────


def _hash_file(path: Path) -> Tuple[str, str, int]:
    """Return (md5, sha256, size). Streams the file so huge images are fine."""
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    size = 0
    with path.open("rb") as f, tqdm(
        total=path.stat().st_size,
        unit="B",
        unit_scale=True,
        desc="Hashing",
        leave=False,
    ) as bar:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            md5.update(chunk)
            sha.update(chunk)
            size += len(chunk)
            bar.update(len(chunk))
    return md5.hexdigest(), sha.hexdigest(), size


def _archive_directory(directory: Path, compress: bool) -> Path:
    """
    Pack a directory into a single .zip next to it.

    Compression mode depends on `compress`: DEFLATE if True (slower, smaller),
    STORED otherwise (fast, binary-identical files — useful when evidence is
    already compressed media).
    """
    out = directory.with_suffix(".zip")
    mode = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    click.echo(f"Packaging {directory} → {out.name} …")

    all_files = [p for p in directory.rglob("*") if p.is_file()]
    with zipfile.ZipFile(out, "w", mode) as zf, tqdm(
        total=len(all_files), desc="Archiving", unit="file", leave=False,
    ) as bar:
        for f in all_files:
            zf.write(f, arcname=f.relative_to(directory.parent))
            bar.update(1)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Upload with progress bar
# ─────────────────────────────────────────────────────────────────────────────


class _ProgressReader:
    """
    Wraps a file so requests' multipart encoder streams data while tqdm tracks
    progress. Required because requests reads the whole BufferedIOBase at once
    otherwise, which hides the upload from the user.
    """

    def __init__(self, fh, total: int, desc: str):
        self._fh = fh
        self._bar = tqdm(total=total, unit="B", unit_scale=True, desc=desc)

    def read(self, size: int = -1) -> bytes:
        chunk = self._fh.read(size)
        if chunk:
            self._bar.update(len(chunk))
        return chunk

    def close(self) -> None:
        self._bar.close()
        self._fh.close()

    # Requests checks for `len(body)` and `body.seek/tell` in some paths —
    # forward these to the underlying file.
    def __len__(self) -> int:
        return self._bar.total

    def seek(self, *a, **kw):
        return self._fh.seek(*a, **kw)

    def tell(self):
        return self._fh.tell()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version="1.0.0", prog_name="forensic-agent")
def cli() -> None:
    """Forensic Platform agent — upload evidence, track jobs, download reports."""


@cli.command("upload")
@click.argument(
    "path",
    type=click.Path(exists=True, dir_okay=True, file_okay=True, path_type=Path),
)
@click.option("--api-url", default=None, help="Backend URL (env: FORENSIC_API_URL).")
@click.option("--api-key", default=None, help="Agent API key (env: FORENSIC_API_KEY).")
@click.option(
    "--keywords",
    default="password,login,bitcoin,admin,secret,gmail,exe,pdf",
    help="Comma-separated keywords to search for.",
)
@click.option(
    "--investigator",
    default=None,
    help="Investigator name recorded on the case (default: OS username).",
)
@click.option(
    "--compress/--no-compress",
    default=True,
    help="When PATH is a directory, compress the archive (default: on).",
)
@click.option(
    "--no-hash",
    is_flag=True,
    default=False,
    help="Skip the local pre-upload hash (faster for huge images).",
)
@click.option(
    "--watch",
    is_flag=True,
    default=False,
    help="After upload, poll job status until it completes.",
)
@click.option(
    "--download-report",
    "download_report",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Save the PDF report to this path after completion (implies --watch).",
)
def upload(
    path: Path,
    api_url: Optional[str],
    api_key: Optional[str],
    keywords: str,
    investigator: Optional[str],
    compress: bool,
    no_hash: bool,
    watch: bool,
    download_report: Optional[Path],
) -> None:
    """Upload a disk image or directory to the forensic backend for analysis."""
    base_url = _api_url(api_url)
    key = _api_key(api_key)
    investigator = investigator or os.environ.get("USER") or os.environ.get("USERNAME") or "agent"

    # ── Prepare the artefact we'll upload ────────────────────────────────────
    evidence_path: Path
    cleanup_after: Optional[Path] = None
    if path.is_dir():
        evidence_path = _archive_directory(path, compress=compress)
        cleanup_after = evidence_path
    else:
        evidence_path = path

    size = evidence_path.stat().st_size
    click.echo(f"Evidence: {evidence_path} ({_human(size)})")

    if not no_hash:
        md5, sha, _ = _hash_file(evidence_path)
        click.echo(f"  MD5   : {md5}")
        click.echo(f"  SHA256: {sha}")

    # ── Upload with streaming progress ───────────────────────────────────────
    url = f"{base_url}/api/agent/upload"
    click.echo(f"Uploading to {url} …")

    reader = _ProgressReader(open(evidence_path, "rb"), total=size, desc="Upload")
    try:
        files = {"evidence": (evidence_path.name, reader, "application/octet-stream")}
        data = {"keywords": keywords, "investigator": investigator}
        resp = requests.post(url, headers=_headers(key), files=files, data=data, timeout=None)
    finally:
        reader.close()
        if cleanup_after is not None and cleanup_after.exists():
            try:
                cleanup_after.unlink()
            except OSError:
                pass

    if resp.status_code >= 400:
        raise click.ClickException(
            f"Upload failed ({resp.status_code}): {resp.text}"
        )

    payload = resp.json()
    case_id = payload.get("case_id") or payload.get("job_id")
    click.secho(f"✓ Uploaded. Case ID: {case_id}", fg="green")
    click.echo(f"  Status URL : {base_url}{payload.get('status_url')}")
    click.echo(f"  Results    : {base_url}{payload.get('results_url')}")
    click.echo(f"  PDF Report : {base_url}{payload.get('pdf_url')}")

    if watch or download_report:
        _watch(base_url, case_id, key)

    if download_report:
        _download_pdf(base_url, case_id, download_report)


@cli.command("scan")
@click.argument(
    "path",
    type=click.Path(exists=True, dir_okay=True, file_okay=True, path_type=Path),
)
@click.option("--api-url", default=None, help="Backend URL (env: FORENSIC_API_URL).")
@click.option("--api-key", default=None, help="Agent API key (env: FORENSIC_API_KEY).")
@click.option(
    "--investigator",
    default=None,
    help="Investigator name recorded on the case (default: OS username).",
)
@click.option(
    "--keywords",
    default="password,login,bitcoin,admin,secret,gmail,token,api_key",
    help="Comma-separated keywords to flag in text previews.",
)
@click.option(
    "--output-json",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Also write the raw findings JSON to this path (for debugging / chain of custody).",
)
@click.option(
    "--include-rar/--skip-rar",
    default=None,
    help=(
        "Force include or skip .rar archives. Default: prompt interactively when "
        "any .rar files are found."
    ),
)
@click.option(
    "--upload-images/--no-upload-images",
    default=False,
    help=(
        "If any disk images (.dd .e01 .iso ...) are found, also upload them to "
        "the backend for Sleuth Kit analysis. Default: off — only metadata is sent."
    ),
)
@click.option(
    "--watch",
    is_flag=True,
    default=False,
    help="Poll the case status after submission.",
)
@click.option(
    "--download-report",
    "download_report",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Save the PDF report locally after completion (implies --watch).",
)
def scan(
    path: Path,
    api_url: Optional[str],
    api_key: Optional[str],
    investigator: Optional[str],
    keywords: str,
    output_json: Optional[Path],
    include_rar: Optional[bool],
    upload_images: bool,
    watch: bool,
    download_report: Optional[Path],
) -> None:
    """
    Scan a folder (or file) locally and send findings to the backend.

    Unlike `upload`, this command does **not** ship raw evidence over the wire
    by default. It walks the path, hashes every file, extracts EXIF from
    images, text from PDF/DOCX/TXT, and lists archive contents, then POSTs a
    compact JSON findings package to the backend. The backend creates a new
    case and generates the PDF report from these findings.

    Disk images (`.dd`, `.e01`, `.iso`, etc.) can only be analysed server-side
    because Sleuth Kit tools need root; use `--upload-images` to also upload
    them, or run `forensic-agent upload <disk.dd>` separately.
    """
    # ── Import the scanner lazily so bad installs don't break other commands ─
    scanner = _scanner_pkg
    if scanner is None:
        try:
            import scanner as _sc  # type: ignore
            scanner = _sc
        except ImportError as e:
            raise click.ClickException(
                f"scanner module not importable: {e}. Re-install the agent: "
                "pip install -e ."
            )

    base_url = _api_url(api_url)
    key = _api_key(api_key)
    investigator = investigator or os.environ.get("USER") or os.environ.get("USERNAME") or "agent"

    # ── Interactive RAR decision, unless overridden ─────────────────────────
    def _rar_callback(rar_path: Path, count: int) -> bool:
        if include_rar is not None:
            return include_rar
        click.secho(
            f"\n⚠  Found {count} .rar archive(s) (e.g. {rar_path.name}).",
            fg="yellow",
        )
        click.echo(
            "   Reading RAR contents requires the `unrar` (or `unar`) binary on PATH\n"
            "   and the `rarfile` Python package. Without them, RAR entries will be\n"
            "   listed by name/size only with a note explaining why."
        )
        if sys.platform == "darwin":
            click.echo("   Install on macOS:   brew install rar")
        elif sys.platform.startswith("win"):
            click.echo("   Install on Windows: download UnRAR from https://www.rarlab.com/ and add to PATH")
        else:
            click.echo("   Install on Linux:   sudo apt install unrar  (or: unar)")
        return click.confirm(
            "   Attempt to include .rar contents now?",
            default=False,
        )

    # ── Run the scan with a progress bar ────────────────────────────────────
    click.secho(f"Scanning {path} …", fg="cyan")
    bar = {"pbar": None}

    def _progress(done: int, total: int) -> None:
        if bar["pbar"] is None:
            bar["pbar"] = tqdm(total=total, unit="file", desc="Scan")
        bar["pbar"].update(done - bar["pbar"].n)
        if done >= total:
            bar["pbar"].close()

    findings = scanner.scan(path, rar_decision=_rar_callback, on_progress=_progress)
    findings["investigator"] = investigator
    findings["keywords"] = [k.strip() for k in keywords.split(",") if k.strip()]

    summary = findings.get("summary", {})
    by_type = summary.get("by_type", {})
    click.echo("")
    click.secho("── Scan summary ─────────────────────────────", fg="cyan")
    click.echo(f"  Files   : {summary.get('total_files', 0):>6}")
    click.echo(f"  Size    : {_human(summary.get('total_size_bytes', 0))}")
    click.echo(f"  Types   : {', '.join(f'{k}={v}' for k, v in by_type.items()) or '-'}")
    click.echo(f"  EXIF    : {summary.get('with_exif', 0)}")
    click.echo(f"  Text    : {summary.get('with_text', 0)}")
    click.echo(f"  Errors  : {len(findings.get('errors', []))}")
    if summary.get("truncated"):
        click.secho(f"  ⚠  Truncated at {scanner.MAX_FILES} files — consider scanning a smaller root.", fg="yellow")

    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
        click.echo(f"  Findings JSON written to {output_json}")

    # ── Send findings to backend ────────────────────────────────────────────
    url = f"{base_url}/api/agent/findings"
    click.echo(f"\nSubmitting findings to {url} …")
    try:
        resp = requests.post(
            url,
            headers={**_headers(key), "Content-Type": "application/json"},
            data=json.dumps(findings, default=str),
            timeout=120,
        )
    except requests.RequestException as e:
        raise click.ClickException(f"Network error contacting backend: {e}")

    if resp.status_code >= 400:
        raise click.ClickException(
            f"Submission failed ({resp.status_code}): {resp.text[:500]}"
        )
    payload = resp.json()
    case_id = payload.get("case_id")
    click.secho(f"✓ Findings submitted. Case ID: {case_id}", fg="green")
    click.echo(f"  Results    : {base_url}{payload.get('results_url', '/results/' + case_id)}")
    click.echo(f"  Timeline   : {base_url}{payload.get('timeline_url', '/timeline/' + case_id)}")
    click.echo(f"  PDF Report : {base_url}{payload.get('pdf_url', '/report/' + case_id)}")

    # ── Optionally upload disk images for Sleuth Kit processing ─────────────
    disk_imgs = findings.get("images_to_upload", [])
    if disk_imgs and upload_images:
        click.secho(
            f"\nUploading {len(disk_imgs)} disk image(s) for server-side TSK analysis …",
            fg="cyan",
        )
        for img in disk_imgs:
            img_path = Path(img)
            if not img_path.exists():
                click.secho(f"  skipped (missing): {img}", fg="yellow")
                continue
            _upload_one(img_path, base_url, key, keywords, investigator)
    elif disk_imgs:
        click.secho(
            f"\nℹ  Found {len(disk_imgs)} disk image(s). Re-run with --upload-images "
            "to also upload them for Sleuth Kit analysis, or use `forensic-agent upload`:",
            fg="yellow",
        )
        for img in disk_imgs[:5]:
            click.echo(f"     {img}")
        if len(disk_imgs) > 5:
            click.echo(f"     ... and {len(disk_imgs) - 5} more")

    if watch or download_report:
        _watch(base_url, case_id, key)
    if download_report:
        _download_pdf(base_url, case_id, download_report)


def _upload_one(
    path: Path, base_url: str, key: str, keywords: str, investigator: str
) -> None:
    """Small helper that POSTs a single file to /api/agent/upload."""
    size = path.stat().st_size
    reader = _ProgressReader(open(path, "rb"), total=size, desc=f"Upload {path.name}")
    try:
        resp = requests.post(
            f"{base_url}/api/agent/upload",
            headers=_headers(key),
            files={"evidence": (path.name, reader, "application/octet-stream")},
            data={"keywords": keywords, "investigator": investigator},
            timeout=None,
        )
    finally:
        reader.close()
    if resp.status_code >= 400:
        click.secho(f"  ✗ {path.name}: {resp.status_code} {resp.text[:200]}", fg="red")
        return
    cid = resp.json().get("case_id")
    click.secho(f"  ✓ {path.name} → case {cid}", fg="green")


@cli.command("status")
@click.argument("case_id")
@click.option("--api-url", default=None)
@click.option("--api-key", default=None)
def status(case_id: str, api_url: Optional[str], api_key: Optional[str]) -> None:
    """Print the current status of a case (exits non-zero on failure)."""
    base_url = _api_url(api_url)
    headers = _headers(_api_key(api_key)) if os.getenv("FORENSIC_API_KEY") else {}
    resp = requests.get(f"{base_url}/api/status/{case_id}", headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    click.echo(f"Case {case_id}: {data.get('status')} ({data.get('progress')}%)")
    for line in (data.get("log") or [])[-10:]:
        click.echo(f"  {line}")
    if data.get("status") == "failed":
        sys.exit(1)


@cli.command("watch")
@click.argument("case_id")
@click.option("--api-url", default=None)
@click.option("--api-key", default=None)
def watch(case_id: str, api_url: Optional[str], api_key: Optional[str]) -> None:
    """Poll a case until it reaches a terminal state."""
    _watch(_api_url(api_url), case_id, _api_key(api_key) if os.getenv("FORENSIC_API_KEY") else "")


@cli.command("report")
@click.argument("case_id")
@click.option(
    "--output", "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Output path (default: ./forensic_report_<case>.pdf).",
)
@click.option("--api-url", default=None)
def report(case_id: str, output: Optional[Path], api_url: Optional[str]) -> None:
    """Download the PDF forensic report for a completed case."""
    base_url = _api_url(api_url)
    out = output or Path.cwd() / f"forensic_report_{case_id}.pdf"
    _download_pdf(base_url, case_id, out)


@cli.command("health")
@click.option("--api-url", default=None)
def health(api_url: Optional[str]) -> None:
    """Check the backend is reachable and list available tools."""
    base_url = _api_url(api_url)
    resp = requests.get(f"{base_url}/api/health", timeout=10)
    resp.raise_for_status()
    click.echo(resp.text)


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers for watch/report/download
# ─────────────────────────────────────────────────────────────────────────────


def _watch(base_url: str, case_id: str, key: str) -> None:
    """Poll `/api/status/<id>` until a terminal state, rendering a live bar."""
    url = f"{base_url}/api/status/{case_id}"
    headers = _headers(key) if key else {}
    last_progress = -1
    last_log_len = 0
    with tqdm(total=100, desc=f"Case {case_id}", unit="%") as bar:
        while True:
            try:
                resp = requests.get(url, headers=headers, timeout=30)
                resp.raise_for_status()
            except requests.RequestException as e:
                click.secho(f"[poll] {e} — retrying in 3s", fg="yellow")
                time.sleep(3)
                continue

            data = resp.json()
            progress = int(data.get("progress") or 0)
            status_v = data.get("status")
            if progress != last_progress:
                bar.update(progress - last_progress)
                last_progress = progress

            log_lines = data.get("log") or []
            for line in log_lines[last_log_len:]:
                tqdm.write(f"  {line}")
            last_log_len = len(log_lines)

            if status_v in {"completed", "failed", "interrupted"}:
                bar.close()
                if status_v == "completed":
                    click.secho(f"✓ Case {case_id} complete.", fg="green")
                else:
                    click.secho(
                        f"✗ Case {case_id} {status_v}: {data.get('error', '')}",
                        fg="red",
                    )
                    sys.exit(2)
                return
            time.sleep(2)


def _download_pdf(base_url: str, case_id: str, out: Path) -> None:
    url = f"{base_url}/report/{case_id}"
    click.echo(f"Downloading PDF → {out}")
    with requests.get(url, stream=True, timeout=300) as resp:
        if resp.status_code >= 400:
            raise click.ClickException(
                f"Report download failed ({resp.status_code}): {resp.text}"
            )
        total = int(resp.headers.get("Content-Length", 0)) or None
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("wb") as f, tqdm(
            total=total, unit="B", unit_scale=True, desc="PDF", leave=False,
        ) as bar:
            for chunk in resp.iter_content(CHUNK_SIZE):
                if chunk:
                    f.write(chunk)
                    bar.update(len(chunk))
    click.secho(f"✓ Saved {out}", fg="green")


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


if __name__ == "__main__":
    cli()
