"""
pdf_report.py — Professional forensic PDF report generator.

Produces an investigator-ready PDF containing:
    * Cover page (case ID, evidence name, generation timestamp, investigator)
    * Chain-of-custody hash table (MD5, SHA-1, SHA-256)
    * Executive / AI summary
    * Evidence statistics
    * Disk partition & filesystem section (when applicable)
    * File listings (all + deleted, with sensible truncation)
    * Forensic timeline highlights
    * Keyword-search findings
    * Footer on every page with page numbers and confidentiality notice

Implementation notes
--------------------
* We use reportlab's **platypus** (high-level Flowables) rather than the
  canvas API — it handles page breaks and tables automatically.
* Long tables are truncated to a configurable cap so a PDF for a 2 TB image
  doesn't balloon to hundreds of pages. A line like
  "... (N more rows omitted)" is appended so the investigator knows.
* The generator is defensive: every section try/except-guards missing data so
  a partial analysis still produces a valid (if smaller) PDF.

Public API
----------
    generate_pdf_report(
        case_id, evidence_name, evidence_type, hashes,
        disk_results, artifacts, timeline, search_results,
        ai_summary, output_path,
        investigator="Unknown", created_at=None,
    ) -> Path
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)

# ─────────────────────────────────────────────────────────────────────────────
# Palette — kept muted/professional, not flashy.
# ─────────────────────────────────────────────────────────────────────────────

NAVY = colors.HexColor("#0b2447")
STEEL = colors.HexColor("#19376d")
ACCENT = colors.HexColor("#576cbc")
MUTED = colors.HexColor("#8c8c8c")
DELETED = colors.HexColor("#a83232")
BG_HEAD = colors.HexColor("#1c2a4a")
BG_ROW = colors.HexColor("#f2f4fb")

# Cap oversized tables so the PDF remains readable.
MAX_FILES_IN_TABLE = 60
MAX_DELETED_IN_TABLE = 40
MAX_TIMELINE_ROWS = 80
MAX_BROWSER_ROWS = 40
MAX_SEARCH_HITS_PER_KW = 15


# ─────────────────────────────────────────────────────────────────────────────
# Paragraph / table style helpers.
# ─────────────────────────────────────────────────────────────────────────────


def _build_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    styles = {
        "h1": ParagraphStyle(
            "H1", parent=base["Heading1"], fontName="Helvetica-Bold",
            fontSize=22, leading=26, textColor=NAVY, spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "H2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=14, leading=18, textColor=STEEL,
            spaceBefore=14, spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "H3", parent=base["Heading3"], fontName="Helvetica-Bold",
            fontSize=11, leading=14, textColor=ACCENT,
            spaceBefore=8, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "Body", parent=base["BodyText"], fontName="Helvetica",
            fontSize=9.5, leading=13, alignment=TA_JUSTIFY, textColor=colors.black,
        ),
        "mono": ParagraphStyle(
            "Mono", parent=base["BodyText"], fontName="Courier",
            fontSize=8.5, leading=11, textColor=colors.black,
        ),
        "cover_title": ParagraphStyle(
            "CoverTitle", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=28, leading=32, textColor=NAVY, alignment=TA_CENTER,
            spaceAfter=12,
        ),
        "cover_sub": ParagraphStyle(
            "CoverSub", parent=base["BodyText"], fontName="Helvetica",
            fontSize=13, leading=18, textColor=STEEL, alignment=TA_CENTER,
            spaceAfter=6,
        ),
        "caption": ParagraphStyle(
            "Caption", parent=base["BodyText"], fontName="Helvetica-Oblique",
            fontSize=8, leading=10, textColor=MUTED,
        ),
    }
    return styles


def _default_table_style(header_bg=BG_HEAD) -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ALIGN", (0, 0), (-1, 0), "LEFT"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 7),
        ("TOPPADDING", (0, 0), (-1, 0), 7),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.black),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_ROW]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c5cbd6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ])


def _truncate(text: Any, width: int) -> str:
    s = "" if text is None else str(text)
    return s if len(s) <= width else s[: width - 1] + "…"


# ─────────────────────────────────────────────────────────────────────────────
# Document template with running header/footer.
# ─────────────────────────────────────────────────────────────────────────────


class _ForensicDocTemplate(BaseDocTemplate):
    """BaseDocTemplate subclass that paints a footer on every page."""

    def __init__(self, filename: str, case_id: str, **kw):
        super().__init__(
            filename,
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
            title=f"Forensic Report — Case {case_id}",
            author="Digital Forensics Investigation Platform",
            **kw,
        )
        self.case_id = case_id

        frame = Frame(
            self.leftMargin, self.bottomMargin,
            self.width, self.height,
            id="main",
        )
        self.addPageTemplates([
            PageTemplate(id="Report", frames=[frame], onPage=self._draw_footer),
        ])

    def _draw_footer(self, canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        footer_text = (
            f"Case {self.case_id}   •   "
            f"Digital Forensics Investigation Platform   •   "
            f"CONFIDENTIAL"
        )
        canvas.drawString(2 * cm, 1.2 * cm, footer_text)
        canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Page {_doc.page}")
        # Thin rule above the footer
        canvas.setStrokeColor(MUTED)
        canvas.setLineWidth(0.3)
        canvas.line(2 * cm, 1.55 * cm, A4[0] - 2 * cm, 1.55 * cm)
        canvas.restoreState()


# ─────────────────────────────────────────────────────────────────────────────
# Section builders — each returns a list of Flowables.
# ─────────────────────────────────────────────────────────────────────────────


def _cover_section(
    styles, case_id, evidence_name, evidence_type, created_at, investigator
) -> List[Any]:
    story: List[Any] = []
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("Digital Forensics Report", styles["cover_title"]))
    story.append(Paragraph(
        "Confidential — Chain-of-Custody Document",
        styles["cover_sub"],
    ))
    story.append(Spacer(1, 2.2 * cm))

    tbl = Table(
        [
            ["Case ID", case_id],
            ["Evidence", evidence_name or "—"],
            ["Evidence Type", (evidence_type or "unknown").upper()],
            ["Investigator", investigator or "—"],
            ["Report Generated", created_at],
        ],
        colWidths=[5 * cm, 11 * cm],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), NAVY),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.whitesmoke),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c5cbd6")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph(
        "This document was produced by an automated forensic analysis pipeline "
        "using The Sleuth Kit and supporting tooling. All findings should be "
        "reviewed by a qualified investigator prior to legal use.",
        styles["caption"],
    ))
    story.append(PageBreak())
    return story


def _hashes_section(styles, hashes: Dict[str, Any]) -> List[Any]:
    story = [Paragraph("1. Chain of Custody — Evidence Hashes", styles["h2"])]
    story.append(Paragraph(
        "Cryptographic digests computed over the raw evidence at ingest. "
        "These values authenticate the evidence: any subsequent modification "
        "will produce different digests.",
        styles["body"],
    ))
    story.append(Spacer(1, 4 * mm))

    rows = [["Algorithm", "Digest"]]
    for algo in ("md5", "sha1", "sha256"):
        if hashes.get(algo):
            rows.append([algo.upper(), hashes[algo]])
    rows.append(["File Name", hashes.get("file_name", "—")])
    rows.append(["File Size", hashes.get("file_size_human", str(hashes.get("file_size", "—")))])

    tbl = Table(rows, colWidths=[3.5 * cm, 13 * cm])
    style = _default_table_style()
    # Monospace the digests
    style.add("FONTNAME", (1, 1), (1, 3), "Courier")
    style.add("FONTSIZE", (1, 1), (1, 3), 8)
    tbl.setStyle(style)
    story.append(tbl)
    return story


def _summary_section(styles, ai_summary: str) -> List[Any]:
    if not ai_summary:
        return []
    story = [Paragraph("2. Executive Summary", styles["h2"])]
    # Split on blank lines so markdown-ish bullets render reasonably.
    for block in str(ai_summary).split("\n\n"):
        block = block.strip()
        if not block:
            continue
        # Very light markdown handling: "## " → h3, "- " → indented bullet
        if block.startswith("## "):
            story.append(Paragraph(block[3:].strip(), styles["h3"]))
        elif block.startswith("**") and block.endswith("**"):
            story.append(Paragraph(
                f"<b>{block.strip('*')}</b>", styles["body"],
            ))
        else:
            # Convert very simple "- item" bullet lines.
            html = block.replace("\n- ", "<br/>&bull; ")
            if html.startswith("- "):
                html = "&bull; " + html[2:]
            html = html.replace("**", "")
            story.append(Paragraph(html, styles["body"]))
        story.append(Spacer(1, 2 * mm))
    return story


def _stats_section(
    styles, artifacts: Dict[str, Any], disk_results: Dict[str, Any], recovered_count: int,
) -> List[Any]:
    multimedia = artifacts.get("multimedia", []) or []
    images = [m for m in multimedia if m.get("type") == "image"]
    videos = [m for m in multimedia if m.get("type") == "video"]
    docs = artifacts.get("documents", []) or []
    browser = artifacts.get("browser_history", []) or []
    metadata = artifacts.get("metadata", []) or []
    deleted = disk_results.get("deleted_files", []) or []
    partitions = disk_results.get("partitions", []) or []

    rows = [
        ["Metric", "Count"],
        ["Total recovered files", recovered_count],
        ["Deleted files detected", len(deleted)],
        ["Image files", len(images)],
        ["Video files", len(videos)],
        ["Document files", len(docs)],
        ["Browser history entries", len(browser)],
        ["Files with metadata", len(metadata)],
        ["Disk partitions", len(partitions)],
    ]
    tbl = Table(rows, colWidths=[10 * cm, 6.5 * cm])
    tbl.setStyle(_default_table_style())

    return [
        Paragraph("3. Evidence Statistics", styles["h2"]),
        Paragraph(
            "Top-line counts across the forensic pipeline. See the detailed "
            "sections below for file-level breakdowns.",
            styles["body"],
        ),
        Spacer(1, 4 * mm),
        tbl,
    ]


def _partitions_section(styles, disk_results: Dict[str, Any]) -> List[Any]:
    partitions = disk_results.get("partitions", []) or []
    if not partitions:
        return []

    rows = [["#", "Start", "Length", "Type", "Description"]]
    for p in partitions:
        rows.append([
            _truncate(p.get("slot") or p.get("index"), 6),
            _truncate(p.get("start"), 12),
            _truncate(p.get("length"), 14),
            _truncate(p.get("type") or p.get("fstype"), 20),
            _truncate(p.get("description"), 40),
        ])
    tbl = Table(rows, colWidths=[1 * cm, 3 * cm, 3 * cm, 4 * cm, 5.5 * cm])
    tbl.setStyle(_default_table_style())

    fsstat = disk_results.get("fsstat_summary") or disk_results.get("filesystem", {})
    story = [
        Paragraph("4. Disk Image — Partitions &amp; Filesystem", styles["h2"]),
        Paragraph(
            "Partition map recovered via <b>mmls</b>. File-system details "
            "were extracted with <b>fsstat</b>.",
            styles["body"],
        ),
        Spacer(1, 4 * mm),
        tbl,
    ]
    if isinstance(fsstat, dict) and fsstat:
        fs_rows = [["Property", "Value"]]
        for k, v in list(fsstat.items())[:12]:
            fs_rows.append([_truncate(k, 28), _truncate(v, 60)])
        fs_tbl = Table(fs_rows, colWidths=[5 * cm, 11.5 * cm])
        fs_tbl.setStyle(_default_table_style())
        story += [Spacer(1, 4 * mm), Paragraph("Filesystem details", styles["h3"]), fs_tbl]
    return story


def _files_section(
    styles, disk_results: Dict[str, Any], artifacts: Dict[str, Any], recovered_count: int,
) -> List[Any]:
    files = (
        disk_results.get("all_files")
        or disk_results.get("files")
        or artifacts.get("files")
        or []
    )
    if not files:
        return [
            Paragraph("5. File Listing", styles["h2"]),
            Paragraph(
                f"{recovered_count} files were recovered; a detailed per-file "
                "listing was not produced by this analysis run.",
                styles["body"],
            ),
        ]

    rows = [["Inode", "Name", "Size", "Modified"]]
    for f in files[:MAX_FILES_IN_TABLE]:
        rows.append([
            _truncate(f.get("inode") or f.get("meta_addr"), 12),
            _truncate(f.get("name") or f.get("path"), 55),
            _truncate(f.get("size") or f.get("size_human"), 12),
            _truncate(f.get("modified") or f.get("mtime"), 22),
        ])
    tbl = Table(rows, colWidths=[2.5 * cm, 8 * cm, 2.5 * cm, 3.5 * cm])
    tbl.setStyle(_default_table_style())

    story = [
        Paragraph("5. File Listing", styles["h2"]),
        Paragraph(
            f"Files identified by <b>fls</b> / <b>tsk_recover</b>. "
            f"Showing {min(len(files), MAX_FILES_IN_TABLE)} of {len(files)} entries.",
            styles["body"],
        ),
        Spacer(1, 4 * mm),
        tbl,
    ]
    if len(files) > MAX_FILES_IN_TABLE:
        story.append(Paragraph(
            f"… {len(files) - MAX_FILES_IN_TABLE} additional rows omitted for brevity.",
            styles["caption"],
        ))
    return story


def _deleted_section(styles, disk_results: Dict[str, Any]) -> List[Any]:
    deleted = disk_results.get("deleted_files", []) or []
    if not deleted:
        return []

    rows = [["Inode", "Name", "Size", "Deleted Time"]]
    for f in deleted[:MAX_DELETED_IN_TABLE]:
        rows.append([
            _truncate(f.get("inode") or f.get("meta_addr"), 12),
            _truncate(f.get("name") or f.get("path"), 55),
            _truncate(f.get("size") or f.get("size_human"), 12),
            _truncate(f.get("modified") or f.get("mtime"), 22),
        ])
    tbl = Table(rows, colWidths=[2.5 * cm, 8 * cm, 2.5 * cm, 3.5 * cm])
    style = _default_table_style(header_bg=DELETED)
    tbl.setStyle(style)

    story = [
        Paragraph("6. Deleted Files (High-Interest)", styles["h2"]),
        Paragraph(
            f"Files flagged as deleted by the file system. These often contain "
            f"significant forensic artifacts. Showing "
            f"{min(len(deleted), MAX_DELETED_IN_TABLE)} of {len(deleted)}.",
            styles["body"],
        ),
        Spacer(1, 4 * mm),
        tbl,
    ]
    if len(deleted) > MAX_DELETED_IN_TABLE:
        story.append(Paragraph(
            f"… {len(deleted) - MAX_DELETED_IN_TABLE} additional rows omitted.",
            styles["caption"],
        ))
    return story


def _timeline_section(styles, timeline: List[Dict[str, Any]]) -> List[Any]:
    if not timeline:
        return []
    rows = [["Timestamp", "Action", "File / Artifact"]]
    for ev in timeline[:MAX_TIMELINE_ROWS]:
        rows.append([
            _truncate(ev.get("timestamp") or ev.get("time"), 22),
            _truncate(ev.get("action") or ev.get("macb") or ev.get("event"), 18),
            _truncate(ev.get("file") or ev.get("path") or ev.get("name"), 70),
        ])
    tbl = Table(rows, colWidths=[3.5 * cm, 3 * cm, 10 * cm])
    tbl.setStyle(_default_table_style())

    story = [
        Paragraph("7. Forensic Timeline", styles["h2"]),
        Paragraph(
            "MAC-time events assembled from <b>fls -m</b> + <b>mactime</b> "
            f"(with filesystem-stat fallback). Showing {min(len(timeline), MAX_TIMELINE_ROWS)} "
            f"of {len(timeline)} events.",
            styles["body"],
        ),
        Spacer(1, 4 * mm),
        tbl,
    ]
    if len(timeline) > MAX_TIMELINE_ROWS:
        story.append(Paragraph(
            f"… {len(timeline) - MAX_TIMELINE_ROWS} additional events omitted.",
            styles["caption"],
        ))
    return story


def _browser_section(styles, artifacts: Dict[str, Any]) -> List[Any]:
    history = artifacts.get("browser_history", []) or []
    if not history:
        return []
    rows = [["Browser", "Visit Time", "Title", "URL"]]
    for h in history[:MAX_BROWSER_ROWS]:
        rows.append([
            _truncate(h.get("browser"), 10),
            _truncate(h.get("visit_time") or h.get("last_visit"), 20),
            _truncate(h.get("title"), 40),
            _truncate(h.get("url"), 65),
        ])
    tbl = Table(rows, colWidths=[1.8 * cm, 3 * cm, 5 * cm, 6.7 * cm])
    tbl.setStyle(_default_table_style())

    story = [
        Paragraph("8. Browser History Artifacts", styles["h2"]),
        Paragraph(
            "URLs and visit timestamps recovered from Chrome <i>History</i> and "
            "Firefox <i>places.sqlite</i> databases.",
            styles["body"],
        ),
        Spacer(1, 4 * mm),
        tbl,
    ]
    if len(history) > MAX_BROWSER_ROWS:
        story.append(Paragraph(
            f"… {len(history) - MAX_BROWSER_ROWS} additional entries omitted.",
            styles["caption"],
        ))
    return story


def _search_section(styles, search_results: Dict[str, List[Dict[str, Any]]]) -> List[Any]:
    if not search_results:
        return []
    story = [
        Paragraph("9. Keyword Search Findings", styles["h2"]),
        Paragraph(
            "Hits found by the keyword engine across filenames, text content, "
            "browser history, metadata and recovered SQLite databases.",
            styles["body"],
        ),
        Spacer(1, 3 * mm),
    ]
    any_hits = False
    for keyword, hits in search_results.items():
        if not hits:
            continue
        any_hits = True
        story.append(Paragraph(f"Keyword: <b>{keyword}</b> — {len(hits)} hits", styles["h3"]))
        rows = [["Source", "Context"]]
        for h in hits[:MAX_SEARCH_HITS_PER_KW]:
            rows.append([
                _truncate(h.get("source") or h.get("type"), 18),
                _truncate(h.get("context") or h.get("match") or h.get("path"), 85),
            ])
        tbl = Table(rows, colWidths=[3.5 * cm, 13 * cm])
        tbl.setStyle(_default_table_style())
        story.append(KeepTogether(tbl))
        if len(hits) > MAX_SEARCH_HITS_PER_KW:
            story.append(Paragraph(
                f"… {len(hits) - MAX_SEARCH_HITS_PER_KW} additional hits omitted.",
                styles["caption"],
            ))
        story.append(Spacer(1, 3 * mm))
    if not any_hits:
        story.append(Paragraph(
            "No matches found for any of the configured keywords.",
            styles["body"],
        ))
    return story


def _appendix_section(styles, case_id, evidence_type) -> List[Any]:
    return [
        Paragraph("Appendix — Methodology", styles["h2"]),
        Paragraph(
            "This report was generated automatically by the Digital Forensics "
            "Investigation Platform. The analysis pipeline executed the "
            "following stages, in order:",
            styles["body"],
        ),
        Spacer(1, 2 * mm),
        Paragraph(
            "&bull; Evidence-type detection (magic bytes + extension heuristics).<br/>"
            "&bull; Cryptographic hashing (MD5, SHA-1, SHA-256) for chain of custody.<br/>"
            "&bull; Disk analysis via The Sleuth Kit — <b>mmls</b>, <b>fsstat</b>, "
            "<b>fls</b>, <b>ils</b>, <b>tsk_recover</b>.<br/>"
            "&bull; Artifact extraction — browser history (Chrome/Firefox SQLite), "
            "EXIF metadata (exiftool), multimedia &amp; documents.<br/>"
            "&bull; Timeline construction via <b>fls -m</b> + <b>mactime</b> with a "
            "filesystem-timestamp fallback.<br/>"
            "&bull; Keyword search across filenames, textual content, metadata, "
            "SQLite and browser history.<br/>"
            "&bull; Narrative summarization (OpenAI GPT-4o-mini, with a local "
            "template fallback).",
            styles["body"],
        ),
        Spacer(1, 4 * mm),
        Paragraph(
            f"Case ID <b>{case_id}</b> analysed evidence of type "
            f"<b>{(evidence_type or 'unknown').upper()}</b>.",
            styles["body"],
        ),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point.
# ─────────────────────────────────────────────────────────────────────────────


def generate_pdf_report(
    case_id: str,
    evidence_name: str,
    evidence_type: str,
    hashes: Dict[str, Any],
    disk_results: Dict[str, Any],
    artifacts: Dict[str, Any],
    timeline: List[Dict[str, Any]],
    search_results: Dict[str, List[Dict[str, Any]]],
    ai_summary: str,
    output_path: str,
    investigator: str = "Digital Forensics Platform",
    created_at: Optional[str] = None,
    recovered_count: int = 0,
) -> Path:
    """
    Render the full forensic PDF report and return its Path.
    Never raises on missing pipeline data — every section is guarded.
    """
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    created_at = created_at or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    styles = _build_styles()

    doc = _ForensicDocTemplate(str(output), case_id=case_id)
    story: List[Any] = []

    # Cover
    story += _cover_section(
        styles, case_id, evidence_name, evidence_type, created_at, investigator,
    )

    # Body sections — each one is wrapped so a bug in one doesn't kill the PDF.
    for builder, args in [
        (_hashes_section,    (styles, hashes or {})),
        (_summary_section,   (styles, ai_summary or "")),
        (_stats_section,     (styles, artifacts or {}, disk_results or {}, recovered_count)),
        (_partitions_section,(styles, disk_results or {})),
        (_files_section,     (styles, disk_results or {}, artifacts or {}, recovered_count)),
        (_deleted_section,   (styles, disk_results or {})),
        (_timeline_section,  (styles, timeline or [])),
        (_browser_section,   (styles, artifacts or {})),
        (_search_section,    (styles, search_results or {})),
        (_appendix_section,  (styles, case_id, evidence_type)),
    ]:
        try:
            story += builder(*args)
        except Exception as e:  # never fail the whole PDF over one section
            story.append(Paragraph(
                f"<i>[section '{builder.__name__}' failed: {e}]</i>",
                styles["caption"],
            ))

    doc.build(story)
    return output
