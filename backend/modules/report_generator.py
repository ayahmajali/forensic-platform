"""
report_generator.py — Interactive HTML Report Generator
Generates professional forensic investigation reports.
"""

import os
import json
import html
import base64
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional


class ReportGenerator:
    """
    Generates interactive HTML forensic investigation reports.
    Includes: summary, partitions, files, multimedia preview, browser history, timeline, and search.
    """

    def __init__(self, job_id: str, evidence_name: str, evidence_type: str,
                 hashes: Dict, disk_results: Dict, artifacts: Dict,
                 timeline: List, search_results: Dict, ai_summary: str,
                 recovered_path: str, reports_dir: str):
        self.job_id = job_id
        self.evidence_name = evidence_name
        self.evidence_type = evidence_type
        self.hashes = hashes
        self.disk_results = disk_results
        self.artifacts = artifacts
        self.timeline = timeline
        self.search_results = search_results
        self.ai_summary = ai_summary
        self.recovered_path = Path(recovered_path)
        self.reports_dir = Path(reports_dir)

    def generate(self) -> Path:
        """Generate the full HTML report and return its path."""
        report_dir = self.reports_dir / self.job_id
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "report.html"

        html_content = self._build_html()

        with open(str(report_path), "w", encoding="utf-8") as f:
            f.write(html_content)

        return report_path

    def _safe(self, text) -> str:
        """HTML-escape a string."""
        return html.escape(str(text or ""))

    def _get_image_b64(self, img_path: str) -> str:
        """Convert image to base64 for inline embedding."""
        try:
            if os.path.getsize(img_path) > 2 * 1024 * 1024:  # Skip > 2MB
                return ""
            ext = Path(img_path).suffix.lower().lstrip(".")
            mime_map = {"jpg": "jpeg", "jpeg": "jpeg", "png": "png", "gif": "gif"}
            mime = mime_map.get(ext, "jpeg")
            with open(img_path, "rb") as f:
                data = base64.b64encode(f.read()).decode("utf-8")
            return f"data:image/{mime};base64,{data}"
        except Exception:
            return ""

    def _md_to_html(self, md_text: str) -> str:
        """Convert basic markdown to HTML."""
        import re
        text = self._safe(md_text)
        # Headers
        text = re.sub(r'###\s+(.*)', r'<h3>\1</h3>', text)
        text = re.sub(r'##\s+(.*)', r'<h2>\1</h2>', text)
        text = re.sub(r'#\s+(.*)', r'<h1>\1</h1>', text)
        # Bold
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
        # Code inline
        text = re.sub(r'`(.*?)`', r'<code>\1</code>', text)
        # Table rows (basic)
        text = re.sub(r'\|(.*?)\|(.*?)\|', r'<tr><td>\1</td><td>\2</td></tr>', text)
        # Bullet points
        lines = text.split('\n')
        new_lines = []
        in_list = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('- ') or stripped.startswith('* '):
                if not in_list:
                    new_lines.append('<ul class="ai-list">')
                    in_list = True
                new_lines.append(f'<li>{stripped[2:]}</li>')
            else:
                if in_list:
                    new_lines.append('</ul>')
                    in_list = False
                if stripped:
                    new_lines.append(f'<p>{stripped}</p>')
                else:
                    new_lines.append('<br>')
        if in_list:
            new_lines.append('</ul>')
        return '\n'.join(new_lines)

    def _build_html(self) -> str:
        """Assemble the full HTML report."""
        browser_history = self.artifacts.get("browser_history", [])
        multimedia = self.artifacts.get("multimedia", [])
        images = [m for m in multimedia if m.get("type") == "image"]
        videos = [m for m in multimedia if m.get("type") == "video"]
        documents = self.artifacts.get("documents", [])
        metadata = self.artifacts.get("metadata", [])
        all_files = self.disk_results.get("all_files", [])
        deleted_files = self.disk_results.get("deleted_files", [])
        partitions = self.disk_results.get("partitions", [])
        fsstat = self.disk_results.get("fsstat", {})

        # Build sections
        partitions_html = self._build_partitions(partitions)
        fsstat_html = self._build_fsstat(fsstat)
        all_files_html = self._build_file_table(all_files, "All Files", "file-table")
        deleted_html = self._build_file_table(deleted_files, "Deleted Files", "deleted-table", deleted=True)
        multimedia_html = self._build_multimedia(images, videos)
        docs_html = self._build_documents(documents)
        browser_html = self._build_browser_history(browser_history)
        timeline_html = self._build_timeline()
        metadata_html = self._build_metadata(metadata)
        search_html = self._build_search_results()
        ai_html = self._md_to_html(self.ai_summary)
        sidebar_html = self._build_sidebar(all_files, deleted_files, images, videos, documents)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Forensic Report — {self._safe(self.evidence_name)}</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔍</text></svg>"/>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
<style>
{self._get_css()}
</style>
</head>
<body>
<!-- TOP NAV -->
<nav class="topnav">
  <div class="nav-brand">
    <i class="fas fa-search-plus"></i>
    <span>ForensicPlatform</span>
  </div>
  <div class="nav-info">
    <span class="badge badge-blue"><i class="fas fa-file-alt"></i> {self._safe(self.evidence_type.upper())}</span>
    <span class="badge badge-green"><i class="fas fa-check-circle"></i> Analysis Complete</span>
    <span class="nav-date"><i class="fas fa-clock"></i> {now}</span>
  </div>
</nav>

<div class="layout">
  <!-- SIDEBAR -->
  <aside class="sidebar" id="sidebar">
    <div class="sidebar-header">
      <i class="fas fa-folder-open"></i> Evidence Explorer
    </div>
    {sidebar_html}
  </aside>

  <!-- MAIN CONTENT -->
  <main class="main-content">
    
    <!-- SEARCH BAR -->
    <div class="search-bar-top">
      <div class="search-wrap">
        <i class="fas fa-search search-icon"></i>
        <input type="text" id="globalSearch" placeholder="Search evidence: keyword, .exe, @gmail.com, bitcoin..." 
               onkeydown="if(event.key==='Enter') runGlobalSearch()"/>
        <button onclick="runGlobalSearch()" class="btn-search">Search</button>
      </div>
      <div id="searchResults" class="search-results-inline" style="display:none"></div>
    </div>

    <!-- AI SUMMARY -->
    <section class="card ai-card" id="section-summary">
      <div class="card-header">
        <i class="fas fa-robot"></i> AI Investigation Summary
        <span class="badge badge-purple ml-auto">AI Generated</span>
      </div>
      <div class="card-body ai-summary-body">
        {ai_html}
      </div>
    </section>

    <!-- EVIDENCE INFO -->
    <section class="card" id="section-evidence">
      <div class="card-header"><i class="fas fa-info-circle"></i> Evidence Information</div>
      <div class="card-body">
        <div class="info-grid">
          <div class="info-item">
            <div class="info-label">File Name</div>
            <div class="info-value">{self._safe(self.evidence_name)}</div>
          </div>
          <div class="info-item">
            <div class="info-label">Evidence Type</div>
            <div class="info-value"><span class="badge badge-blue">{self._safe(self.evidence_type.upper())}</span></div>
          </div>
          <div class="info-item">
            <div class="info-label">File Size</div>
            <div class="info-value">{self._safe(self.hashes.get('file_size_human', 'N/A'))}</div>
          </div>
          <div class="info-item">
            <div class="info-label">Analysis Date</div>
            <div class="info-value">{now}</div>
          </div>
        </div>
        <div class="hash-grid mt-2">
          <div class="hash-item">
            <div class="hash-label"><i class="fas fa-hashtag"></i> MD5</div>
            <div class="hash-value">{self._safe(self.hashes.get('md5', 'N/A'))}</div>
          </div>
          <div class="hash-item">
            <div class="hash-label"><i class="fas fa-hashtag"></i> SHA-256</div>
            <div class="hash-value">{self._safe(self.hashes.get('sha256', 'N/A'))}</div>
          </div>
          <div class="hash-item">
            <div class="hash-label"><i class="fas fa-hashtag"></i> SHA-1</div>
            <div class="hash-value">{self._safe(self.hashes.get('sha1', 'N/A'))}</div>
          </div>
        </div>
      </div>
    </section>

    <!-- STATS CARDS -->
    <div class="stats-row">
      <div class="stat-card stat-blue">
        <div class="stat-icon"><i class="fas fa-files"></i></div>
        <div class="stat-num">{len(all_files)}</div>
        <div class="stat-label">Total Files</div>
      </div>
      <div class="stat-card stat-red">
        <div class="stat-icon"><i class="fas fa-trash"></i></div>
        <div class="stat-num">{len(deleted_files)}</div>
        <div class="stat-label">Deleted Files</div>
      </div>
      <div class="stat-card stat-green">
        <div class="stat-icon"><i class="fas fa-image"></i></div>
        <div class="stat-num">{len(images)}</div>
        <div class="stat-label">Images</div>
      </div>
      <div class="stat-card stat-orange">
        <div class="stat-icon"><i class="fas fa-video"></i></div>
        <div class="stat-num">{len(videos)}</div>
        <div class="stat-label">Videos</div>
      </div>
      <div class="stat-card stat-purple">
        <div class="stat-icon"><i class="fas fa-file-pdf"></i></div>
        <div class="stat-num">{len(documents)}</div>
        <div class="stat-label">Documents</div>
      </div>
      <div class="stat-card stat-teal">
        <div class="stat-icon"><i class="fas fa-globe"></i></div>
        <div class="stat-num">{len(browser_history)}</div>
        <div class="stat-label">Browser History</div>
      </div>
    </div>

    <!-- PARTITIONS -->
    <section class="card" id="section-partitions">
      <div class="card-header"><i class="fas fa-layer-group"></i> Disk Partitions
        <span class="badge badge-gray ml-auto">{len(partitions)} partitions</span>
      </div>
      <div class="card-body">{partitions_html}</div>
    </section>

    <!-- FILESYSTEM INFO -->
    <section class="card" id="section-filesystem">
      <div class="card-header"><i class="fas fa-hdd"></i> Filesystem Information</div>
      <div class="card-body">{fsstat_html}</div>
    </section>

    <!-- ALL FILES -->
    <section class="card" id="section-files">
      <div class="card-header">
        <i class="fas fa-folder"></i> All Files
        <span class="badge badge-gray ml-auto">{len(all_files)} entries</span>
        <input type="text" class="table-filter" placeholder="Filter files..." 
               onkeyup="filterTable(this, 'file-table')"/>
      </div>
      <div class="card-body">{all_files_html}</div>
    </section>

    <!-- DELETED FILES -->
    <section class="card" id="section-deleted">
      <div class="card-header">
        <i class="fas fa-trash-alt text-red"></i> Deleted Files
        <span class="badge badge-red ml-auto">{len(deleted_files)} deleted</span>
        <input type="text" class="table-filter" placeholder="Filter deleted..." 
               onkeyup="filterTable(this, 'deleted-table')"/>
      </div>
      <div class="card-body">{deleted_html}</div>
    </section>

    <!-- MULTIMEDIA -->
    <section class="card" id="section-multimedia">
      <div class="card-header"><i class="fas fa-photo-video"></i> Multimedia Evidence
        <span class="badge badge-green ml-auto">{len(images)} images, {len(videos)} videos</span>
      </div>
      <div class="card-body">{multimedia_html}</div>
    </section>

    <!-- DOCUMENTS -->
    <section class="card" id="section-documents">
      <div class="card-header"><i class="fas fa-file-alt"></i> Documents
        <span class="badge badge-orange ml-auto">{len(documents)} files</span>
      </div>
      <div class="card-body">{docs_html}</div>
    </section>

    <!-- BROWSER HISTORY -->
    <section class="card" id="section-browser">
      <div class="card-header">
        <i class="fas fa-globe"></i> Browser History
        <span class="badge badge-teal ml-auto">{len(browser_history)} entries</span>
        <input type="text" class="table-filter" placeholder="Filter URLs..." 
               onkeyup="filterTable(this, 'browser-table')"/>
      </div>
      <div class="card-body">{browser_html}</div>
    </section>

    <!-- METADATA -->
    <section class="card" id="section-metadata">
      <div class="card-header"><i class="fas fa-tags"></i> Image Metadata / EXIF
        <span class="badge badge-gray ml-auto">{len(metadata)} entries</span>
      </div>
      <div class="card-body">{metadata_html}</div>
    </section>

    <!-- TIMELINE -->
    <section class="card" id="section-timeline">
      <div class="card-header">
        <i class="fas fa-history"></i> Forensic Timeline
        <span class="badge badge-gray ml-auto">{len(self.timeline)} events</span>
        <input type="text" class="table-filter" placeholder="Filter timeline..." 
               onkeyup="filterTable(this, 'timeline-table')"/>
      </div>
      <div class="card-body">{timeline_html}</div>
    </section>

    <!-- KEYWORD SEARCH RESULTS -->
    <section class="card" id="section-search">
      <div class="card-header"><i class="fas fa-search"></i> Keyword Search Results</div>
      <div class="card-body">{search_html}</div>
    </section>

    <!-- FOOTER -->
    <footer class="report-footer">
      <i class="fas fa-shield-alt"></i>
      Digital Forensics Investigation Platform &nbsp;|&nbsp;
      Report ID: {self.job_id} &nbsp;|&nbsp;
      Generated: {now}
    </footer>
  </main>
</div>

<script>
{self._get_js()}
</script>
</body>
</html>"""

    # ──────────────────────────────────────────────────────────
    # Section Builders
    # ──────────────────────────────────────────────────────────

    def _build_sidebar(self, all_files, deleted_files, images, videos, documents) -> str:
        nav_items = [
            ("section-summary", "fas fa-robot", "AI Summary"),
            ("section-evidence", "fas fa-info-circle", "Evidence Info"),
            ("section-partitions", "fas fa-layer-group", f"Partitions ({len(self.disk_results.get('partitions',[]))})"),
            ("section-filesystem", "fas fa-hdd", "Filesystem"),
            ("section-files", "fas fa-folder", f"All Files ({len(all_files)})"),
            ("section-deleted", "fas fa-trash-alt", f"Deleted ({len(deleted_files)})"),
            ("section-multimedia", "fas fa-photo-video", f"Multimedia ({len(images)+len(videos)})"),
            ("section-documents", "fas fa-file-alt", f"Documents ({len(documents)})"),
            ("section-browser", "fas fa-globe", f"Browser History ({len(self.artifacts.get('browser_history', []))})"),
            ("section-metadata", "fas fa-tags", f"Metadata ({len(self.artifacts.get('metadata', []))})"),
            ("section-timeline", "fas fa-history", f"Timeline ({len(self.timeline)})"),
            ("section-search", "fas fa-search", "Search Results"),
        ]
        items = ""
        for section_id, icon, label in nav_items:
            items += f'<a href="#{section_id}" class="sidebar-item" onclick="scrollTo(\'{section_id}\')">'
            items += f'<i class="{icon}"></i><span>{label}</span></a>'
        return items

    def _build_partitions(self, partitions: List) -> str:
        if not partitions:
            return '<div class="empty-state"><i class="fas fa-info-circle"></i> No partition data (logical file or TSK unavailable)</div>'
        
        rows = ""
        for p in partitions:
            rows += f"""
            <tr>
              <td><span class="badge badge-blue">{self._safe(p.get('slot',''))}</span></td>
              <td>{self._safe(p.get('start',''))}</td>
              <td>{self._safe(p.get('end',''))}</td>
              <td>{self._safe(p.get('length',''))}</td>
              <td>{self._safe(p.get('offset',''))}</td>
              <td>{self._safe(p.get('description',''))}</td>
            </tr>"""
        
        return f"""
        <table class="data-table">
          <thead><tr>
            <th>Slot</th><th>Start</th><th>End</th><th>Length</th><th>Offset (bytes)</th><th>Description</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    def _build_fsstat(self, fsstat: Dict) -> str:
        if not fsstat or fsstat.get("fs_type") == "unknown":
            return f'<div class="code-block">{self._safe(fsstat.get("raw", "No filesystem data available"))}</div>'
        
        info_html = f"""
        <div class="info-grid">
          <div class="info-item"><div class="info-label">FS Type</div>
            <div class="info-value"><span class="badge badge-blue">{self._safe(fsstat.get('fs_type',''))}</span></div></div>
          <div class="info-item"><div class="info-label">Volume Name</div>
            <div class="info-value">{self._safe(fsstat.get('volume_name','N/A'))}</div></div>
          <div class="info-item"><div class="info-label">Block Size</div>
            <div class="info-value">{self._safe(fsstat.get('block_size','N/A'))}</div></div>
          <div class="info-item"><div class="info-label">Block Count</div>
            <div class="info-value">{self._safe(fsstat.get('block_count','N/A'))}</div></div>
        </div>
        <details class="raw-details">
          <summary>Raw fsstat output</summary>
          <pre class="code-block">{self._safe(fsstat.get('raw',''))[:3000]}</pre>
        </details>"""
        return info_html

    def _build_file_table(self, files: List, title: str, table_id: str, deleted: bool = False) -> str:
        if not files:
            return f'<div class="empty-state"><i class="fas fa-folder-open"></i> No {title.lower()} found</div>'
        
        rows = ""
        for f in files[:2000]:
            name = self._safe(f.get("name", ""))
            inode = self._safe(f.get("inode", ""))
            ftype = self._safe(f.get("type", ""))
            is_del = f.get("deleted", deleted)
            
            row_class = "deleted-row" if is_del else ""
            del_badge = '<span class="badge badge-red">DELETED</span>' if is_del else ""
            type_icon = "fa-folder text-yellow" if ftype == "directory" else "fa-file text-blue"
            
            rows += f"""<tr class="{row_class}">
              <td><i class="fas {type_icon}"></i> {ftype}</td>
              <td class="filename-cell">{name}</td>
              <td><code>{inode}</code></td>
              <td>{del_badge}</td>
            </tr>"""
        
        return f"""
        <div class="table-wrap">
        <table class="data-table" id="{table_id}">
          <thead><tr><th>Type</th><th>Name/Path</th><th>Inode</th><th>Status</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
        </div>"""

    def _build_multimedia(self, images: List, videos: List) -> str:
        if not images and not videos:
            return '<div class="empty-state"><i class="fas fa-photo-video"></i> No multimedia files found</div>'
        
        html_parts = []
        
        if images:
            html_parts.append('<h3 class="section-sub"><i class="fas fa-image"></i> Images</h3>')
            html_parts.append('<div class="media-grid">')
            for img in images[:50]:
                b64 = self._get_image_b64(img.get("path", ""))
                if b64:
                    src = b64
                else:
                    src = f"/recovered/{self.job_id}/{self._safe(img.get('relative_path',''))}"
                
                size = self._format_size(img.get("size", 0))
                html_parts.append(f"""
                <div class="media-card" onclick="openLightbox('{self._safe(img.get('filename',''))}', '{src}', 'image')">
                  <div class="media-thumb">
                    <img src="{src}" alt="{self._safe(img.get('filename',''))}" 
                         onerror="this.style.display='none';this.nextSibling.style.display='block'"/>
                    <div class="no-preview" style="display:none"><i class="fas fa-image"></i></div>
                  </div>
                  <div class="media-info">
                    <div class="media-name" title="{self._safe(img.get('filename',''))}">{self._safe(img.get('filename',''))[:25]}</div>
                    <div class="media-size">{size}</div>
                  </div>
                </div>""")
            html_parts.append('</div>')
        
        if videos:
            html_parts.append('<h3 class="section-sub mt-2"><i class="fas fa-video"></i> Videos</h3>')
            html_parts.append('<div class="media-grid">')
            for vid in videos[:20]:
                src = f"/recovered/{self.job_id}/{self._safe(vid.get('relative_path',''))}"
                size = self._format_size(vid.get("size", 0))
                html_parts.append(f"""
                <div class="media-card" onclick="openLightbox('{self._safe(vid.get('filename',''))}', '{src}', 'video')">
                  <div class="media-thumb video-thumb">
                    <i class="fas fa-play-circle"></i>
                    <div class="video-ext">{self._safe(vid.get('extension','').upper())}</div>
                  </div>
                  <div class="media-info">
                    <div class="media-name" title="{self._safe(vid.get('filename',''))}">{self._safe(vid.get('filename',''))[:25]}</div>
                    <div class="media-size">{size}</div>
                  </div>
                </div>""")
            html_parts.append('</div>')
        
        # Lightbox modal
        html_parts.append("""
        <div id="lightbox" class="lightbox" onclick="closeLightbox()">
          <div class="lightbox-inner" onclick="event.stopPropagation()">
            <button class="lightbox-close" onclick="closeLightbox()"><i class="fas fa-times"></i></button>
            <div id="lightbox-title" class="lightbox-title"></div>
            <div id="lightbox-content"></div>
          </div>
        </div>""")
        
        return "\n".join(html_parts)

    def _build_documents(self, documents: List) -> str:
        if not documents:
            return '<div class="empty-state"><i class="fas fa-file-alt"></i> No documents found</div>'
        
        rows = ""
        for doc in documents[:200]:
            icon_map = {
                ".pdf": "fa-file-pdf text-red",
                ".docx": "fa-file-word text-blue",
                ".doc": "fa-file-word text-blue",
                ".xlsx": "fa-file-excel text-green",
                ".txt": "fa-file-lines text-gray",
                ".csv": "fa-file-csv text-green",
            }
            icon = icon_map.get(doc.get("extension", ""), "fa-file text-gray")
            size = self._format_size(doc.get("size", 0))
            
            rows += f"""
            <tr>
              <td><i class="fas {icon}"></i></td>
              <td class="filename-cell">{self._safe(doc.get('filename',''))}</td>
              <td><span class="badge badge-gray">{self._safe(doc.get('doc_type',''))}</span></td>
              <td>{size}</td>
              <td>{self._safe(doc.get('extension',''))}</td>
            </tr>"""
        
        return f"""
        <table class="data-table">
          <thead><tr><th></th><th>Filename</th><th>Type</th><th>Size</th><th>Ext</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    def _build_browser_history(self, history: List) -> str:
        if not history:
            return '<div class="empty-state"><i class="fas fa-globe"></i> No browser history found</div>'
        
        rows = ""
        for entry in history[:500]:
            browser = entry.get("browser", "")
            url = entry.get("url", "")
            title = entry.get("title", "N/A")
            visit_time = entry.get("visit_time", "")
            
            browser_icon = "fab fa-chrome" if "chrome" in browser.lower() else \
                           "fab fa-firefox" if "firefox" in browser.lower() else "fas fa-globe"
            
            rows += f"""
            <tr>
              <td><i class="{browser_icon}"></i> {self._safe(browser)}</td>
              <td class="url-cell"><a href="{self._safe(url)}" target="_blank" class="url-link">{self._safe(url[:80])}</a></td>
              <td>{self._safe(title[:60])}</td>
              <td>{self._safe(visit_time)}</td>
            </tr>"""
        
        return f"""
        <div class="table-wrap">
        <table class="data-table" id="browser-table">
          <thead><tr><th>Browser</th><th>URL</th><th>Title</th><th>Visit Time</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
        </div>"""

    def _build_metadata(self, metadata: List) -> str:
        if not metadata:
            return '<div class="empty-state"><i class="fas fa-tags"></i> No metadata extracted</div>'
        
        rows = ""
        for meta in metadata[:200]:
            gps_link = ""
            if meta.get("gps_latitude") and meta.get("gps_longitude"):
                lat = meta["gps_latitude"]
                lon = meta["gps_longitude"]
                gps_link = f'<a href="https://maps.google.com/maps?q={lat},{lon}" target="_blank" class="gps-link"><i class="fas fa-map-marker-alt"></i> View on Map</a>'
            
            rows += f"""
            <tr>
              <td class="filename-cell">{self._safe(meta.get('filename',''))}</td>
              <td>{self._safe(meta.get('make',''))}</td>
              <td>{self._safe(meta.get('model',''))}</td>
              <td>{self._safe(meta.get('serial_number',''))}</td>
              <td>{self._safe(meta.get('datetime_original','') or meta.get('create_date',''))}</td>
              <td>{gps_link or self._safe(meta.get('gps_position','N/A'))}</td>
            </tr>"""
        
        return f"""
        <table class="data-table">
          <thead><tr><th>Filename</th><th>Make</th><th>Model</th><th>Serial #</th><th>Date</th><th>GPS</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    def _build_timeline(self) -> str:
        if not self.timeline:
            return '<div class="empty-state"><i class="fas fa-history"></i> No timeline data available</div>'
        
        rows = ""
        for event in self.timeline[:500]:
            activity = event.get("activity", "")
            activity_badge = {
                "M": "badge-blue",
                "A": "badge-green",
                "C": "badge-orange",
                "B": "badge-purple",
            }.get(activity, "badge-gray")
            activity_label = {
                "M": "Modified",
                "A": "Accessed",
                "C": "Changed",
                "B": "Born",
            }.get(activity, activity)
            
            rows += f"""
            <tr>
              <td>{self._safe(event.get('date',''))}</td>
              <td><span class="badge {activity_badge}">{self._safe(activity_label)}</span></td>
              <td class="filename-cell">{self._safe(str(event.get('filename',''))[:100])}</td>
              <td>{self._safe(event.get('size',''))}</td>
              <td><code>{self._safe(event.get('inode',''))}</code></td>
            </tr>"""
        
        return f"""
        <div class="table-wrap">
        <table class="data-table" id="timeline-table">
          <thead><tr><th>Date/Time</th><th>Activity</th><th>File</th><th>Size</th><th>Inode</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
        </div>"""

    def _build_search_results(self) -> str:
        if not self.search_results:
            return '<div class="empty-state"><i class="fas fa-search"></i> No keyword searches performed</div>'
        
        html_parts = []
        
        for keyword, results in self.search_results.items():
            badge_class = "badge-red" if results else "badge-gray"
            html_parts.append(f"""
            <div class="search-keyword-group">
              <div class="search-kw-header">
                <i class="fas fa-key"></i> 
                <span class="kw-text">{self._safe(keyword)}</span>
                <span class="badge {badge_class} ml-auto">{len(results)} hits</span>
              </div>""")
            
            if results:
                html_parts.append('<div class="search-hits">')
                for hit in results[:50]:
                    match_type = hit.get("match_type", "")
                    icon_map = {
                        "filename": "fas fa-file",
                        "content": "fas fa-align-left",
                        "browser_history": "fas fa-globe",
                        "metadata": "fas fa-tags",
                        "database": "fas fa-database",
                        "email": "fas fa-envelope",
                        "url": "fas fa-link",
                    }
                    icon = icon_map.get(match_type, "fas fa-search")
                    
                    html_parts.append(f"""
                    <div class="search-hit">
                      <div class="hit-meta">
                        <i class="{icon}"></i>
                        <span class="badge badge-gray">{self._safe(match_type)}</span>
                        <span class="hit-file">{self._safe(str(hit.get('file',''))[:60])}</span>
                        {f'<span class="hit-line">L:{hit["line_number"]}</span>' if hit.get("line_number") else ''}
                      </div>
                      <div class="hit-context">{self._safe(hit.get('context','')[:200])}</div>
                    </div>""")
                html_parts.append('</div>')
            else:
                html_parts.append('<div class="no-hits">No matches found</div>')
            
            html_parts.append('</div>')
        
        return "\n".join(html_parts)

    def _format_size(self, size: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.0f} {unit}"
            size /= 1024
        return f"{size:.1f} GB"

    # ──────────────────────────────────────────────────────────
    # CSS & JS
    # ──────────────────────────────────────────────────────────

    def _get_css(self) -> str:
        return """
        :root {
          --primary: #2563eb;
          --primary-dark: #1d4ed8;
          --secondary: #64748b;
          --success: #16a34a;
          --danger: #dc2626;
          --warning: #d97706;
          --purple: #7c3aed;
          --teal: #0891b2;
          --bg: #f8fafc;
          --surface: #ffffff;
          --border: #e2e8f0;
          --text: #1e293b;
          --text-muted: #64748b;
          --sidebar-w: 260px;
          --topnav-h: 60px;
          --radius: 10px;
          --shadow: 0 2px 8px rgba(0,0,0,.08);
          --shadow-md: 0 4px 16px rgba(0,0,0,.12);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; }
        body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; 
               background: var(--bg); color: var(--text); font-size: 14px; }

        /* TOP NAV */
        .topnav {
          position: fixed; top: 0; left: 0; right: 0; z-index: 1000;
          height: var(--topnav-h);
          background: var(--surface);
          border-bottom: 1px solid var(--border);
          display: flex; align-items: center; padding: 0 24px;
          gap: 16px; box-shadow: var(--shadow);
        }
        .nav-brand { display: flex; align-items: center; gap: 10px; font-size: 18px; font-weight: 700; color: var(--primary); }
        .nav-brand i { font-size: 22px; }
        .nav-info { display: flex; align-items: center; gap: 10px; margin-left: auto; }
        .nav-date { font-size: 12px; color: var(--text-muted); }

        /* LAYOUT */
        .layout { display: flex; margin-top: var(--topnav-h); min-height: calc(100vh - var(--topnav-h)); }

        /* SIDEBAR */
        .sidebar {
          width: var(--sidebar-w); min-height: 100%;
          background: var(--surface);
          border-right: 1px solid var(--border);
          position: fixed; top: var(--topnav-h); left: 0;
          overflow-y: auto; padding-bottom: 32px;
          box-shadow: var(--shadow);
        }
        .sidebar-header {
          padding: 16px; font-weight: 700; font-size: 12px;
          text-transform: uppercase; letter-spacing: .05em;
          color: var(--text-muted); border-bottom: 1px solid var(--border);
          display: flex; align-items: center; gap: 8px;
        }
        .sidebar-item {
          display: flex; align-items: center; gap: 10px;
          padding: 10px 16px; color: var(--text-muted); text-decoration: none;
          font-size: 13px; transition: all .15s; border-left: 3px solid transparent;
          cursor: pointer;
        }
        .sidebar-item:hover { background: #f1f5f9; color: var(--primary); border-left-color: var(--primary); }
        .sidebar-item i { width: 16px; text-align: center; }

        /* MAIN CONTENT */
        .main-content { margin-left: var(--sidebar-w); flex: 1; padding: 24px; max-width: 1400px; }

        /* SEARCH BAR */
        .search-bar-top { margin-bottom: 24px; }
        .search-wrap { display: flex; align-items: center; background: var(--surface);
          border: 2px solid var(--border); border-radius: var(--radius);
          padding: 0 16px; transition: border-color .2s;
          box-shadow: var(--shadow); }
        .search-wrap:focus-within { border-color: var(--primary); }
        .search-icon { color: var(--text-muted); margin-right: 10px; }
        .search-wrap input { flex: 1; border: none; outline: none; padding: 14px 0;
          font-size: 14px; background: transparent; color: var(--text); }
        .btn-search { background: var(--primary); color: #fff; border: none; 
          padding: 8px 20px; border-radius: 6px; cursor: pointer; font-weight: 600;
          transition: background .2s; }
        .btn-search:hover { background: var(--primary-dark); }
        .search-results-inline { background: var(--surface); border: 1px solid var(--border);
          border-radius: var(--radius); margin-top: 8px; padding: 16px;
          max-height: 400px; overflow-y: auto; box-shadow: var(--shadow-md); }

        /* CARDS */
        .card { background: var(--surface); border: 1px solid var(--border);
          border-radius: var(--radius); margin-bottom: 20px; 
          box-shadow: var(--shadow); overflow: hidden; }
        .card-header { padding: 14px 20px; font-weight: 700; font-size: 14px;
          background: #f8fafc; border-bottom: 1px solid var(--border);
          display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        .card-header i { color: var(--primary); }
        .card-body { padding: 20px; }
        
        /* AI CARD */
        .ai-card .card-header { background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%); color: #fff; }
        .ai-card .card-header i { color: #a5b4fc; }
        .ai-summary-body { line-height: 1.7; }
        .ai-summary-body h2 { font-size: 16px; font-weight: 700; margin: 16px 0 8px; color: var(--primary); }
        .ai-summary-body h3 { font-size: 14px; font-weight: 700; margin: 14px 0 6px; color: var(--secondary); }
        .ai-summary-body p { margin: 8px 0; color: var(--text); }
        .ai-summary-body code { background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
        .ai-summary-body strong { color: var(--text); }
        .ai-list { padding-left: 20px; margin: 8px 0; }
        .ai-list li { margin: 4px 0; }
        .ai-summary-body table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        .ai-summary-body tr { border-bottom: 1px solid var(--border); }
        .ai-summary-body td { padding: 8px 12px; }

        /* STATS ROW */
        .stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 20px; }
        .stat-card { background: var(--surface); border: 1px solid var(--border);
          border-radius: var(--radius); padding: 18px 16px; text-align: center;
          box-shadow: var(--shadow); border-top: 3px solid; transition: transform .15s; }
        .stat-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-md); }
        .stat-blue { border-top-color: var(--primary); }
        .stat-red { border-top-color: var(--danger); }
        .stat-green { border-top-color: var(--success); }
        .stat-orange { border-top-color: var(--warning); }
        .stat-purple { border-top-color: var(--purple); }
        .stat-teal { border-top-color: var(--teal); }
        .stat-icon { font-size: 22px; margin-bottom: 8px; opacity: .7; }
        .stat-num { font-size: 28px; font-weight: 800; color: var(--text); line-height: 1; }
        .stat-label { font-size: 12px; color: var(--text-muted); margin-top: 4px; }

        /* BADGES */
        .badge { display: inline-flex; align-items: center; gap: 4px;
          padding: 2px 9px; border-radius: 20px; font-size: 11px; font-weight: 600; }
        .badge-blue { background: #dbeafe; color: #1d4ed8; }
        .badge-green { background: #dcfce7; color: #15803d; }
        .badge-red { background: #fee2e2; color: #b91c1c; }
        .badge-orange { background: #fef3c7; color: #b45309; }
        .badge-purple { background: #ede9fe; color: #6d28d9; }
        .badge-teal { background: #cffafe; color: #0e7490; }
        .badge-gray { background: #f1f5f9; color: #475569; }

        /* INFO GRID */
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }
        .info-item { padding: 12px; background: #f8fafc; border-radius: 8px; border: 1px solid var(--border); }
        .info-label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px; font-weight: 600; }
        .info-value { font-size: 14px; font-weight: 600; color: var(--text); }

        /* HASH GRID */
        .hash-grid { display: grid; gap: 10px; margin-top: 12px; }
        .hash-item { background: #f8fafc; border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px;
          display: flex; align-items: center; gap: 12px; }
        .hash-label { font-size: 11px; font-weight: 700; color: var(--text-muted); min-width: 60px; }
        .hash-value { font-family: 'Courier New', monospace; font-size: 12px; color: var(--text); word-break: break-all; }
        .mt-2 { margin-top: 16px; }
        .ml-auto { margin-left: auto; }

        /* DATA TABLE */
        .table-wrap { overflow-x: auto; }
        .data-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .data-table th { background: #f8fafc; padding: 10px 12px; text-align: left;
          font-weight: 700; font-size: 11px; text-transform: uppercase; letter-spacing: .04em;
          color: var(--text-muted); border-bottom: 2px solid var(--border); white-space: nowrap; }
        .data-table td { padding: 9px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: middle; }
        .data-table tbody tr:hover { background: #f8fafc; }
        .deleted-row { background: #fff5f5 !important; }
        .deleted-row:hover { background: #fee2e2 !important; }
        .filename-cell { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .url-cell { max-width: 350px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .url-link { color: var(--primary); text-decoration: none; }
        .url-link:hover { text-decoration: underline; }
        .text-red { color: var(--danger) !important; }
        .text-blue { color: var(--primary) !important; }
        .text-yellow { color: var(--warning) !important; }
        .text-green { color: var(--success) !important; }
        .text-gray { color: var(--text-muted) !important; }

        /* TABLE FILTER */
        .table-filter { border: 1px solid var(--border); border-radius: 6px; padding: 5px 10px;
          font-size: 12px; outline: none; transition: border-color .2s; margin-left: 8px; }
        .table-filter:focus { border-color: var(--primary); }

        /* MEDIA GRID */
        .media-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 14px; }
        .media-card { border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden;
          cursor: pointer; transition: all .2s; box-shadow: var(--shadow); }
        .media-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); border-color: var(--primary); }
        .media-thumb { height: 110px; background: #f1f5f9; display: flex; align-items: center;
          justify-content: center; overflow: hidden; }
        .media-thumb img { width: 100%; height: 100%; object-fit: cover; }
        .no-preview { font-size: 36px; color: var(--text-muted); }
        .video-thumb { background: #1e1b4b; color: #a5b4fc; flex-direction: column; gap: 6px; }
        .video-thumb i { font-size: 36px; }
        .video-ext { font-size: 11px; font-weight: 700; letter-spacing: .1em; color: #a5b4fc; }
        .media-info { padding: 8px 10px; background: var(--surface); }
        .media-name { font-size: 12px; font-weight: 600; white-space: nowrap;
          overflow: hidden; text-overflow: ellipsis; color: var(--text); }
        .media-size { font-size: 11px; color: var(--text-muted); }

        /* LIGHTBOX */
        .lightbox { display: none; position: fixed; inset: 0; z-index: 9999;
          background: rgba(0,0,0,.85); align-items: center; justify-content: center; }
        .lightbox.open { display: flex; }
        .lightbox-inner { background: var(--surface); border-radius: 12px; padding: 24px;
          max-width: 90vw; max-height: 90vh; overflow: auto; position: relative; min-width: 300px; }
        .lightbox-close { position: absolute; top: 12px; right: 12px; background: #f1f5f9;
          border: none; border-radius: 50%; width: 32px; height: 32px; cursor: pointer;
          display: flex; align-items: center; justify-content: center; font-size: 14px; }
        .lightbox-title { font-weight: 700; margin-bottom: 16px; font-size: 14px; padding-right: 40px; }
        #lightbox-content img { max-width: 100%; max-height: 70vh; border-radius: 8px; }
        #lightbox-content video { max-width: 100%; max-height: 70vh; border-radius: 8px; }

        /* SECTION SUB */
        .section-sub { font-size: 14px; font-weight: 700; color: var(--text); margin: 0 0 14px;
          display: flex; align-items: center; gap: 8px; }

        /* CODE BLOCK */
        .code-block { background: #1e293b; color: #e2e8f0; padding: 16px;
          border-radius: 8px; font-family: 'Courier New', monospace; font-size: 12px;
          overflow-x: auto; line-height: 1.6; white-space: pre-wrap; }
        .raw-details { margin-top: 12px; }
        .raw-details summary { cursor: pointer; color: var(--primary); font-weight: 600;
          font-size: 13px; padding: 6px 0; }

        /* SEARCH RESULTS */
        .search-keyword-group { border: 1px solid var(--border); border-radius: var(--radius);
          margin-bottom: 16px; overflow: hidden; }
        .search-kw-header { padding: 12px 16px; background: #f8fafc; display: flex;
          align-items: center; gap: 10px; font-weight: 700; }
        .kw-text { font-family: monospace; background: #1e293b; color: #f8fafc;
          padding: 2px 10px; border-radius: 4px; font-size: 13px; }
        .search-hits { padding: 12px; display: flex; flex-direction: column; gap: 8px; }
        .search-hit { background: #f8fafc; border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; }
        .hit-meta { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; flex-wrap: wrap; }
        .hit-file { font-family: monospace; font-size: 12px; color: var(--primary); }
        .hit-line { font-size: 11px; color: var(--text-muted); }
        .hit-context { font-family: monospace; font-size: 12px; color: var(--text);
          background: #fff; border: 1px solid var(--border); padding: 6px 10px; border-radius: 4px;
          overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
        .no-hits { padding: 12px 16px; color: var(--text-muted); font-style: italic; }

        /* GPS LINK */
        .gps-link { color: var(--success); text-decoration: none; font-weight: 600; }
        .gps-link:hover { text-decoration: underline; }

        /* EMPTY STATE */
        .empty-state { display: flex; align-items: center; gap: 10px; color: var(--text-muted);
          padding: 24px; font-size: 14px; justify-content: center; }
        .empty-state i { font-size: 20px; }

        /* FOOTER */
        .report-footer { text-align: center; padding: 24px; color: var(--text-muted);
          font-size: 12px; border-top: 1px solid var(--border); margin-top: 32px; }

        /* SCROLLBAR */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #f1f5f9; }
        ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 3px; }

        @media (max-width: 900px) {
          .sidebar { display: none; }
          .main-content { margin-left: 0; }
        }
        """

    def _get_js(self) -> str:
        search_data = json.dumps({
            "filenames": [f.get("name", "") for f in self.disk_results.get("all_files", [])[:1000]],
            "browser": [{"url": h.get("url",""), "title": h.get("title","")} 
                        for h in self.artifacts.get("browser_history", [])[:500]],
        })
        
        return f"""
        // Sidebar scroll
        function scrollTo(id) {{
          const el = document.getElementById(id);
          if (el) el.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
          // Update active sidebar
          document.querySelectorAll('.sidebar-item').forEach(i => i.classList.remove('active'));
          event.currentTarget.classList.add('active');
        }}
        
        // Table filter
        function filterTable(input, tableId) {{
          const filter = input.value.toLowerCase();
          const table = document.getElementById(tableId);
          if (!table) return;
          const rows = table.getElementsByTagName('tr');
          for (let i = 1; i < rows.length; i++) {{
            const text = rows[i].textContent.toLowerCase();
            rows[i].style.display = text.includes(filter) ? '' : 'none';
          }}
        }}
        
        // Lightbox
        function openLightbox(name, src, type) {{
          document.getElementById('lightbox-title').textContent = name;
          const content = document.getElementById('lightbox-content');
          if (type === 'image') {{
            content.innerHTML = `<img src="${{src}}" alt="${{name}}"/>`;
          }} else if (type === 'video') {{
            content.innerHTML = `<video controls autoplay><source src="${{src}}"/></video>`;
          }}
          document.getElementById('lightbox').classList.add('open');
        }}
        function closeLightbox() {{
          document.getElementById('lightbox').classList.remove('open');
          document.getElementById('lightbox-content').innerHTML = '';
        }}
        document.addEventListener('keydown', e => {{ if (e.key === 'Escape') closeLightbox(); }});
        
        // Global search
        const searchData = {search_data};
        
        function runGlobalSearch() {{
          const q = document.getElementById('globalSearch').value.trim().toLowerCase();
          if (!q) return;
          
          const results = [];
          
          // Search filenames
          searchData.filenames.forEach(name => {{
            if (name.toLowerCase().includes(q)) {{
              results.push({{ type: 'File', context: name }});
            }}
          }});
          
          // Search browser
          searchData.browser.forEach(entry => {{
            if ((entry.url||'').toLowerCase().includes(q) || (entry.title||'').toLowerCase().includes(q)) {{
              results.push({{ type: 'Browser', context: entry.url + ' — ' + entry.title }});
            }}
          }});
          
          const div = document.getElementById('searchResults');
          div.style.display = 'block';
          
          if (!results.length) {{
            div.innerHTML = '<div style="color:#64748b;padding:10px"><i class="fas fa-search"></i> No matches found for "<strong>' + q + '</strong>"</div>';
            return;
          }}
          
          let html = `<div style="font-weight:700;margin-bottom:8px;color:#2563eb"><i class="fas fa-check-circle"></i> ${{results.length}} match(es) for "${{q}}"</div>`;
          results.slice(0, 30).forEach(r => {{
            html += `<div style="padding:8px;background:#f8fafc;border-radius:6px;margin-bottom:4px;border:1px solid #e2e8f0">
              <span style="background:#dbeafe;color:#1d4ed8;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700">${{r.type}}</span>
              <span style="font-family:monospace;font-size:12px;margin-left:10px">${{r.context.slice(0,150)}}</span>
            </div>`;
          }});
          if (results.length > 30) {{
            html += `<div style="color:#64748b;font-size:12px;margin-top:4px">+ ${{results.length - 30}} more results</div>`;
          }}
          div.innerHTML = html;
        }}
        
        // Close search on outside click
        document.addEventListener('click', function(e) {{
          const searchDiv = document.getElementById('searchResults');
          const searchBar = document.querySelector('.search-bar-top');
          if (searchBar && !searchBar.contains(e.target)) {{
            if (searchDiv) searchDiv.style.display = 'none';
          }}
        }});
        
        // Highlight active sidebar on scroll
        window.addEventListener('scroll', function() {{
          const sections = document.querySelectorAll('section[id]');
          const sidebarItems = document.querySelectorAll('.sidebar-item');
          let current = '';
          sections.forEach(section => {{
            const sectionTop = section.offsetTop - 80;
            if (window.pageYOffset >= sectionTop) {{
              current = section.getAttribute('id');
            }}
          }});
          sidebarItems.forEach(item => {{
            item.classList.remove('active');
            if (item.getAttribute('onclick') && item.getAttribute('onclick').includes(current)) {{
              item.classList.add('active');
            }}
          }});
        }});
        
        // Active sidebar style
        const style = document.createElement('style');
        style.textContent = '.sidebar-item.active {{ background: #eff6ff; color: #2563eb; border-left-color: #2563eb; }}';
        document.head.appendChild(style);
        """
