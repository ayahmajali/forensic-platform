"""
ai_summary.py — AI Evidence Summarization Module
Uses OpenAI GPT to generate concise forensic investigation summaries.
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional


class AISummarizer:
    """
    AI-powered evidence summarization using OpenAI's GPT models.
    Falls back gracefully if API key not configured.
    """

    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY", "")
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.available = bool(self.api_key)

    def generate_summary(self, analysis_data: Dict) -> str:
        """
        Generate an AI-powered forensic summary.
        Falls back to template-based summary if OpenAI unavailable.
        """
        if self.available:
            try:
                return self._openai_summary(analysis_data)
            except Exception as e:
                print(f"OpenAI API error: {e}, using template summary")
        
        return self._template_summary(analysis_data)

    def _openai_summary(self, data: Dict) -> str:
        """Generate summary using OpenAI API."""
        import urllib.request
        import json as jsonlib
        
        evidence_name = data.get("evidence_name", "Unknown")
        evidence_type = data.get("evidence_type", "unknown")
        hashes = data.get("hashes", {})
        artifacts = data.get("artifacts", {})
        disk_results = data.get("disk_results", {})
        search_results = data.get("search_results", {})
        recovered_count = data.get("recovered_count", 0)
        timeline_count = data.get("timeline_count", 0)

        browser_history = artifacts.get("browser_history", [])
        multimedia = artifacts.get("multimedia", [])
        documents = artifacts.get("documents", [])
        metadata = artifacts.get("metadata", [])
        deleted_files = disk_results.get("deleted_files", [])

        # Top URLs
        top_urls = list(set([
            h.get("url", "")[:80] for h in browser_history[:20] if h.get("url")
        ]))[:10]

        # Suspicious keywords
        suspicious = []
        for kw, hits in search_results.items():
            if hits:
                suspicious.append(f"{kw} ({len(hits)} hits)")

        # GPS locations
        gps_items = [m for m in metadata if m.get("gps_latitude") or m.get("gps_position")]

        prompt = f"""You are a senior digital forensics investigator. Analyze the following evidence findings and write a professional forensic investigation summary.

EVIDENCE OVERVIEW:
- File: {evidence_name}
- Type: {evidence_type.upper()}
- SHA256: {hashes.get('sha256', 'N/A')}
- MD5: {hashes.get('md5', 'N/A')}
- Size: {hashes.get('file_size_human', 'N/A')}

RECOVERED FILES:
- Total recovered: {recovered_count}
- Images: {len([m for m in multimedia if m.get('type') == 'image'])}
- Videos: {len([m for m in multimedia if m.get('type') == 'video'])}
- Documents: {len(documents)}
- Deleted files detected: {len(deleted_files)}
- Timeline events: {timeline_count}

BROWSER ARTIFACTS:
- History entries: {len(browser_history)}
- Top visited domains: {', '.join(top_urls[:5]) if top_urls else 'None'}

METADATA FINDINGS:
- Files with EXIF: {len(metadata)}
- Files with GPS: {len(gps_items)}

KEYWORD SEARCH RESULTS:
{json.dumps(suspicious, indent=2) if suspicious else 'No suspicious keywords flagged'}

Write a professional forensic summary in Markdown format with:
1. Executive Summary (2-3 sentences)
2. Key Findings (bullet points)
3. Suspicious Activity (if any)
4. Recommended Follow-up Actions
5. Evidence Integrity Statement

Keep it professional, concise, and actionable for an investigator."""

        payload = jsonlib.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a professional digital forensics investigator writing official case reports."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 1000,
            "temperature": 0.3
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            },
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            response = jsonlib.loads(resp.read().decode("utf-8"))
            return response["choices"][0]["message"]["content"]

    def _template_summary(self, data: Dict) -> str:
        """Generate structured summary without AI."""
        evidence_name = data.get("evidence_name", "Unknown")
        evidence_type = data.get("evidence_type", "unknown")
        hashes = data.get("hashes", {})
        artifacts = data.get("artifacts", {})
        disk_results = data.get("disk_results", {})
        search_results = data.get("search_results", {})
        recovered_count = data.get("recovered_count", 0)
        timeline_count = data.get("timeline_count", 0)

        browser_history = artifacts.get("browser_history", [])
        multimedia = artifacts.get("multimedia", [])
        images = [m for m in multimedia if m.get("type") == "image"]
        videos = [m for m in multimedia if m.get("type") == "video"]
        documents = artifacts.get("documents", [])
        metadata = artifacts.get("metadata", [])
        deleted_files = disk_results.get("deleted_files", [])
        partitions = disk_results.get("partitions", [])

        # Suspicious findings
        suspicious = []
        for kw, hits in search_results.items():
            if hits:
                suspicious.append(f"**{kw}**: {len(hits)} occurrence(s)")

        # GPS items
        gps_items = [m for m in metadata if m.get("gps_latitude") or m.get("gps_position")]

        # Camera info
        cameras = list(set([
            f"{m.get('make','')} {m.get('model','')}".strip()
            for m in metadata
            if m.get("make") or m.get("model")
        ]))

        # Browser domains
        domains = list(set([
            h.get("url", "").split("/")[2] if "/" in h.get("url", "") else ""
            for h in browser_history[:50]
            if h.get("url")
        ]))
        domains = [d for d in domains if d][:10]

        return f"""## 🔍 AI Investigation Summary

**Case File:** {evidence_name}  
**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Evidence Type:** {evidence_type.upper()}  

---

### Executive Summary
This forensic analysis examined **{evidence_name}** ({evidence_type.upper()}). The investigation 
recovered **{recovered_count}** files, identified **{len(deleted_files)}** deleted files, and 
generated **{timeline_count}** timeline events. 
{f'Browser history revealed **{len(browser_history)}** activity entries.' if browser_history else ''}

---

### 📁 Evidence Integrity
| Hash | Value |
|------|-------|
| **MD5** | `{hashes.get('md5', 'N/A')}` |
| **SHA256** | `{hashes.get('sha256', 'N/A')}` |
| **File Size** | {hashes.get('file_size_human', 'N/A')} |

---

### 🗂️ Recovered Files Summary
| Category | Count |
|----------|-------|
| Total Recovered | **{recovered_count}** |
| Images | **{len(images)}** |
| Videos | **{len(videos)}** |
| Documents | **{len(documents)}** |
| Deleted Files | **{len(deleted_files)}** |
| Timeline Events | **{timeline_count}** |
| Partitions | **{len(partitions)}** |

---

### 🌐 Browser Activity
{f'- **{len(browser_history)}** browsing history entries detected' if browser_history else '- No browser history found'}
{('- **Top domains visited:** ' + ', '.join(f'`{d}`' for d in domains[:5])) if domains else ''}

---

### 📸 Metadata Findings  
- **{len(metadata)}** files with extractable metadata
{('- **GPS Coordinates found:** ' + str(len(gps_items)) + ' location(s)') if gps_items else '- No GPS data found'}
{('- **Camera models:** ' + ', '.join(cameras[:3])) if cameras else ''}

---

### 🚨 Keyword Search Findings
{chr(10).join(f'- {s}' for s in suspicious) if suspicious else '- No suspicious keywords flagged in this analysis'}

---

### ✅ Recommendations
1. Review all **{len(deleted_files)}** deleted files for evidence of data wiping
{f'2. Investigate browser history entries for suspicious URLs' if browser_history else ''}
{f'3. Cross-reference GPS coordinates with case timeline' if gps_items else ''}
4. Verify file integrity using provided hash values
5. Document chain of custody for all recovered evidence

---
*Summary generated automatically by Digital Forensics Investigation Platform*
"""
