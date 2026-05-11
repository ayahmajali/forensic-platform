# Digital Forensics Investigation Platform — Abstract

**Author:** Basil
**Project type:** Graduation project — Computer Science / Cybersecurity
**Repository:** https://github.com/ayahmajali/forensic-platform
**Live site:** https://forensic-site.onrender.com

---

## Abstract

Digital forensic investigations require examiners to recover, catalogue, and
report on evidence drawn from disk images, file systems, and live machines.
The industry-standard tools for this work — Autopsy and The Sleuth Kit — are
powerful but heavy desktop applications that demand local installation,
significant training, and a workstation with the suspect drive physically
attached. This project reimagines that workflow as a lightweight, modern web
platform paired with a portable desktop agent, lowering the barrier to
professional-grade forensic triage without sacrificing analytical rigour.

The platform is divided into three independent surfaces. A **FastAPI backend**
deployed on Render hosts case records in a MongoDB Atlas database, runs the
heavy server-side analysis pipeline (hashing, Sleuth Kit subprocess
orchestration, ExifTool metadata extraction, browser-artifact parsing, and AI
summarisation), and renders an interactive HTML case report with a
court-deliverable PDF. A **cross-platform desktop agent**, packaged as a
single PyInstaller binary that bundles its own copy of The Sleuth Kit and
PhotoRec, runs on the investigator's machine and produces structured JSON
findings that are submitted to the backend — the raw evidence files never
leave the operator's device, preserving privacy and chain of custody.
A **vanilla-JavaScript frontend** hosted on Cloudflare Pages provides the
public-facing investigation portal.

The agent integrates two complementary recovery tools with explicit
investigator control: The Sleuth Kit's `tsk_recover` recovers deleted files
together with their original filenames, while PhotoRec performs raw-block
signature carving for cases where filesystem metadata has already been
overwritten. The investigator selects the recovery strategy, the file types
of interest, and the scan depth through a guided four-step interface; the
agent then orchestrates the chosen pipeline, detects SSD TRIM conditions that
would render recovery futile, and surfaces every error transparently in the
final case record.

The result is a working, deployed system that demonstrates how open-source
forensic tooling can be wrapped in a modern web architecture to produce a
usable, auditable, privacy-respecting investigative platform — one that
delivers a complete forensic report in minutes rather than the hours
traditionally required by legacy desktop tools.

---

## Keywords

Digital forensics · The Sleuth Kit · PhotoRec · File carving · Chain of
custody · FastAPI · MongoDB · PyInstaller · Cross-platform agent · Incident
response · Cybersecurity

---

## Technical contributions

1. **Hybrid recovery pipeline** — the agent runs Sleuth Kit (filename-preserving) and PhotoRec (signature-carving) in either-or-both modes, with the investigator choosing which 13 PhotoRec file-format signatures to enable. Trimming the signature set from 13 to 3 reduces scan time on a 30 GB USB from roughly 20 minutes to under 5.
2. **Privacy-by-architecture** — only structured JSON findings (paths, hashes, timestamps, counts) are transmitted to the backend. Raw evidence files never leave the investigator's machine; recovered files are written locally to `~/Desktop/RestoredFiles/`.
3. **Native admin elevation** — the agent triggers Touch ID (macOS), UAC (Windows), or PolicyKit (Linux) for the raw block-device reads PhotoRec requires, eliminating the terminal-`sudo` friction that hinders field use.
4. **Court-ready reporting** — every case produces both an interactive HTML report and a downloadable PDF, with chain-of-custody hashes (MD5 + SHA-1 + SHA-256), a forensic timeline derived from `fls -rd`, and an AI-generated investigation summary.
5. **Self-contained binary** — the Windows agent ships as a single 95 MB `.exe` with The Sleuth Kit and PhotoRec embedded; the target machine needs no prior installation, no Python runtime, and no admin tooling beyond what the OS already provides.

## System scope

The system supports E01, DD, RAW, IMG, ISO, and logical file inputs. The
agent enumerates the system Trash / Recycle Bin, parses browser history
across nine browser families (Chrome, Edge, Firefox, Brave, Opera, Vivaldi,
Safari, Arc, Yandex) on macOS, Windows, and Linux, and performs MD5 /
SHA-1 / SHA-256 hashing on every file walked. Disk-image analysis runs the
full Sleuth Kit pipeline (`mmls` → `fsstat` → `fls -rd` → `tsk_recover`).
The backend exposes a REST API documented by FastAPI's auto-generated
OpenAPI specification.
