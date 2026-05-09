# Forensic Platform — Defense Demo Script

A click-by-click runbook for the graduation defense. Built so the demo
is **rehearsable**, **partner-runnable**, and has **fallback paths** if
anything misbehaves on stage.

---

## 1. Before you walk in (15 min before defense)

**A. Power & network**

- [ ] Demo laptop plugged in (don't trust the battery)
- [ ] Wi-Fi or hotspot working — open `https://forensic-platform-sy5q.onrender.com/api/health` in a browser tab; it should return `{"status":"ok"}`. If it's slow, it means Render is cold-starting; just refresh until it responds.
- [ ] Browser bookmarks bar visible with: live site, GitHub repo, the test case URL from yesterday's smoke run

**B. Evidence pre-positioned**

- [ ] USB stick plugged in, drive letter noted (probably `D:` or `E:`)
- [ ] On the USB: a folder named `evidence-demo` containing 3–4 files (PDF, JPG, DOCX). These are about to be "deleted" on stage.
- [ ] On the USB: a backup copy of those same files at `evidence-demo-backup\` so we can restore for the next rehearsal.
- [ ] Optional safety net: a known-good disk image at `C:\Users\Public\Downloads\forensic-platform\docs\demo-evidence\sample.dd` (if pre-prepared)

**C. Agent ready**

- [ ] `ForensicAgent.exe` exists at `C:\Users\Public\Downloads\forensic-platform\backend\static\downloads\ForensicAgent-windows.exe`
- [ ] Or rebuilt copy at `agent\dist\ForensicAgent.exe`
- [ ] You **know** which one is freshest. Both should work; in doubt, prefer `dist\ForensicAgent.exe`.

**D. Speaking notes**

- One paragraph elevator pitch ready (see §6 below)
- Architecture diagram open in a browser tab (README.md in GitHub renders Mermaid)

---

## 2. The headline pitch (30 seconds, opening)

> "We built a digital-forensics platform inspired by Autopsy and The Sleuth Kit. An investigator runs a small native agent on the suspect machine, the agent scans the file system, the Recycle Bin, browser history, and any disk images it finds, and uses the open-source Sleuth Kit and PhotoRec under the hood for deep recovery. The findings — never the raw evidence — are sent to a FastAPI backend on Render, stored in MongoDB with a chain-of-custody hash, and rendered as a forensic case report with a downloadable PDF."

Then transition into the demo.

---

## 3. Demo flow A — System trash recovery (always works, the safe demo)

This path doesn't depend on PhotoRec, BitLocker, or TRIM — it just shows the Recycle Bin pipeline.

| Step | Action | What to say |
|---|---|---|
| 1 | Open File Explorer → navigate to the USB → folder `evidence-demo` | "Imagine these are files seized from a suspect machine." |
| 2 | Select all → press `Delete` (regular delete, **not** Shift+Delete) | "The suspect 'deletes' them. To them, they're gone." |
| 3 | Confirm files now sit in the Recycle Bin | "Of course they're not actually gone. They're in `$Recycle.Bin`." |
| 4 | Right-click `ForensicAgent-windows.exe` → **Run as administrator** → click Yes on UAC | "The agent needs admin to read raw filesystem metadata. It asks **once**, at startup." |
| 5 | Step 1: Click **Choose folder**, pick the USB drive root | Point out the **Backend reachable** green tick — "It's already talking to the case server." |
| 6 | Step 2: leave defaults — **Recover deleted files** ticked, **Deep recover** unticked, **Include browser history** unticked | "For this scenario we don't need raw-disk carving — the trash is the smoking gun." |
| 7 | Click **Start scan** | Wait ~5 seconds. Live log streams. |
| 8 | When **Done** appears, point to the counter row: **N files**, **0 modified**, **0 deleted (image)**, **N in trash** | "Four files in the OS trash — exactly what we deleted." |
| 9 | Click the **System Trash** tab | Point at the table — original path, deletion timestamp, size. |
| 10 | When the **"We found N deleted file(s) — restore?"** dialog appears, click **Yes** | "The agent doesn't just **report** what's recoverable — it actually pulls the files back." |
| 11 | Open File Explorer at `C:\Users\<you>\Desktop\RestoredFiles\` — show the recovered files | "These are byte-for-byte the originals. Same content, same name." |
| 12 | Back to agent, click **Submit** in Step 4 | Watch the green check appear with a Case ID like `b2bd66fa`. |
| 13 | Open browser → navigate to `https://forensic-platform-sy5q.onrender.com/case/<that-id>` | "And here's the published case report — auto-generated, viewable from anywhere." |
| 14 | Scroll the case page; click **Download PDF** | "This PDF is the deliverable a court would receive." |

**Stop here for the safe demo. Total time: ~3 minutes.**

---

## 4. Demo flow B — Disk image analysis (the technically impressive demo)

Run this if Demo A worked smoothly and you have time. Uses the same agent but a different code path: **The Sleuth Kit** (`mmls`, `fls`, `tsk_recover`) operating on a real disk image file.

| Step | Action | What to say |
|---|---|---|
| 1 | In the agent, click **Choose folder** → navigate to `C:\Users\Public\Downloads\forensic-platform\docs\demo-evidence\` | "Same workflow — but this folder contains a `.dd` disk image, not loose files." |
| 2 | Tick **Recover deleted files** | "We want unallocated entries pulled out." |
| 3 | Click **Start scan** | The log pane shows the TSK pipeline: `mmls` (partition table) → `fsstat` (filesystem) → `fls -rd` (deleted entries) → `tsk_recover` (recovery). |
| 4 | When done, click the **Deleted (Disk Image)** tab | Show the table of entries TSK undeleted. |
| 5 | Click the **Overview** tab to show partition table + filesystem details | "This is what a forensic examiner pays Autopsy for. We replicate it with the same upstream tool." |

---

## 5. Demo flow C — Deep Recovery (PhotoRec) — **only if green-lit ahead of time**

This is the riskiest demo path because PhotoRec depends on:

- The drive not having TRIM zeroed the deleted blocks (so use an HDD or a USB stick, **not** the laptop's NVMe)
- The drive not being BitLocker encrypted
- A long enough scan budget (~5–15 min for a small USB)

If we got Deep Recovery working in last night's diagnostics, run it on the USB **after** a Shift+Delete (which bypasses Recycle Bin entirely):

| Step | Action | What to say |
|---|---|---|
| 1 | Restore the demo files to the USB from `evidence-demo-backup\` | (off-camera reset) |
| 2 | On the USB: select all → **Shift+Delete** (skips Recycle Bin) | "Suspect tries to evade by hard-deleting." |
| 3 | Empty the system Recycle Bin for good measure | "Files are gone from any standard tooling now." |
| 4 | Run agent again, point it at the USB folder, **tick Deep recover**, Start scan | A separate console window pops showing PhotoRec live-carving. "Underneath, that's PhotoRec — same tool a sworn examiner would use." |
| 5 | Wait. Don't fill the silence — let the bar tick. | If asked: "It scans the entire raw partition by signature, not file system." |
| 6 | When done → **Deep Recovery** tab → recovered file count + paths | "Files reconstructed from the raw flash without any filesystem help." |

**If Deep Recovery has issues mid-demo:** fall back gracefully — "What the audience just saw is the failure mode being captured cleanly: PhotoRec exited, the agent caught the error, surfaced the diagnostic log, and the case report still records that an attempt was made. That's the forensic chain of custody — we don't pretend a tool worked when it didn't."

---

## 6. Anticipated questions & answers

**Q: Why not just upload the disk image to the server and analyze it there?**
A: Privacy and chain-of-custody. The raw evidence stays on the investigator's machine. Only the structured findings (JSON metadata, hashes, recovered file listings) leave the device. The agent never uploads file contents.

**Q: How does the agent authenticate to the backend?**
A: A shared API key, sent in the `X-API-Key` header. It's set as an environment variable on the Render server and pasted into the agent's GUI on first launch. Without it, write endpoints return 503.

**Q: What if the suspect's computer doesn't have Python installed?**
A: It doesn't need to. We ship a single self-contained `.exe` built with PyInstaller. The Python runtime, Sleuth Kit binaries, and PhotoRec are all bundled inside. Total size ~95 MB. Drop it on a USB stick, double-click on the target machine, done.

**Q: How is this different from Autopsy?**
A: Autopsy is a heavy desktop application that imports a disk image and gives you a forensic browser. We're a triage tool: lightweight, agent-based, designed for the situation where you're at someone's computer and want to extract findings into a case file in 5 minutes. We use the same upstream tools (TSK, PhotoRec) so the underlying analysis quality is equivalent.

**Q: What about TRIM on SSDs? Doesn't that make recovery impossible?**
A: Yes — and we're honest about it. The agent detects when the volume is on a TRIM-enabled SSD and warns the operator that recovery may yield nothing. We don't pretend bytes exist that the drive controller has already zeroed.

**Q: Why MongoDB instead of PostgreSQL?**
A: Cases are document-shaped — variable-shape findings, nested arrays of files, optional metadata. Mongo's schema-flexibility fits naturally and we don't need joins.

**Q: Can the backend handle multiple concurrent scans?**
A: Yes — FastAPI is async; case submissions are independent documents. We've tested with synthetic workloads. Real bottleneck is single-tenant Mongo Atlas free tier (512 MB).

**Q: What happens to the recovered files? Do they leave the investigator's machine?**
A: No. Only **listings and hashes** are sent to the backend. The recovered files themselves stay in `~/Desktop/RestoredFiles/` on the investigator's local machine. The privacy panel in the agent UI says this explicitly.

**Q: What's the failure mode when something goes wrong on a real seizure?**
A: Every operation has a timeout, every subprocess error is captured, and the agent submits a case **with errors logged** rather than silently dying. The Errors tab in the case report shows exactly what failed.

---

## 7. Backup plan (if the live demo breaks completely)

1. **Have a screen recording ready.** Record demo flow A on a working machine the night before. If the live demo dies, switch to the recording, narrate over it, and treat the technical hiccup as honesty: "On a real seizure that's why we have field protocols — let me walk through what the recording shows."

2. **Have an existing case URL ready.** If submission fails, paste an already-submitted case URL into the browser and demo the report from there.

3. **Have the GitHub repo open in a tab.** If everything dies, switch to "code walk-through" mode — show the architecture diagram, the agent code, the FastAPI endpoints. Defending the engineering is just as legitimate as showing it run.

---

## 8. After the defense

- [ ] Power down the laptop before unplugging
- [ ] Recover the USB stick — don't leave demo evidence behind
- [ ] Take a victory photo
- [ ] One final commit: tag this revision as `v1.0-defense` in git so you know what shipped on the day

```bash
git tag v1.0-defense
git push origin v1.0-defense
```

Good luck. 🎓
