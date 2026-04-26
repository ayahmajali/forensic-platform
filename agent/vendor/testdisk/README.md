# Vendored PhotoRec / TestDisk Binaries

This folder holds the PhotoRec (and optionally TestDisk) Windows CLI binaries
that get **bundled into the Windows agent `.exe`** at build time so
investigators can run Deep Recovery (raw-disk file carving) on a machine
without a system-wide TestDisk install.

`agent/recovery.py` looks here first (`vendor/testdisk/`) when resolving the
`photorec_win.exe` binary, and falls back to `sys._MEIPASS/testdisk/` once
PyInstaller has extracted the one-file bundle at runtime. See
`_candidate_dirs()` in that module for the exact search order.

---

## Required files (Windows — for bundling into `ForensicAgent.exe`)

Drop these files directly into this folder (no subdirectories):

    photorec_win.exe       # REQUIRED — the raw-disk file carver
    testdisk_win.exe       # OPTIONAL — partition table repair (not used today)
    fidentify_win.exe      # OPTIONAL — reports file types from signatures

Plus any supporting DLLs the TestDisk Windows build ships alongside those
`.exe` files — the build script grabs everything matching `*.exe` and `*.dll`
in this folder.

## Where to get them

1. Download the TestDisk/PhotoRec Windows release (a portable zip, ~10 MB):
   <https://www.cgsecurity.org/wiki/TestDisk_Download>
2. Unzip it somewhere temporary. You'll get a folder like
   `testdisk-7.2\` containing the binaries at the top level.
3. Copy `photorec_win.exe` (and any companion DLLs) into *this* folder.

TestDisk/PhotoRec is licensed under the GNU GPL v2+ — redistribution inside
our bundled `.exe` is permitted. See `../../../LICENSE.third_party.md` (TODO
if not already present) for the compliance note.

## Why PhotoRec beats tsk_recover for emptied Recycle Bin scenarios

`tsk_recover` (Sleuth Kit) only undeletes files the filesystem still has
metadata for — recently-deleted NTFS MFT entries, ext4 entries before the
journal rotates. Once the filesystem reclaims that metadata — which happens
as soon as you empty the Recycle Bin — `tsk_recover` has nothing to recover.

PhotoRec is **signature-based**: it ignores the filesystem entirely and reads
the raw block device looking for JPEG/PDF/DOCX/... headers. That's why it can
bring back files that `tsk_recover` cannot, and why we wire it into Deep
Recovery mode.

## macOS / Linux

On macOS we expect investigators to `brew install testdisk`; on Linux,
`sudo apt install testdisk` or the distro equivalent. The agent finds the
`photorec` binary via `PATH` and does not ship a vendored copy for those
platforms.

## What if the folder is empty?

The build still succeeds — the resulting `.exe` will include everything
*except* the PhotoRec binary. Deep Recovery inside the GUI will then fail
with a friendly "PhotoRec is not installed" message pointing the user back
here. TSK-based recovery, logical-folder scans, and browser-history parsing
continue to work regardless.
