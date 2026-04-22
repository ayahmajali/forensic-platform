# Vendored Sleuth Kit Binaries

This folder holds the Sleuth Kit (TSK) CLI binaries that get **bundled into the
Windows agent `.exe`** at build time so investigators can run disk-image
analysis on a machine without a system-wide TSK install.

`agent/tsk_runner.py` looks here first (`vendor/tsk/`) when resolving the
`mmls`, `fsstat`, `fls`, `tsk_recover`, and `icat` binaries, and falls back to
`sys._MEIPASS/tsk/` once PyInstaller has extracted the one-file bundle at
runtime. See `_candidate_dirs()` in that module for the exact search order.

---

## Required files (Windows — for bundling into `ForensicAgent.exe`)

Drop these `.exe` files directly into this folder (no subdirectories):

    mmls.exe
    fsstat.exe
    fls.exe
    tsk_recover.exe
    icat.exe

Any supporting DLLs the Sleuth Kit Windows build ships alongside those `.exe`
files (for example `libtsk.dll`, `libewf.dll`, `zlib1.dll`) belong here too —
the build script grabs everything matching `*.exe` and `*.dll`.

## Where to get them

1. Download the Sleuth Kit Windows release (a zip, around 20–25 MB):
   <https://www.sleuthkit.org/sleuthkit/download.php>
2. Unzip it somewhere temporary.
3. Copy the `bin\*.exe` and `bin\*.dll` files into *this* folder.

The files are licensed under the Common Public License / IBM Public License —
redistribution inside our bundled `.exe` is permitted as long as the licence
text ships with the product. See `../../../LICENSE.third_party.md` (TODO if
not already present) for the compliance note.

## macOS / Linux

On macOS we expect investigators to `brew install sleuthkit`; on Linux,
`apt-get install sleuthkit` or the distro equivalent. The agent finds the
binaries via `PATH` and does not ship a vendored copy for those platforms.

## What if the folder is empty?

The build still succeeds — the resulting `.exe` will include everything
*except* the TSK binaries. Disk-image mode inside the GUI will then fail with
a friendly "Sleuth Kit is not available" message pointing the user back here.
Logical-folder scans and browser-history parsing continue to work regardless.
