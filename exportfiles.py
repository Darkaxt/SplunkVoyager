"""Export folders: per-window part files while a run is going, one compressed export.zip once it is complete.

Readers go through parts() / open_part() and don't care which form a folder is in (loose part files win over
the same name inside the zip, e.g. a window re-downloaded with --retry-failed after packing).

  python exportfiles.py pack FOLDER [FOLDER...]   pack every complete run found under the folders
"""
import argparse
import glob
import io
import json
import os
import sys
import time
import zipfile
from pathlib import Path

ZIP_NAME = "export.zip"


class Part:
    __slots__ = ("name", "size", "key", "_zip", "_path")

    def __init__(self, name, size, key, zip_path=None, path=None):
        self.name, self.size, self.key, self._zip, self._path = name, size, key, zip_path, path

    def open(self, newline=None, encoding="utf-8"):
        """Text stream of the part (utf-8-sig handled by the caller's encoding)."""
        if self._path:
            return open(self._path, encoding=encoding, newline=newline)
        z = zipfile.ZipFile(self._zip)
        raw = z.open(self.name)
        stream = io.TextIOWrapper(raw, encoding=encoding, newline=newline)
        stream._voyager_zip = z          # keep the archive open as long as the stream
        return stream


def parts(folder, ext):
    """Part files of a folder, oldest window first (part-0001 = earliest), loose files and zip members."""
    folder = str(folder)
    found = {}
    zp = os.path.join(folder, ZIP_NAME)
    if os.path.isfile(zp):
        try:
            with zipfile.ZipFile(zp) as z:
                for i in z.infolist():
                    if i.filename.startswith("part-") and i.filename.endswith("." + ext):
                        found[i.filename] = Part(i.filename, i.file_size, f"{zp}::{i.filename}", zip_path=zp)
        except zipfile.BadZipFile:
            print(f"WARNING: {zp} is damaged; reading only the loose part files", file=sys.stderr)
    for f in glob.glob(os.path.join(folder, f"part-*.{ext}")):
        n = os.path.basename(f)
        found[n] = Part(n, os.path.getsize(f), f, path=f)
    return [found[k] for k in sorted(found)]


def open_part(key, encoding="utf-8"):
    """Open a part by the key parts() gave it (a path, or 'zip::member')."""
    if "::" in key and not os.path.isfile(key):
        zp, member = key.split("::", 1)
        return Part(member, 0, key, zip_path=zp).open(encoding=encoding)
    return open(key, encoding=encoding)


def total_size(folder, ext):
    return sum(p.size for p in parts(folder, ext))


def pack(folder, log=print):
    """Move the loose part files of a complete run into export.zip (added to an existing one). Verified first."""
    folder = Path(folder)
    loose = sorted(folder.glob("part-*.*"))
    loose = [p for p in loose if p.suffix in (".jsonl", ".csv")]
    if not loose:
        return 0
    zp = folder / ZIP_NAME
    tmp = folder / (ZIP_NAME + ".tmp")
    before = sum(p.stat().st_size for p in loose)
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as out:
        names = {p.name for p in loose}
        if zp.is_file():                   # keep what is already packed, except names being replaced
            with zipfile.ZipFile(zp) as old:
                for i in old.infolist():
                    if i.filename not in names:
                        out.writestr(i, old.read(i.filename))
        for p in loose:
            out.write(p, p.name)
    with zipfile.ZipFile(tmp) as z:        # verify before deleting anything
        bad = z.testzip()
        sizes = {i.filename: i.file_size for i in z.infolist()}
    if bad or any(sizes.get(p.name) != p.stat().st_size for p in loose):
        tmp.unlink()
        raise RuntimeError(f"packing {folder} failed verification; the part files were left as they are")
    for i in range(40):                    # Windows: antivirus or an indexer may hold the file for a moment
        try:
            os.replace(tmp, zp)
            break
        except PermissionError:
            if i == 39:
                tmp.unlink()
                raise RuntimeError(f"{zp} is locked by another program; the part files were left as they are")
            time.sleep(0.25)
    left = []
    for p in loose:
        try:
            p.unlink()
        except OSError:
            left.append(p.name)            # a verified copy is in the zip; removed by the next pack
    if left:
        log(f"{len(left)} part file(s) could not be removed yet (in use); they are already in {zp.name}")
    after = zp.stat().st_size
    log(f"Packed {len(loose)} part file(s) into {zp} ({before / 1e6:,.1f} MB -> {after / 1e6:,.1f} MB)")
    return len(loose)


def complete(folder):
    """True when the folder's manifest says every window is done (or there is no manifest but there are parts)."""
    try:
        man = json.loads((Path(folder) / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    ws = man.get("windows") or []
    return bool(ws) and all(w.get("state") == "done" for w in ws)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pack", help="pack complete export runs found under the given folders")
    p.add_argument("folders", nargs="+")
    a = ap.parse_args()
    runs = sorted({str(m.parent) for f in a.folders for m in Path(f).rglob("manifest.json")})
    packed = skipped = 0
    for r in runs:
        if not complete(r):
            if list(Path(r).glob("part-*.*")):
                print(f"skipped (run not complete): {r}")
                skipped += 1
            continue
        try:
            packed += bool(pack(r))
        except (RuntimeError, OSError, zipfile.BadZipFile) as e:
            print(f"ERROR {r}: {e}")
    print(f"{packed} run(s) packed, {skipped} incomplete run(s) left as they are")


if __name__ == "__main__":
    main()
