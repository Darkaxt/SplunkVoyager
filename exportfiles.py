"""Export folders: each finished window's part file is compressed into its own zip as soon as it is done
(part-0001.jsonl -> part-0001.jsonl.zip), so loose files never pile up during a long run. Runs packed by older
versions have one export.zip; both forms are read.

Readers go through parts() / open_part() and don't care which form a folder is in. Precedence for one name:
loose part file (e.g. a window downloaded again with --retry-failed) > its own zip > export.zip.

  python exportfiles.py pack FOLDER [FOLDER...]   compress the finished windows of every run under the folders
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
            if os.path.isfile(self._path) or not os.path.isfile(self._path + ".zip"):
                return open(self._path, encoding=encoding, newline=newline)
            self._zip = self._path + ".zip"      # compressed since it was listed
        z = zipfile.ZipFile(self._zip)
        raw = z.open(self.name)
        stream = io.TextIOWrapper(raw, encoding=encoding, newline=newline)
        stream._voyager_zip = z          # keep the archive open as long as the stream
        return stream


def _part_zips(folder, ext):
    for f in glob.glob(os.path.join(folder, f"part-*.{ext}.zip")):
        member = os.path.basename(f)[:-4]
        try:
            with zipfile.ZipFile(f) as z:
                yield member, z.getinfo(member).file_size, f
        except (zipfile.BadZipFile, KeyError, OSError):
            print(f"WARNING: {f} is damaged or not a part zip; skipped", file=sys.stderr)


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
    for member, size, f in _part_zips(folder, ext):
        found[member] = Part(member, size, f"{f}::{member}", zip_path=f)
    for f in glob.glob(os.path.join(folder, f"part-*.{ext}")):
        n = os.path.basename(f)
        found[n] = Part(n, os.path.getsize(f), f, path=f)
    return [found[k] for k in sorted(found)]


def open_part(key, encoding="utf-8"):
    """Open a part by the key parts() gave it (a path, or 'zip::member')."""
    if "::" not in key and not os.path.isfile(key) and os.path.isfile(key + ".zip"):
        key = f"{key}.zip::{os.path.basename(key)}"   # compressed since it was listed
    if "::" in key and not os.path.isfile(key):
        zp, member = key.split("::", 1)
        return Part(member, 0, key, zip_path=zp).open(encoding=encoding)
    return open(key, encoding=encoding)


def total_size(folder, ext):
    return sum(p.size for p in parts(folder, ext))


def pack_part(path, log=print):
    """Compress one finished part file into <name>.zip next to it, verified, then remove the loose file.
    Safe to call from several processes at once: the .tmp file is taken exclusively. Returns bytes saved or None."""
    path = Path(path)
    if not path.is_file():
        return None
    zp = path.with_name(path.name + ".zip")
    tmp = path.with_name(path.name + ".zip.tmp")
    try:
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        try:
            if time.time() - tmp.stat().st_mtime < 600:   # still being written
                return None                # being packed by someone else
            tmp.unlink()                   # left over by a crash
            fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except OSError:
            return None
    try:
        size = path.stat().st_size
        with os.fdopen(fd, "wb") as fh, zipfile.ZipFile(fh, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            z.write(path, path.name)
        with zipfile.ZipFile(tmp) as z:
            if z.testzip() is not None or z.getinfo(path.name).file_size != size or path.stat().st_size != size:
                raise RuntimeError(f"{zp.name} failed verification")
        for i in range(40):                # Windows: antivirus or an indexer may hold the file for a moment
            try:
                os.replace(tmp, zp)
                break
            except PermissionError:
                if i == 39:
                    raise RuntimeError(f"{zp} is locked by another program")
                time.sleep(0.25)
    except BaseException as e:
        try:
            tmp.unlink()
        except OSError:
            pass
        if isinstance(e, (RuntimeError, OSError, zipfile.BadZipFile)):
            log(f"Could not compress {path.name} ({e}); it stays as it is")
            return None
        raise
    for i in range(20):
        try:
            path.unlink()
            break
        except FileNotFoundError:
            break
        except OSError:                    # in use: the zip is complete and the loose copy wins until removed
            time.sleep(0.25)
    after = zp.stat().st_size
    log(f"Compressed {path.name} ({size / 1e6:,.1f} MB -> {after / 1e6:,.1f} MB)")
    return size - after


def pack_done(folder, log=print):
    """Compress the part files of every finished window of a run (retroactive for runs already under way)."""
    folder = Path(folder)
    try:
        man = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    n = 0
    for w in man.get("windows") or []:
        if w.get("state") == "done" and w.get("file") and (folder / w["file"]).is_file():
            n += pack_part(folder / w["file"], log) is not None
    return n


def sweep(root, log=print):
    """pack_done for every export run under root (Voyager runs this periodically)."""
    n = 0
    for m in Path(root).rglob("manifest.json"):
        if any(m.parent.glob("part-*.jsonl")) or any(m.parent.glob("part-*.csv")):
            n += pack_done(m.parent, log)
    return n


def pack(folder, log=print):
    """Compress all loose part files of a complete run, each into its own zip. Returns how many."""
    folder = Path(folder)
    loose = sorted(p for p in folder.glob("part-*.*") if p.suffix in (".jsonl", ".csv"))
    return sum(pack_part(p, log) is not None for p in loose)


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
    p = sub.add_parser("pack", help="compress the finished windows of the export runs under the given folders")
    p.add_argument("folders", nargs="+")
    a = ap.parse_args()
    runs = sorted({str(m.parent) for f in a.folders for m in Path(f).rglob("manifest.json")})
    files = 0
    for r in runs:
        files += pack_done(r)
    print(f"{files} part file(s) compressed in {len(runs)} run(s)")


if __name__ == "__main__":
    main()
