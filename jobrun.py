"""Runs one Voyager job: its steps in order, each a command line, output appended to log.txt.

Started detached by the web app (python jobrun.py JOB_DIR), so it keeps going when the web app
restarts. State lives in JOB_DIR/job.json; a job that is started again continues at the step it
stopped in (the exporter and the pivot seeding resume their own work from their manifests).
"""
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent


def now():
    return datetime.now().isoformat(timespec="seconds")


def read(path):
    for i in range(20):
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            time.sleep(0.2)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, data):
    path = Path(path)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    for i in range(40):  # Windows: antivirus or a reader can hold the file for a moment
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            time.sleep(0.25)
    path.write_text(tmp.read_text(encoding="utf-8"), encoding="utf-8")
    tmp.unlink(missing_ok=True)


def pid_alive(pid):
    if not pid:
        return False
    try:
        import psutil
        return psutil.pid_exists(int(pid))
    except ImportError:  # never os.kill(pid, 0) on Windows: it terminates the process
        return os.name != "nt" and _posix_alive(pid)


def _posix_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


class Job:
    def __init__(self, job_dir):
        self.dir = Path(job_dir)
        self.path = self.dir / "job.json"
        self.log = open(self.dir / "log.txt", "a", encoding="utf-8", buffering=1)
        self.child = None
        self.lock_path = None

    def update(self, **kv):
        d = read(self.path)
        d.update(kv)
        write(self.path, d)
        return d

    def say(self, msg):
        self.log.write(f"[{datetime.now():%H:%M:%S}] {msg}\n")

    def acquire(self, lock):
        """One job at a time per lock name in an investigation (e.g. jobs writing the same pivot case)."""
        self.lock_path = self.dir.parent.parent / f".{lock}.lock"
        told = False
        while True:
            try:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return
            except FileExistsError:
                try:
                    holder = int(self.lock_path.read_text() or 0)
                except (OSError, ValueError):
                    holder = 0
                if not pid_alive(holder):
                    self.lock_path.unlink(missing_ok=True)   # left by a job that died
                    continue
                if not told:
                    self.say(f"Waiting for another {lock} job of this investigation to finish...")
                    self.update(status="waiting")
                    told = True
                time.sleep(5)

    def release(self):
        if self.lock_path:
            try:
                if self.lock_path.read_text() == str(os.getpid()):
                    self.lock_path.unlink()
            except OSError:
                pass

    def stop(self, *_):
        if self.child and self.child.poll() is None:
            self.child.terminate()
        self.say("Stopped.")
        self.release()
        self.update(status="stopped", ended=now(), pid=None)
        sys.exit(1)

    def run(self):
        d = self.update(status="running", pid=os.getpid(), started=now(), ended=None, rc=None, error=None)
        for sig in (signal.SIGTERM, getattr(signal, "SIGBREAK", None)):
            if sig:
                signal.signal(sig, self.stop)
        if d.get("lock"):
            self.acquire(d["lock"])
            self.update(status="running")
        env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
        try:
            for i in range(d.get("step", 0), len(d["steps"])):
                st = d["steps"][i]
                self.update(step=i, step_started=time.time())
                self.say(f"== step {i + 1}/{len(d['steps'])}: {st['name']}")
                argv = [sys.executable if a == "{python}" else a for a in st["argv"]]
                self.child = subprocess.Popen(argv, cwd=st.get("cwd") or str(HERE), stdout=self.log,
                                              stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env)
                rc = self.child.wait()
                if rc != 0:
                    self.say(f"Step '{st['name']}' failed (exit {rc}).")
                    self.update(status="failed", rc=rc, ended=now(), pid=None,
                                error=f"step '{st['name']}' failed (exit {rc})")
                    return rc
            self.say("Done.")
            self.update(status="done", step=len(d["steps"]), rc=0, ended=now(), pid=None)
            return 0
        finally:
            self.release()


if __name__ == "__main__":
    sys.exit(Job(sys.argv[1]).run())
