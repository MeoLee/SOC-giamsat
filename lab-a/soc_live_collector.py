#!/usr/bin/env python3
"""Incremental SOC lab capture. Python 3.9+, standard library only.

Run BEFORE the scenario, leave Docker running, then Ctrl+C this collector.
Raw files preserve original bytes and contain only complete newline records.
This exports log events, not packets. It never deletes container logs.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

SOURCES = [
    ("auth", "ubuntu-endpoint", "/var/log/auth.log", "ubuntu-auth.log"),
    ("eve", "ubuntu-endpoint", "/var/log/suricata/eve.json", "suricata-eve.jsonl"),
    ("alerts", "single-node-wazuh.manager-1", "/var/ossec/logs/alerts/alerts.json", "wazuh-alerts.jsonl"),
]
CHUNK = 4 * 1024 * 1024
# Open once, then stat/read the same descriptor, including across rename.
READ_SCRIPT = r'''
exec 3< "$1" || exit 2
stat -Lc '%d:%i:%s' /proc/self/fd/3 || exit 3
dd if=/proc/self/fd/3 iflag=skip_bytes,count_bytes skip="$2" count="$3" status=none
'''


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def atomic_json(path, value):
    # Reuse the project's tested Windows atomic-write/retry implementation.
    from soc_ai.common import write_json
    write_json(path, value)


class Collector:
    def __init__(self, args):
        self.args = args
        self.docker = shutil.which(args.docker_command)
        if not self.docker:
            raise RuntimeError("Docker CLI not found. Start Docker Desktop and check docker version.")
        self.stop_at = None
        self.force_stop = False
        self.lock_file = None
        if args.resume:
            self.folder = Path(args.resume).resolve()
            self.acquire_lock()
            self.state = json.loads((self.folder / "checkpoint.json").read_text(encoding="utf-8"))
            if self.state.get("format") != "soc-capture/1.0":
                raise RuntimeError("Unsupported checkpoint format")
            if self.state.get("closed"):
                raise RuntimeError("Session already closed. Start a new session instead of --resume.")
            self.recover_outputs()
            self.state["resumed_at"].append(utc())
        else:
            tag = re.sub(r"[^a-zA-Z0-9._-]+", "-", args.scenario_id).strip(".-")[:64] or "session"
            stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            self.folder = Path(args.output_dir).resolve() / "raw" / (stamp + "-" + tag + "-" + uuid.uuid4().hex[:6])
            self.folder.mkdir(parents=True)
            self.acquire_lock()
            self.state = {
                "format": "soc-capture/1.0", "session_id": self.folder.name,
                "scenario_id": args.scenario_id, "scenario_id_is_ground_truth": False,
                "started_at_utc": utc(), "capture_mode": "from-start" if args.from_start else "new-events",
                "closed": False, "status": "initializing", "resumed_at": [],
                "sources": [], "gaps": [], "partials": [], "rotations": [],
            }
            for name, container, path, output in getattr(args, 'sources', SOURCES):
                cid = self.container_id(container)
                ident, size, _ = self.read(container, path, 0, 0)
                offset = 0 if args.from_start else size
                anchor = b""
                if offset:
                    ident2, _, anchor = self.read(container, path, max(0, offset - 64), min(64, offset))
                    if ident != ident2 or len(anchor) != min(64, offset):
                        raise RuntimeError("Log changed during initialization. Run collector again.")
                source = {
                    "name": name, "container": container, "container_id": cid,
                    "path": path, "output": output, "identity": ident,
                    "offset": offset, "initial_offset": offset, "output_bytes": 0,
                    "pending": "", "anchor": base64.b64encode(anchor).decode(),
                    "discard_fragment": bool(offset and anchor[-1:] != b"\n"),
                    "last_error": None, "last_ok_utc": utc(), "records": 0,
                }
                (self.folder / output).touch(exist_ok=False)
                self.state["sources"].append(source)
        self.state["status"] = "running"
        self.save()

    def acquire_lock(self):
        self.lock_file = (self.folder / ".collector.lock").open("a+b")
        self.lock_file.seek(0)
        if os.name == "nt":
            import msvcrt
            self.lock_file.write(b"0")
            self.lock_file.flush()
            self.lock_file.seek(0)
            try:
                msvcrt.locking(self.lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                self.lock_file.close()
                raise RuntimeError("Another collector is already using this session folder.")
        else:
            import fcntl
            try:
                fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                self.lock_file.close()
                raise RuntimeError("Another collector is already using this session folder.")

    def command(self, argv):
        kwargs = {"capture_output": True, "timeout": 15}
        # Isolate Docker children from the console's Ctrl+C; finish an in-flight read.
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        try:
            result = subprocess.run([self.docker] + argv, **kwargs)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Docker command timed out")
        except OSError as exc:
            raise RuntimeError("Cannot run Docker CLI: " + str(exc))
        if result.returncode:
            message = result.stderr.decode("utf-8", errors="replace").strip()[-700:]
            raise RuntimeError(message or "Docker command failed")
        return result.stdout

    def container_id(self, container):
        value = self.command(["inspect", "--type", "container", "--format", "{{.Id}}", container]).decode().strip()
        if not value:
            raise RuntimeError("Cannot resolve container " + container)
        return value

    def read(self, container, path, offset, count):
        raw = self.command(["exec", container, "sh", "-c", READ_SCRIPT, "soc-read", path, str(offset), str(count)])
        try:
            header, data = raw.split(b"\n", 1)
            dev, ino, size = header.decode("ascii").strip().split(":")
            return dev + ":" + ino, int(size), data
        except (ValueError, UnicodeError):
            raise RuntimeError("Invalid Docker reader response; GNU stat and dd are required in container")

    def save(self):
        self.state["checkpoint_at_utc"] = utc()
        atomic_json(self.folder / "checkpoint.json", self.state)
        # session.json is a readable manifest, not the crash-recovery journal.
        manifest = {k: v for k, v in self.state.items() if k != "sources"}
        manifest["sources"] = [{k: v for k, v in s.items() if k not in ("pending", "anchor")} for s in self.state["sources"]]
        atomic_json(self.folder / "session.json", manifest)

    def recover_outputs(self):
        for s in self.state["sources"]:
            path = self.folder / s["output"]
            expected = s["output_bytes"]
            actual = path.stat().st_size
            if actual < expected:
                raise RuntimeError("Captured file shorter than checkpoint: " + str(path))
            if actual > expected:
                recovery = path.with_name(path.name + ".uncommitted-" + uuid.uuid4().hex[:6])
                with path.open("r+b") as f, recovery.open("wb") as extra:
                    f.seek(expected)
                    shutil.copyfileobj(f, extra)
                    extra.flush()
                    os.fsync(extra.fileno())
                    f.truncate(expected)
                    f.flush()
                    os.fsync(f.fileno())
                print("Recovered uncommitted host bytes; source will be reread:", recovery.name, flush=True)

    def gap(self, s, reason):
        item = {"at_utc": utc(), "source": s["name"], "reason": reason, "offset": s["offset"], "identity": s["identity"]}
        self.state["gaps"].append(item)
        print("GAP:", s["name"], reason, flush=True)

    def finish_fragment(self, s, reason):
        if s["pending"]:
            self.state["partials"].append({"source": s["name"], "at_utc": utc(), "reason": reason, "bytes_base64": s["pending"]})
        s["pending"] = ""
        s["discard_fragment"] = False

    def reset_cursor(self, s, ident, cid):
        self.finish_fragment(s, "file-boundary")
        s.update(identity=ident, container_id=cid, offset=0, anchor="")

    def append(self, s, data):
        if not data:
            return
        previous_anchor = base64.b64decode(s["anchor"])
        next_anchor = base64.b64encode((previous_anchor + data)[-64:]).decode()
        next_offset = s["offset"] + len(data)
        if s["discard_fragment"]:
            boundary = data.find(b"\n")
            if boundary < 0:
                s.update(anchor=next_anchor, offset=next_offset)
                return
            data = data[boundary + 1:]
        combined = base64.b64decode(s["pending"]) + data
        end = combined.rfind(b"\n") + 1
        complete, pending = combined[:end], combined[end:]
        if len(pending) > 16 * 1024 * 1024:
            raise RuntimeError("A log record exceeded 16 MiB without a newline; stop and inspect the source")
        if complete:
            with (self.folder / s["output"]).open("ab") as f:
                f.write(complete)
                f.flush()
                os.fsync(f.fileno())
            s["output_bytes"] += len(complete)
            s["records"] += complete.count(b"\n")
        s.update(anchor=next_anchor, offset=next_offset, discard_fragment=False)
        s["pending"] = base64.b64encode(pending).decode()

    def old_path(self, s):
        dev, ino = s["identity"].split(":")
        parent = s["path"].rsplit("/", 1)[0]
        # Recover rename-based rotation, including Wazuh date subdirectories.
        found = self.command(["exec", s["container"], "find", parent, "-maxdepth", "5", "-type", "f", "-inum", ino, "-print0"])
        for value in found.split(b"\0"):
            if value:
                path = os.fsdecode(value)
                ident, _, _ = self.read(s["container"], path, 0, 0)
                if ident == dev + ":" + ino:
                    return path
        return None

    def poll_source(self, s, cid):
        anchor = base64.b64decode(s["anchor"])
        start = max(0, s["offset"] - len(anchor))
        ident, size, payload = self.read(s["container"], s["path"], start, len(anchor) + CHUNK)
        if cid != s["container_id"]:
            self.gap(s, "Container was recreated; continuity cannot be guaranteed")
            self.reset_cursor(s, ident, cid)
            ident, size, payload = self.read(s["container"], s["path"], 0, CHUNK)
        elif ident != s["identity"]:
            old = self.old_path(s)
            if old:
                # Bounded work: if old file has a backlog, drain it over several polls.
                old_ident, old_size, old_data = self.read(s["container"], old, s["offset"], CHUNK)
                if old_ident != s["identity"] or old_size < s["offset"]:
                    self.gap(s, "Rotated file changed before recovery")
                else:
                    self.append(s, old_data)
                    if s["offset"] < old_size:
                        return True
            else:
                self.gap(s, "Old inode unavailable after rotation (possibly compressed/deleted); unread tail may be missing")
            self.state["rotations"].append({"source": s["name"], "at_utc": utc(), "old_identity": s["identity"], "new_identity": ident})
            self.reset_cursor(s, ident, cid)
            ident2, size, payload = self.read(s["container"], s["path"], 0, CHUNK)
            if ident2 != ident:
                raise RuntimeError("Log rotated again while reading; retrying")
        elif size < s["offset"] or (anchor and payload[:len(anchor)] != anchor):
            self.gap(s, "Same inode was truncated/rewritten; continuity cannot be guaranteed")
            self.reset_cursor(s, ident, cid)
            ident, size, payload = self.read(s["container"], s["path"], 0, CHUNK)
        else:
            payload = payload[len(anchor):]
        self.append(s, payload)
        return s["offset"] < size

    def poll(self):
        containers = {}
        more = False
        for s in self.state["sources"]:
            try:
                name = s["container"]
                if name not in containers:
                    containers[name] = self.container_id(name)
                more = self.poll_source(s, containers[name]) or more
                if s["last_error"]:
                    print("RECOVERED:", s["name"], flush=True)
                s["last_error"] = None
                s["last_ok_utc"] = utc()
            except RuntimeError as exc:
                message = str(exc)
                if message != s["last_error"]:
                    print("RETRY:", s["name"], message, flush=True)
                s["last_error"] = message
            # Commit each source so a failure elsewhere cannot discard its progress.
            self.save()
        return more

    def on_signal(self, signum, frame):
        if self.stop_at is None:
            self.stop_at = time.monotonic() + self.args.grace
            print("\nSTOP requested: collecting late events for", self.args.grace, "seconds. Keep Docker running.", flush=True)
        else:
            self.force_stop = True
            print("\nSecond stop requested: closing with an incomplete-capture marker.", flush=True)

    def run(self):
        signal.signal(signal.SIGINT, self.on_signal)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, self.on_signal)
        print("SESSION:", self.folder, flush=True)
        print("READY: run your lab tests now. Ctrl+C HERE ends this capture session.", flush=True)
        while True:
            more = self.poll()
            now = time.monotonic()
            if self.force_stop or (self.stop_at is not None and now >= self.stop_at):
                break
            delay = 0.05 if more else (1.0 if self.stop_at is not None else self.args.interval)
            deadline = now + delay
            while time.monotonic() < deadline and not self.force_stop:
                if self.stop_at is not None:
                    deadline = min(deadline, time.monotonic() + 1.0, self.stop_at)
                time.sleep(0.1)
        for s in self.state["sources"]:
            self.finish_fragment(s, "session-end; incomplete line excluded from raw files")
        self.state["closed"] = True
        self.state["ended_at_utc"] = utc()
        incomplete = self.force_stop or more or any(s["last_error"] for s in self.state["sources"])
        self.state["status"] = "incomplete" if incomplete else ("degraded" if self.state["gaps"] or self.state["partials"] else "completed")
        self.state["sha256"] = {}
        for s in self.state["sources"]:
            digest = hashlib.sha256()
            with (self.folder / s["output"]).open("rb") as f:
                for block in iter(lambda: f.read(1024 * 1024), b""):
                    digest.update(block)
            self.state["sha256"][s["output"]] = digest.hexdigest()
        self.save()
        print("DONE:", self.state["status"], flush=True)
        for s in self.state["sources"]:
            print(" ", s["output"], "records=", s["records"], "bytes=", s["output_bytes"], flush=True)
        return 0 if self.state["status"] == "completed" else 2


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--output-dir", default=r"E:\SOC-Lab\dataset")
    p.add_argument("--scenario-id", default="unlabelled-session")
    p.add_argument("--interval", type=float, default=10.0)
    p.add_argument("--grace", type=float, default=8.0)
    p.add_argument("--from-start", action="store_true", help="Import current files from byte zero, including older events")
    p.add_argument("--resume", help="Resume an unclosed session folder from checkpoint")
    p.add_argument("--docker-command", default="docker", help=argparse.SUPPRESS)
    args = p.parse_args()
    if args.interval < 0.1 or args.grace < 0:
        p.error("interval must be >= 0.1 and grace >= 0")
    if args.resume and args.from_start:
        p.error("--resume cannot be combined with --from-start")
    collector = None
    try:
        collector = Collector(args)
        return collector.run()
    except (RuntimeError, OSError, ValueError) as exc:
        print("ERROR:", str(exc), file=sys.stderr)
        if collector and hasattr(collector, "state"):
            collector.state["status"] = "interrupted"
            collector.state["error"] = str(exc)
            collector.save()
            print("Resume with --resume", str(collector.folder), file=sys.stderr)
        return 1
    finally:
        if collector and collector.lock_file:
            collector.lock_file.close()


if __name__ == "__main__":
    sys.exit(main())
