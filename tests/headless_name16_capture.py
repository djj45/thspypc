#!/usr/bin/env python3
"""Keep x32dbg headless attached to hexin while a -cf script captures name_16_16."""
import argparse
import os
import subprocess
import sys
import time


def tail_state(stdout_path):
    try:
        with open(stdout_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return ""
    for line in reversed(lines):
        s = line.strip()
        if "[STATE]" in s:
            return s
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--script", required=True)
    ap.add_argument("--userdir", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--stdout", required=True)
    ap.add_argument("--headless", default=r"D:\software\x64dbg\release\x32\headless.exe")
    ap.add_argument("--plugin", default=r"D:\software\x64dbg\release\x32\plugins\ScyllaHideX64DBGPlugin.dp32")
    ap.add_argument("--timeout", type=int, default=900)
    args = ap.parse_args()

    os.makedirs(args.userdir, exist_ok=True)
    out = open(args.stdout, "w", encoding="utf-8", errors="replace")
    cmd = [
        args.headless,
        "-pid", str(args.pid),
        "-userdir", args.userdir,
        "-plugin", args.plugin,
        "-c", 'RedirectLog "{}"'.format(args.log),
        "-cf", args.script,
    ]
    print("spawn:", " ".join(cmd), file=out, flush=True)
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=out, stderr=subprocess.STDOUT)
    start = time.time()
    capture_ready = False
    last_resume = 0.0
    try:
        while time.time() - start < args.timeout:
            rc = proc.poll()
            if rc is not None:
                print("headless exited rc={}".format(rc), file=out, flush=True)
                return rc
            state = tail_state(args.stdout)
            if "CAPTURE_READY" in open(args.stdout, "r", encoding="utf-8", errors="replace").read():
                capture_ready = True
            if capture_ready and "paused" in state and time.time() - last_resume > 2.0:
                try:
                    proc.stdin.write(b"run\n")
                    proc.stdin.flush()
                    print("resumed at {}".format(time.strftime("%H:%M:%S")), file=out, flush=True)
                    last_resume = time.time()
                except Exception:
                    pass
            time.sleep(1)
        print("timeout reached, sending exit", file=out, flush=True)
    finally:
        try:
            proc.stdin.write(b"exit\n")
            proc.stdin.flush()
        except Exception:
            pass
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())