#!/usr/bin/env python3
"""Throughput ladder and overload recovery for the sensor pipeline (not a pass/fail test).

For each offered rate it starts a real `panopticon-sensord` (default providers, a WAL, no Manager), drives a loopback
connection storm (`netstorm.py`; a connection is four network events), samples the pipeline while it runs, waits for the
backlog to drain and prints one row:

  offered/s     events per second the providers handed to the sensor during the load
  written/s     events per second that reached the WAL during the load
  peak_backlog  the most events the sensor had accepted from providers but not yet written (a proxy for queue depth:
                the sensor exposes no queue depth, and the record queue is only ever bounded by queue_capacity)
  drain_s       seconds after the load stopped until the backlog was empty (capped at 120)
  wal_MB/s      growth of the WAL while loaded
  cpu           CPU of the pipeline thread over the load
  rss_MiB       peak resident set
  gap / loss    gap = handed over - written - reported queue loss, which should be about 0 (the sensor writes a few
                records of its own); loss = what the sensor reported as lost, by stage

`--recover` runs a baseline, an unlimited overload and the baseline again on ONE sensor, to show that loss starts, is
reported, and stops when the load does.

It never signals a process it did not start, so it can run beside other sensors; it does, however, compete for CPU
and disk with them. Run as root, on a quiet VM, from a Release build.

usage: sudo python3 tests/perf/ladder.py [--seconds 20] [--rates 37,100,250,750,1500,3000] [--recover]
"""
import argparse
import glob
import json
import os
import re
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CLK = os.sysconf("SC_CLK_TCK")


class sensor:
    def __init__(self, sensord, ctl, work):
        self.ctl, self.work = ctl, work
        subprocess.run(["rm", "-rf", work], check=True)
        os.makedirs(work)
        host = open("/etc/machine-id").read().strip()
        with open(work + "/sensor.conf", "w") as conf:
            conf.write("sensor_id=perf-ladder\nhost_id=%s\nwal_path=%s/wal\nwal_quota_bytes=2147483648\n" % (host, work))
        self.log = open(work + "/sensord.log", "w")
        self.proc = subprocess.Popen([sensord, "--config", work + "/sensor.conf", "--control-socket", work + "/ctl.sock"],
                                     stdout=self.log, stderr=self.log)
        for _ in range(100):
            if os.path.exists(work + "/ctl.sock"):
                break
            time.sleep(0.1)
        time.sleep(3)

    def status(self):
        out = subprocess.run([self.ctl, "--socket", self.work + "/ctl.sock", "status"], capture_output=True, text=True).stdout
        data = json.loads(out)
        data = data.get("result", data)
        return {
            "records": data["totals"]["records"],
            "events": data["totals"]["events"],
            "loss_records": data["totals"].get("loss_records", 0),
            "provided": sum(p.get("events", 0) for p in data.get("providers", [])),
            "wal_bytes": data.get("resources", {}).get("wal_bytes", 0),
        }

    def cpu_ticks(self):
        # utime and stime are fields 14 and 15 of the whole line; after the ")" that closes the name they are 12 and 13.
        fields = open("/proc/%d/task/%d/stat" % (self.proc.pid, self.proc.pid)).read().rsplit(")", 1)[1].split()
        return int(fields[11]) + int(fields[12])

    def peak_rss_mib(self):
        for line in open("/proc/%d/status" % self.proc.pid):
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) // 1024
        return 0

    def stop(self):
        self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()

    def losses(self):
        totals = {}
        for path in sorted(glob.glob(self.work + "/wal/wal-*.log")):
            for match in re.finditer(rb'"stage":"([a-z_]+)","count":(\d+)', open(path, "rb").read()):
                stage = match.group(1).decode()
                totals[stage] = totals.get(stage, 0) + int(match.group(2))
        return totals


def storm(rate, seconds, procs, pin):
    command = (["taskset", "-c", pin] if pin else []) + [sys.executable, HERE + "/netstorm.py", "--rate", str(rate),
                                                         "--seconds", str(seconds), "--procs", str(procs)]
    return subprocess.Popen(command, stdout=subprocess.PIPE, text=True)


def drive(s, rate, seconds, procs, pin):
    """One loaded phase on a running sensor, then the drain. Returns its measurements."""
    base = s.status()
    t0_cpu, t0 = s.cpu_ticks(), time.time()
    load = storm(rate, seconds, procs, pin)
    peak = 0
    while load.poll() is None:
        time.sleep(1.0)
        now = s.status()
        peak = max(peak, (now["provided"] - base["provided"]) - (now["events"] - base["events"]))
    elapsed = time.time() - t0
    load_json = json.loads(load.stdout.read())
    cpu = (s.cpu_ticks() - t0_cpu) / CLK / max(elapsed, 1)
    ended = s.status()
    drained, quiet = None, 0
    for second in range(1, 121):
        time.sleep(1.0)
        now = s.status()
        peak = max(peak, (now["provided"] - base["provided"]) - (now["events"] - base["events"]))
        # Empty: everything the providers had handed over when the load ended is written (the sensor's own few
        # records, and the status calls this script makes, are within the tolerance), twice running.
        if (ended["provided"] - base["provided"]) - (now["events"] - base["events"]) <= 50:
            quiet += 1
            if quiet >= 2:
                drained = second
                break
        else:
            quiet = 0
    final = s.status()
    return {
        "conns_s": load_json["conns_per_s"], "errors": load_json["errors"], "elapsed": elapsed,
        "offered": (ended["provided"] - base["provided"]) / elapsed,
        "written": (ended["events"] - base["events"]) / elapsed,
        "peak_backlog": peak, "drain_s": drained if drained is not None else ">120",
        "wal_mb_s": (ended["wal_bytes"] - base["wal_bytes"]) / elapsed / 1e6,
        "cpu": cpu * 100, "provided": final["provided"] - base["provided"], "events": final["events"] - base["events"],
        "loss_records": final["loss_records"] - base["loss_records"],
    }


def row(label, m, losses):
    gap = m["provided"] - m["events"] - losses.get("queue", 0)
    print("%-8s %-10.0f %-10.0f %-12d %-8s %-9.1f %-5.0f%% %-8d gap=%-7d %s" % (
        label, m["offered"], m["written"], m["peak_backlog"], m["drain_s"], m["wal_mb_s"], m["cpu"], m["rss"], gap,
        ",".join("%s=%d" % item for item in sorted(losses.items())) or "none"), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sensord", default=os.environ.get("SENSORD", ROOT + "/build/panopticon-sensord"))
    ap.add_argument("--ctl", default=os.environ.get("CTL", ROOT + "/build/panopticon-ctl"))
    ap.add_argument("--work", default="/var/tmp/perf-ladder")
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--rates", default="37,100,250,750,1500,3000", help="connections per second (4 events each); 0 = unlimited")
    ap.add_argument("--procs", type=int, default=3)
    ap.add_argument("--pin", default=os.environ.get("PERF_LOAD_CPUS", ""), help="taskset list for the generator")
    ap.add_argument("--pause", type=int, default=65, help="seconds between steps (TIME_WAIT sockets)")
    ap.add_argument("--recover", action="store_true")
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root")
    for path in (args.sensord, args.ctl):
        if not os.access(path, os.X_OK):
            sys.exit("build first: " + path)

    print("%-8s %-10s %-10s %-12s %-8s %-9s %-6s %-8s %s" % (
        "target", "offered/s", "written/s", "peak_backlog", "drain_s", "wal_MB/s", "cpu", "rss_MiB", "gap / loss reported"))
    if args.recover:
        s = sensor(args.sensord, args.ctl, args.work)
        try:
            for label, rate in (("base", 37), ("overload", 0), ("recover", 37)):
                m = drive(s, rate, args.seconds, args.procs, args.pin)
                m["rss"] = s.peak_rss_mib()
                row(label, m, s.losses())
                if label == "overload":
                    time.sleep(args.pause)
        finally:
            s.stop()
        return
    for rate in [int(r) for r in args.rates.split(",")]:
        s = sensor(args.sensord, args.ctl, args.work)
        try:
            m = drive(s, rate, args.seconds, args.procs, args.pin)
            m["rss"] = s.peak_rss_mib()
            row(str(rate), m, s.losses())
        finally:
            s.stop()
        time.sleep(args.pause)


if __name__ == "__main__":
    main()
