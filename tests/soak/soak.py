#!/usr/bin/env python3
"""Multi-hour soak of panopticon-sensord under a mixed, realistic workload (reliability evidence).

usage (as root, through tests/soak/run_soak.sh):
  soak.py run --hours H --work DIR --sensord PATH --ctl PATH --signer PATH
  soak.py load [--scale F]              the workload alone (run by `run`, as a child process)
  soak.py analyze DIR [--warmup-minutes M]

What `run` does, all under DIR (default /var/tmp/soak):
  * a fake Manager (tests/e2e/fake_command_manager.py) over HTTPS on loopback: record ingest with strict acks,
    command delivery, a wire log (one line per request with the connection number, for reconnects);
  * the sensor with every provider on, response_mode=dry_run and an ES256 keyring, so the soak also carries
    real signed commands without any action taking effect;
  * the workload: process churn, loopback TCP (short and long-lived), DNS queries to a local responder, file
    churn under /var/tmp and /etc, sensitive-file reads, auth.log lines, real sudo, and a burst every 15 min;
  * faults on a schedule: a Manager outage of 90 s every 30 min, slow acks and dropped acks once an hour;
  * a signed command every 2 min against a long-lived victim, alternating COLLECT_PROCESS_INFO and KILL_PROCESS
    (dry run: the victim must still be alive at the end);
  * a signed local policy (ADR 032, `--no-policy` to leave it out) whose rules match the workload, republished every
    2 min as a new version, every fifth time as an older signed version that must be refused as a rollback; the report
    accounts for each publish and checks that every match follows the record it is about;
  * a sample every 30 s to samples.ndjson: RSS, peak RSS, fds, threads, CPU, WAL bytes, the full status reply,
    and the workload's own counters.
At the end it drains, stops the sensor gracefully, checks the store with tests/chaos/analyze.py and writes
report.txt and report.json with `analyze`.
"""
import argparse
import datetime
import json
import os
import random
import signal
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
TOKEN = "soak-token-0123456789abcdef"
AGENT = "soak-agent"
PORT = 18563
DNS_ADDRESS = "127.0.0.77"  # all of 127/8 is local on Linux; nothing leaves the host
SAMPLE_SECONDS = 30
COMMAND_SECONDS = 120
POLICY_SECONDS = 120
HEALTH_SECONDS = 10


# ---- workload --------------------------------------------------------------------------------------------------

class Counters:
    def __init__(self):
        self.lock = threading.Lock()
        self.values = {}

    def add(self, name, amount=1):
        with self.lock:
            self.values[name] = self.values.get(name, 0) + amount

    def snapshot(self):
        with self.lock:
            return dict(self.values)


def paced(rate, stop, body, counters, name):
    """Calls body() about rate() times a second until stop is set."""
    next_time = time.monotonic()
    while not stop.is_set():
        current = rate()
        if current <= 0:
            time.sleep(0.5)
            next_time = time.monotonic()
            continue
        try:
            body()
        except Exception:  # noqa: BLE001 - a failed operation is counted, the workload keeps going
            counters.add(name + "_failed")
        next_time += 1.0 / current
        delay = next_time - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        elif delay < -2.0:
            next_time = time.monotonic()  # fell behind (burst or slow host): do not try to catch up


PROGRAMS = [
    (["/bin/true"], 30),
    (["/bin/sh", "-c", "echo soak $$ | wc -c"], 15),
    (["/usr/bin/env"], 10),
    (["/bin/ls", "-la", "/usr/bin"], 8),
    (["/usr/bin/id"], 10),
    (["/bin/date", "+%s"], 10),
    (["/bin/cat", "/proc/loadavg"], 10),
    (["/usr/bin/stat", "/etc/hostname"], 5),
    (["/usr/bin/python3", "-c", "pass"], 2),
]


def run_quiet(argv):
    with open(os.devnull, "wb") as null:
        subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=null, stderr=null, timeout=30, check=False)


def load(args):
    stop = threading.Event()
    counters = Counters()
    scale = args.scale
    burst = {"on": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    population = [program for program, weight in PROGRAMS for _ in range(weight)]

    def exec_rate():
        return (300.0 if burst["on"] else 15.0) * scale

    def spawn():
        run_quiet(random.choice(population))
        counters.add("exec")

    # Loopback TCP: a server that echoes; short connections plus ten long-lived ones renewed every 5 min.
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(512)
    port = server.getsockname()[1]

    def echo(peer):
        try:
            while True:
                data = peer.recv(4096)
                if not data:
                    break
                peer.sendall(data)
        except OSError:
            pass
        finally:
            peer.close()

    def serve():
        while not stop.is_set():
            try:
                peer, _ = server.accept()
            except OSError:
                return
            threading.Thread(target=echo, args=(peer,), daemon=True).start()

    def tcp_rate():
        return (300.0 if burst["on"] else 8.0) * scale

    def connect():
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        client.sendall(b"x" * 200)
        client.recv(200)
        client.close()
        counters.add("tcp")

    def long_lived():
        held = []
        while not stop.is_set():
            for client in held:
                client.close()
            held = []
            for _ in range(10):
                try:
                    held.append(socket.create_connection(("127.0.0.1", port), timeout=5))
                except OSError:
                    counters.add("tcp_long_failed")
            counters.add("tcp_long_cycle")
            stop.wait(300)
        for client in held:
            client.close()

    # DNS: unique names to a local responder that answers NXDOMAIN.
    responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    responder.bind((DNS_ADDRESS, 53))

    def answer():
        while not stop.is_set():
            try:
                data, peer = responder.recvfrom(512)
            except OSError:
                return
            if len(data) >= 12:
                flags = struct.pack("!H", 0x8183)  # response, recursion desired and available, NXDOMAIN
                responder.sendto(data[:2] + flags + data[4:6] + b"\0\0\0\0\0\0" + data[12:], peer)

    sequence = {"n": 0}

    def query():
        sequence["n"] += 1
        labels = ["h%d-%d" % (os.getpid(), sequence["n"]), random.choice(["api", "cdn", "update", "telemetry"]), "soak", "test"]
        question = b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\0" + struct.pack("!HH", 1, 1)
        message = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0) + question
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2)
        try:
            client.sendto(message, (DNS_ADDRESS, 53))
            client.recvfrom(512)
        except OSError:
            counters.add("dns_unanswered")
        finally:
            client.close()
        counters.add("dns")

    # File churn: create, write, rename, read, delete; at most 200 names.
    churn = "/var/tmp/soak-files"
    os.makedirs(churn, exist_ok=True)

    def file_op():
        path = os.path.join(churn, "f%03d" % random.randint(0, 199))
        with open(path, "wb") as handle:
            handle.write(os.urandom(4096))
        os.rename(path, path + ".r")
        with open(path + ".r", "rb") as handle:
            handle.read()
        os.unlink(path + ".r")
        counters.add("file")

    def slow_cycle():
        tick = 0
        while not stop.wait(15):
            tick += 1
            try:
                # An auth.log line as sshd writes it (user name and address are attacker-chosen in reality).
                run_quiet(["logger", "-p", "authpriv.warning", "-t", "sshd[%d]" % os.getpid(),
                           "Failed password for invalid user soak%d from 203.0.113.%d port %d ssh2" % (tick, tick % 250 + 1, 40000 + tick % 20000)])
                counters.add("auth_line")
                if tick % 2 == 0:
                    with open("/etc/shadow", "rb") as handle:
                        handle.read(64)
                    counters.add("sensitive_read")
                if tick % 4 == 0:
                    path = "/etc/panopticon-soak.conf"
                    with open(path, "w", encoding="utf-8") as handle:
                        handle.write("soak %d\n" % tick)
                    with open(path, "a", encoding="utf-8") as handle:
                        handle.write("more\n")
                    os.unlink(path)
                    counters.add("etc_change")
                if tick % 8 == 0:
                    run_quiet(["sudo", "-u", "nobody", "/bin/true"])
                    counters.add("sudo")
            except Exception:  # noqa: BLE001
                counters.add("slow_cycle_failed")

    def bursts():
        while not stop.wait(900):
            burst["on"] = True
            counters.add("burst")
            stop.wait(45)
            burst["on"] = False

    threads = [threading.Thread(target=serve, daemon=True), threading.Thread(target=answer, daemon=True),
               threading.Thread(target=long_lived, daemon=True), threading.Thread(target=slow_cycle, daemon=True),
               threading.Thread(target=bursts, daemon=True)]
    for _ in range(4):
        threads.append(threading.Thread(target=paced, args=(lambda: exec_rate() / 4, stop, spawn, counters, "exec"), daemon=True))
    for _ in range(2):
        threads.append(threading.Thread(target=paced, args=(lambda: tcp_rate() / 2, stop, connect, counters, "tcp"), daemon=True))
    threads.append(threading.Thread(target=paced, args=(lambda: 3.0 * scale, stop, query, counters, "dns"), daemon=True))
    threads.append(threading.Thread(target=paced, args=(lambda: 10.0 * scale, stop, file_op, counters, "file"), daemon=True))
    for thread in threads:
        thread.start()
    while not stop.wait(10):
        print(json.dumps({"t": time.time(), "burst": burst["on"], "counts": counters.snapshot()}), flush=True)
    server.close()
    responder.close()
    print(json.dumps({"t": time.time(), "final": True, "counts": counters.snapshot()}), flush=True)


# ---- run -------------------------------------------------------------------------------------------------------

def utc(offset):
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Soak:
    def __init__(self, args):
        self.args = args
        self.work = args.work
        self.manager = None
        self.sensor = None
        self.loader = None
        self.log = open(os.path.join(self.work, "soak.log"), "a", encoding="utf-8", buffering=1)

    def say(self, text):
        line = "[soak %s] %s" % (time.strftime("%H:%M:%S"), text)
        print(line, flush=True)
        self.log.write(line + "\n")

    def path(self, name):
        return os.path.join(self.work, name)

    def setup(self):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3", "-subj", "/CN=127.0.0.1",
                        "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", self.path("key.pem"), "-out", self.path("cert.pem")],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open("/etc/machine-id", encoding="utf-8") as handle:
            self.host = handle.read().strip().replace("-", "")
        with open(self.path("identity.json"), "w", encoding="utf-8") as handle:
            handle.write("%s\n%s\n%s\n" % (AGENT, self.host, TOKEN))
        os.chmod(self.path("identity.json"), 0o600)
        keyline = subprocess.run([self.args.signer, "keygen", self.path("signing.key")], check=True, capture_output=True, text=True).stdout.strip()
        with open(self.path("keyring"), "w", encoding="utf-8") as handle:
            handle.write(keyline.rsplit(" ", 1)[0] + " soak-signing-key\n")
        for name, text in (("mode", "ok\n"), ("commands.ndjson", ""), ("events.ndjson", ""), ("redeliver", "no\n")):
            with open(self.path(name), "w", encoding="utf-8") as handle:
                handle.write(text)
        lines = [
            "sensor_id=soak-sensor", "host_id=" + self.host, "wal_path=" + self.path("wal"),
            "manager_url=https://127.0.0.1:%d" % PORT, "identity_path=" + self.path("identity.json"),
            "ca_bundle=" + self.path("cert.pem"), "health_interval_seconds=%d" % HEALTH_SECONDS, "state_interval_seconds=600",
            "response_mode=dry_run", "response_actions=KILL_PROCESS,COLLECT_PROCESS_INFO", "response_poll_seconds=5",
            "response_signing_keys=" + self.path("keyring"), "response_ledger_path=" + self.path("ledger"),
        ]
        if self.args.policy:
            policy_line = subprocess.run([self.args.signer, "keygen", self.path("policy.key")], check=True, capture_output=True, text=True).stdout.strip()
            with open(self.path("policy.keys"), "w", encoding="utf-8") as handle:
                handle.write(policy_line.rsplit(" ", 1)[0] + " soak-policy-key\n")
            os.chmod(self.path("policy.keys"), 0o644)
            self.policy_version = 0
            self.publish_policy("good")
            lines += ["policy_path=" + self.path("policy"), "policy_signing_keys=" + self.path("policy.keys"), "policy_check_seconds=10"]
        with open(self.path("sensor.conf"), "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    # The policy is rewritten every few minutes under load: a new version (loaded as `updated`), and every fifth time an
    # older, validly signed one (refused as `rollback`, the policy in force stays). Rules match the workload's real
    # processes and DNS names, so match records are produced throughout. It never causes an action.
    POLICY_RULES = ("rule soak-id process.exec exe prefix alert low /usr/bin/id\n"
                    "rule soak-echo * cmdline contains alert low echo soak\n"
                    "rule soak-dns dns.query dest_domain ioc alert low\n"
                    "ioc dest_domain soak.test\n")

    def publish_policy(self, kind):
        if kind == "good":
            self.policy_version += 1
            version = self.policy_version
        else:
            version = max(1, self.policy_version - 1)
        body = self.POLICY_RULES + ("rule soak-date process.exec exe prefix alert low /usr/bin/date\n" if version % 2 else "")
        signed = subprocess.run([self.args.signer, "sign-policy", self.path("policy.key"), "soak-policy", str(version), str(int(time.time()) - 30), str(int(time.time()) + 1800), "all"],
                                input=body, capture_output=True, text=True, check=True).stdout
        with open(self.path("policy.new"), "w", encoding="utf-8") as handle:
            handle.write(signed)
        os.chmod(self.path("policy.new"), 0o644)
        os.replace(self.path("policy.new"), self.path("policy"))
        with open(self.path("policy.sent"), "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"t": time.time(), "version": version, "kind": kind}) + "\n")

    def start_manager(self):
        self.manager = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "tests", "e2e", "fake_command_manager.py"), "--port", str(PORT),
             "--cert", self.path("cert.pem"), "--key", self.path("key.pem"), "--store", self.path("store.ndjson"),
             "--mode-file", self.path("mode"), "--token", TOKEN, "--commands", self.path("commands.ndjson"),
             "--events", self.path("events.ndjson"), "--redeliver-file", self.path("redeliver"), "--wire-log", self.path("wire.ndjson"),
             "--compact-store"],
            stdout=open(self.path("manager.log"), "a"), stderr=subprocess.STDOUT)
        for _ in range(600):
            try:
                socket.create_connection(("127.0.0.1", PORT), timeout=1).close()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("manager did not start")

    def stop_manager(self):
        if self.manager:
            self.manager.kill()
            self.manager.wait()
            self.manager = None

    # An outage is the Manager's port refusing connections and resetting the open one (tcp-reset), as when the
    # Manager host is down; the fake Manager keeps running so it never has to reload a multi-hour store.
    OUTAGE_RULE = ["INPUT", "-p", "tcp", "--dport", str(PORT), "-j", "REJECT", "--reject-with", "tcp-reset"]

    def outage(self, on):
        subprocess.run(["iptables", "-I" if on else "-D"] + self.OUTAGE_RULE, check=on, stderr=subprocess.DEVNULL)

    def cleanup(self):
        self.outage(False)
        for process in (self.loader, self.sensor):
            if process and process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
        self.stop_manager()
        if getattr(self, "victim_process", None) and self.victim_process.poll() is None:
            self.victim_process.kill()

    def start_sensor(self):
        self.sensor = subprocess.Popen([self.args.sensord, "--config", self.path("sensor.conf"), "--control-socket", self.path("ctl.sock")],
                                       stdout=open(self.path("sensord.log"), "a"), stderr=subprocess.STDOUT)
        for _ in range(300):
            if os.path.exists(self.path("ctl.sock")):
                return
            time.sleep(0.1)
        raise RuntimeError("sensor did not start")

    def status(self):
        try:
            text = subprocess.run([self.args.ctl, "--socket", self.path("ctl.sock"), "status"], capture_output=True, text=True, timeout=10).stdout
            value = json.loads(text)
            return value.get("result", value) if isinstance(value, dict) else None
        except (ValueError, subprocess.SubprocessError, OSError):
            return None

    def victim(self):
        process = subprocess.Popen(["sleep", "1000000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open("/proc/%d/stat" % process.pid, encoding="utf-8") as handle:
            ticks = int(handle.read().rsplit(")", 1)[1].split()[19])
        return process, ticks

    def command(self, number, victim, ticks):
        action = "COLLECT_PROCESS_INFO" if number % 2 == 0 else "KILL_PROCESS"
        identifier = "soak-%05d" % number
        body = json.dumps({"command_id": identifier, "schema_version": "1", "agent_id": AGENT, "action": action,
                           "expires_at": utc(300), "target": {"pid": victim.pid, "start_time_ticks": ticks},
                           "correlation_id": "corr-" + identifier, "host_id": self.host, "created_at": utc(0)}, separators=(",", ":"))
        signed = subprocess.run([self.args.signer, "sign", self.path("signing.key")], input=body, capture_output=True, text=True, check=True).stdout.strip()
        with open(self.path("commands.ndjson"), "a", encoding="utf-8") as handle:
            handle.write(signed + "\n")
        with open(self.path("commands.sent"), "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"t": time.time(), "id": identifier, "action": action}) + "\n")

    def sample(self, loader_log):
        pid = self.sensor.pid
        row = {"t": time.time(), "alive": self.sensor.poll() is None}
        try:
            with open("/proc/%d/status" % pid, encoding="utf-8") as handle:
                for line in handle:
                    key, _, value = line.partition(":")
                    if key in ("VmRSS", "VmHWM"):
                        row[key.lower() + "_kb"] = int(value.split()[0])
                    elif key == "Threads":
                        row["threads"] = int(value)
            row["fds"] = len(os.listdir("/proc/%d/fd" % pid))
            with open("/proc/%d/stat" % pid, encoding="utf-8") as handle:
                fields = handle.read().rsplit(")", 1)[1].split()
            row["cpu_ticks"] = int(fields[11]) + int(fields[12])
        except (OSError, ValueError, IndexError):
            pass
        wal = 0
        if os.path.isdir(self.path("wal")):
            for name in os.listdir(self.path("wal")):
                try:
                    wal += os.path.getsize(os.path.join(self.path("wal"), name))
                except OSError:
                    pass
        row["wal_disk_bytes"] = wal
        row["status"] = self.status()
        try:
            with open(loader_log, "rb") as handle:
                handle.seek(max(0, os.path.getsize(loader_log) - 4096))
                lines = handle.read().decode("utf-8", "replace").strip().splitlines()
            row["load"] = json.loads(lines[-1])["counts"] if lines else {}
        except (OSError, ValueError, KeyError, IndexError):
            pass
        with open(self.path("samples.ndjson"), "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row) + "\n")
        return row

    def set_mode(self, text):
        with open(self.path("mode"), "w", encoding="utf-8") as handle:
            handle.write(text + "\n")

    def run(self):
        try:
            return self.soak()
        finally:
            self.cleanup()

    def soak(self):
        hours = self.args.hours
        self.setup()
        self.outage(False)  # a rule left by an interrupted earlier run
        self.start_manager()
        self.start_sensor()
        victim, ticks = self.victim()
        self.victim_process = victim
        loader_log = self.path("load.ndjson")
        self.loader = subprocess.Popen([sys.executable, os.path.abspath(__file__), "load", "--scale", str(self.args.scale)],
                                       stdout=open(loader_log, "a"), stderr=open(self.path("load.err"), "a"))
        self.say("sensor %d, manager %d, load %d, victim %d; %.2f h" % (self.sensor.pid, self.manager.pid, self.loader.pid, victim.pid, hours))
        start = time.time()
        end = start + hours * 3600.0
        next_sample = start
        next_command = start + 60
        next_policy = start + POLICY_SECONDS
        publishes = 0
        commands = 0
        faults = []
        outage_until = None
        mode_until = None
        last_minute = -1
        stopped_early = False
        while time.time() < end:
            now = time.time()
            minute = int((now - start) // 60)
            if minute != last_minute:
                last_minute = minute
                if minute % 30 == 15 and not outage_until:
                    self.outage(True)
                    outage_until = now + 90
                    faults.append((now, "outage"))
                    self.say("manager outage (90 s)")
                if minute % 60 == 40:
                    self.set_mode("slow 3")
                    mode_until = now + 120
                    faults.append((now, "slow"))
                    self.say("slow acks (120 s)")
                if minute % 60 == 50:
                    self.set_mode("drop_ack 3")
                    mode_until = now + 60
                    faults.append((now, "drop_ack"))
                    self.say("three dropped acks")
            if outage_until and now >= outage_until:
                self.outage(False)
                outage_until = None
                self.say("manager back")
            if mode_until and now >= mode_until:
                self.set_mode("ok")
                mode_until = None
            if self.args.policy and now >= next_policy:
                publishes += 1
                rollback = publishes % 5 == 0
                self.publish_policy("rollback" if rollback else "good")
                if rollback:
                    faults.append((now, "policy_reject"))  # health says degraded until the next accepted version
                next_policy += POLICY_SECONDS
            if now >= next_command:
                self.command(commands, victim, ticks)
                commands += 1
                next_command += COMMAND_SECONDS
            if now >= next_sample:
                row = self.sample(loader_log)
                next_sample += SAMPLE_SECONDS
                if not row["alive"]:
                    self.say("SENSOR EXITED with %s; stopping the soak" % self.sensor.returncode)
                    stopped_early = True
                    break
            time.sleep(1)
        self.loader.send_signal(signal.SIGTERM)
        try:
            self.loader.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.loader.kill()
        self.outage(False)
        self.set_mode("ok")
        drained = False
        for _ in range(180):
            if self.sensor.poll() is not None:
                break
            wal = (self.status() or {}).get("wal", {})
            if wal and wal.get("durable_seq", 0) - wal.get("acknowledged_seq", 0) <= 8:
                drained = True
                break
            time.sleep(1)
        self.sample(loader_log)
        self.say("drained=%s; stopping the sensor" % drained)
        alive_at_end = victim.poll() is None
        if self.sensor.poll() is None:
            self.sensor.send_signal(signal.SIGINT)
            try:
                self.sensor.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.sensor.kill()
                self.say("sensor did not stop within 30 s")
        exit_code = self.sensor.wait()
        time.sleep(2)
        self.stop_manager()
        victim.kill()
        with open(self.path("run.json"), "w", encoding="utf-8") as handle:
            json.dump({"start": start, "end": time.time(), "hours": hours, "stopped_early": stopped_early, "commands_sent": commands,
                       "victim_alive_at_end": alive_at_end, "drained": drained, "sensor_exit_code": exit_code, "faults": faults}, handle)
        integrity = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "chaos", "analyze.py"), self.path("store.ndjson"), "--json"],
                                   capture_output=True, text=True)
        with open(self.path("integrity.json"), "w", encoding="utf-8") as handle:
            handle.write(integrity.stdout)
        self.say("store integrity exit %d" % integrity.returncode)
        analyze(argparse.Namespace(work=self.work, warmup_minutes=self.args.warmup_minutes))


# ---- analyze ---------------------------------------------------------------------------------------------------

def parse_time(text):
    return datetime.datetime.strptime(text[:26].rstrip("Z"), "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=datetime.timezone.utc).timestamp()


def slope_per_hour(points):
    if len(points) < 3:
        return 0.0
    mean_x = statistics.fmean(x for x, _ in points)
    mean_y = statistics.fmean(y for _, y in points)
    denominator = sum((x - mean_x) ** 2 for x, _ in points)
    if denominator == 0:
        return 0.0
    return sum((x - mean_x) * (y - mean_y) for x, y in points) / denominator * 3600.0


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(fraction * len(ordered)))]


def read_ndjson(path):
    rows = []
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
    return rows


def analyze(args):
    work = args.work
    samples = read_ndjson(os.path.join(work, "samples.ndjson"))
    run = json.load(open(os.path.join(work, "run.json"), encoding="utf-8")) if os.path.exists(os.path.join(work, "run.json")) else {}
    start = samples[0]["t"]
    warm = start + args.warmup_minutes * 60
    steady = [row for row in samples if row["t"] >= warm and "vmrss_kb" in row]
    report = {"duration_hours": round((samples[-1]["t"] - start) / 3600.0, 2), "samples": len(samples), "warmup_minutes": args.warmup_minutes}
    lines = ["Soak report for %s" % work, "duration %.2f h, %d samples, warm-up %d min excluded from trends" %
             (report["duration_hours"], len(samples), args.warmup_minutes)]

    def trend(name, key, scale=1.0, unit=""):
        points = [((row["t"] - start), row[key] * scale) for row in steady if key in row]
        if not points:
            return
        values = [y for _, y in points]
        half = points[len(points) // 2:]
        entry = {"first": round(values[0], 2), "min": round(min(values), 2), "max": round(max(values), 2), "last": round(values[-1], 2),
                 "slope_per_hour": round(slope_per_hour(points), 3), "slope_per_hour_second_half": round(slope_per_hour(half), 3)}
        report[name] = entry
        lines.append("%-13s first %s  min %s  max %s  last %s%s; slope %+.3f%s/h (second half %+.3f%s/h)" %
                     (name, entry["first"], entry["min"], entry["max"], entry["last"], unit, entry["slope_per_hour"], unit,
                      entry["slope_per_hour_second_half"], unit))

    trend("rss_mib", "vmrss_kb", 1 / 1024.0, " MiB")
    trend("fds", "fds")
    trend("threads", "threads")
    trend("wal_disk_mib", "wal_disk_bytes", 1 / 1048576.0, " MiB")
    report["peak_rss_mib"] = round(max(row.get("vmhwm_kb", 0) for row in samples) / 1024.0, 1)
    lines.append("peak RSS (VmHWM) %.1f MiB" % report["peak_rss_mib"])

    ticks_per_second = os.sysconf("SC_CLK_TCK")
    cpu_rows = [row for row in samples if "cpu_ticks" in row]
    if len(cpu_rows) > 1:
        overall = (cpu_rows[-1]["cpu_ticks"] - cpu_rows[0]["cpu_ticks"]) / ticks_per_second / (cpu_rows[-1]["t"] - cpu_rows[0]["t"]) * 100
        hourly = []
        for hour in range(int((cpu_rows[-1]["t"] - start) // 3600) + 1):
            rows = [row for row in cpu_rows if start + hour * 3600 <= row["t"] < start + (hour + 1) * 3600]
            if len(rows) > 1:
                hourly.append(round((rows[-1]["cpu_ticks"] - rows[0]["cpu_ticks"]) / ticks_per_second / (rows[-1]["t"] - rows[0]["t"]) * 100, 2))
        report["cpu_percent_of_one_core"] = {"overall": round(overall, 2), "per_hour": hourly}
        lines.append("CPU %.2f%% of one core overall; per hour %s" % (overall, hourly))

    statuses = [(row["t"], row["status"]) for row in samples if row.get("status")]
    if len(statuses) > 1:
        first, last = statuses[0][1], statuses[-1][1]
        span = statuses[-1][0] - statuses[0][0]
        events = last["totals"]["events"] - first["totals"]["events"]
        records = last["totals"]["records"] - first["totals"]["records"]
        report["events_per_second"] = round(events / span, 1)
        report["records_per_second"] = round(records / span, 1)
        report["events_total"] = last["totals"]["events"]
        report["loss_records_total"] = last["totals"]["loss_records"]
        report["sink_errors"] = last["totals"]["sink_errors"]
        lines.append("events %d (%.1f/s), records %.1f/s, loss records %d, sink errors %d" %
                     (events, events / span, records / span, last["totals"]["loss_records"], last["totals"]["sink_errors"]))
        report["providers"] = {p["name"]: {"state": p["state"], "events": p["events"], "drops": p["drops"]} for p in last["providers"]}
        lines.append("providers at end: " + ", ".join("%s=%s ev=%d drops=%d" % (name, value["state"], value["events"], value["drops"])
                                                      for name, value in report["providers"].items()))
        # A provider on standby (superseded by a preferred member of its family) is working as designed. A state other
        # than active while an injected fault is in force (plus a minute to recover) is expected and reported apart;
        # only the rest counts against the verdict.
        fault_seconds = {"outage": 90, "slow": 120, "drop_ack": 60}
        windows = [(t, t + fault_seconds.get(kind, 120) + 60) for t, kind in run.get("faults", [])]
        degraded, during_faults, standby = {}, {}, {}
        for t, status in statuses:
            for provider in status["providers"]:
                if provider["state"] == "active":
                    continue
                if provider["state"] == "standby":
                    standby[provider["name"]] = provider["reason"]
                    continue
                bucket = during_faults if any(begin <= t <= end for begin, end in windows) else degraded
                entry = bucket.setdefault(provider["name"], {"samples": 0, "first": t, "last": t, "reasons": set()})
                entry["samples"] += 1
                entry["last"] = t
                entry["reasons"].add(provider["state"] + ": " + provider["reason"])

        def summary(bucket):
            return {name: {"samples": value["samples"], "of": len(statuses), "first_minute": round((value["first"] - start) / 60, 1),
                           "last_minute": round((value["last"] - start) / 60, 1), "reasons": sorted(value["reasons"])}
                    for name, value in bucket.items()}

        report["provider_not_active"] = summary(degraded)
        report["provider_not_active_during_faults"] = summary(during_faults)
        report["provider_standby"] = standby
        lines.append("providers on standby (superseded): %s" % (", ".join(sorted(standby)) or "none"))
        lines.append("providers not active during injected faults (expected): %s" % (report["provider_not_active_during_faults"] or "none"))
        lines.append("providers not active outside faults: %s" % (report["provider_not_active"] or "none"))
        delivery = last.get("delivery", {})
        report["delivery"] = {key: delivery.get(key) for key in ("state", "batches_sent", "records_acknowledged", "retries", "refusals",
                                                                  "records_quarantined", "quarantine_failures")}
        report["delivery"]["max_consecutive_failures"] = max(status.get("delivery", {}).get("consecutive_failures", 0) for _, status in statuses)
        lags = [status["wal"]["durable_seq"] - status["wal"]["acknowledged_seq"] for _, status in statuses]
        report["delivery"]["max_unacknowledged_records"] = max(lags)
        report["delivery"]["unacknowledged_at_end"] = lags[-1]
        report["wal_dropped_records"] = last["wal"]["dropped_records"]
        lines.append("delivery %s" % report["delivery"])
        lines.append("WAL dropped records (quota) %d" % last["wal"]["dropped_records"])

    # Reconnects: every new TLS connection the Manager accepted (the sensor reuses one while it can). The
    # connection counter restarts with each Manager process, so connections are counted per process run.
    wire = read_ndjson(os.path.join(work, "wire.ndjson"))
    if wire:
        runs, previous, connections = 0, None, 0
        seen = set()
        for row in wire:
            conn = row.get("conn", 0)
            if previous is not None and conn < previous:
                runs += 1
                seen = set()
            if conn not in seen:
                seen.add(conn)
                connections += 1
            previous = conn
        report["manager_requests"] = len(wire)
        report["sensor_connections"] = connections
        report["manager_restarts_seen"] = runs
        lines.append("ingest requests %d; TLS connections %d over %d Manager restarts" % (len(wire), connections, runs))

    loss = {}
    health_times = []
    latency = {}
    policy_changes, policy_matches, policy_misordered = {}, {}, 0
    for row in read_ndjson(os.path.join(work, "store.ndjson")):
        try:
            record = json.loads(row["line"])
        except (ValueError, KeyError):
            continue
        kind = record.get("record_type")
        if kind == "event" and record.get("type") == "policy.change":
            # A record without its body (None:None) is counted, not skipped: the policy verdict then fails loudly.
            body = record.get("policy", {})
            key = "%s:%s" % (body.get("outcome"), body.get("reason"))
            policy_changes[key] = policy_changes.get(key, 0) + 1
        elif kind == "event" and record.get("type") == "policy.match":
            body = record.get("policy", {})
            rule = body.get("rule_id")
            policy_matches[rule] = policy_matches.get(rule, 0) + 1
            if body.get("subject", {}).get("seq", 1 << 62) >= record.get("seq", 0):
                policy_misordered += 1
        if kind == "loss":
            body = record.get("loss", {})
            stage = body.get("stage", "?")
            loss[stage] = loss.get(stage, 0) + int(body.get("count", 0))
        elif kind == "health":
            health_times.append(parse_time(record["time"]))
        elif kind == "event" and record.get("type", "").startswith("process."):
            when = parse_time(record["time"])
            latency.setdefault(int((when - start) // 3600), []).append((parse_time(record["observed_time"]) - when) * 1000.0)
    report["loss_by_stage"] = loss
    lines.append("loss by stage (events lost): %s" % (loss or "none"))
    health_times.sort()
    intervals = [b - a for a, b in zip(health_times, health_times[1:])]
    if intervals:
        hourly = {}
        for when, interval in zip(health_times[1:], intervals):
            hourly.setdefault(int((when - start) // 3600), []).append(interval)
        report["health_interval_seconds"] = {"nominal": HEALTH_SECONDS, "median": round(statistics.median(intervals), 3),
                                             "p99": round(percentile(intervals, 0.99), 3), "max": round(max(intervals), 3),
                                             "median_per_hour": [round(statistics.median(v), 3) for _, v in sorted(hourly.items())],
                                             "max_per_hour": [round(max(v), 3) for _, v in sorted(hourly.items())]}
        lines.append("health cadence %s" % report["health_interval_seconds"])
    if latency:
        report["process_time_to_observed_ms_per_hour"] = {hour: {"p50": round(percentile(v, 0.5), 2), "p99": round(percentile(v, 0.99), 2),
                                                                 "max": round(max(v), 2), "n": len(v)} for hour, v in sorted(latency.items())}
        lines.append("process event time->observed (ms) per hour %s" % report["process_time_to_observed_ms_per_hour"])

    sent = read_ndjson(os.path.join(work, "commands.sent"))
    results, accepts = {}, set()
    for row in read_ndjson(os.path.join(work, "events.ndjson")):
        if row.get("accept"):
            accepts.add(row["accept"])
        result = row.get("result")
        if result:
            results.setdefault(result.get("command_id"), []).append((row["rx"], result.get("outcome", ""), result.get("detail", "")))
    outcomes, latencies = {}, []
    for row in sent:
        got = results.get(row["id"])
        key = "%s %s" % (row["action"], (got[0][1] + ":" + got[0][2].split(":")[0]).lower() if got else "no-result")
        outcomes[key] = outcomes.get(key, 0) + 1
        if got:
            latencies.append(got[0][0] - row["t"])
    report["commands"] = {"sent": len(sent), "accepted": len(accepts), "with_result": sum(1 for row in sent if row["id"] in results),
                          "duplicate_results": sum(1 for v in results.values() if len(v) > 1), "outcomes": outcomes,
                          "result_latency_s_p50": round(percentile(latencies, 0.5), 1) if latencies else None,
                          "result_latency_s_max": round(max(latencies), 1) if latencies else None,
                          "victim_alive_at_end": run.get("victim_alive_at_end")}
    lines.append("commands %s" % report["commands"])

    # Every policy publish must be accounted for: a good version is loaded once (`updated`, or `no_previous_state` for the
    # first), an older validly signed one is refused as `rollback`, nothing else happens, nothing expires, and every match
    # comes after the record it is about.
    published = read_ndjson(os.path.join(work, "policy.sent"))
    if published:
        good = sum(1 for row in published if row["kind"] == "good")
        refused = sum(1 for row in published if row["kind"] == "rollback")
        loaded = policy_changes.get("loaded:updated", 0) + policy_changes.get("loaded:no_previous_state", 0)
        report["policy"] = {"published_good": good, "published_rollback": refused, "changes": policy_changes,
                            "matches_by_rule": policy_matches, "matches_total": sum(policy_matches.values()),
                            "matches_before_their_subject": policy_misordered, "last_version": published[-1]["version"]}
        # A publish in the final seconds may not have been picked up before the sensor stopped.
        report["policy"]["loaded_shortfall"] = good - loaded
        report["policy"]["refused_shortfall"] = refused - policy_changes.get("rejected:rollback", 0)
        lines.append("policy %s" % report["policy"])
    integrity_path = os.path.join(work, "integrity.json")
    if os.path.exists(integrity_path):
        try:
            integrity = json.load(open(integrity_path, encoding="utf-8"))
            report["integrity"] = {key: integrity.get(key) for key in ("stored", "first_seq", "last_seq", "missing", "accounted",
                                                                       "conflicts", "other_loss_reported", "problems")}
        except ValueError:
            report["integrity"] = {"problems": ["integrity report unreadable"]}
        lines.append("store integrity %s" % report["integrity"])
    report["run"] = run
    lines.append("run %s" % run)

    # Verdicts are a signal, not a proof; the numbers above are the evidence.
    verdicts = {}
    if "rss_mib" in report:
        r = report["rss_mib"]
        trend_hours = (steady[-1]["t"] - steady[0]["t"]) / 3600.0 if len(steady) > 1 else 0.0
        if trend_hours < 2.0:
            # A short run cannot show a leak or rule one out; say so instead of guessing from a few minutes of samples.
            verdicts["rss"] = "NOT ENOUGH DATA (%.1f h after warm-up; need 2 h)" % trend_hours
        else:
            # Only a rising trend is growth; a falling slope is allocator give-back, not a leak.
            verdicts["rss"] = "GROWTH" if r["slope_per_hour_second_half"] >= 1.0 or (r["slope_per_hour"] > 0 and r["last"] - r["min"] >= 16) else "stable"
    if "fds" in report:
        f = report["fds"]
        verdicts["fds"] = "stable" if f["max"] - f["min"] <= 8 and f["last"] <= f["first"] + 2 else "GROWTH"
    if "threads" in report:
        verdicts["threads"] = "stable" if report["threads"]["max"] == report["threads"]["min"] else "CHANGED"
    if "health_interval_seconds" in report:
        verdicts["timer"] = "on time" if report["health_interval_seconds"]["p99"] <= HEALTH_SECONDS + 1.0 else "DRIFT"
    verdicts["providers"] = "active outside injected faults" if not report.get("provider_not_active") else "NOT ALWAYS ACTIVE"
    c = report["commands"]
    verdicts["commands"] = "all answered, victim alive" if c["sent"] and c["with_result"] == c["sent"] and c["victim_alive_at_end"] else "CHECK"
    if "policy" in report:
        p = report["policy"]
        unexpected = {key: count for key, count in p["changes"].items() if key not in ("loaded:updated", "loaded:no_previous_state", "rejected:rollback")}
        verdicts["policy"] = ("every publish accounted for, matches ordered" if 0 <= p["loaded_shortfall"] <= 1 and 0 <= p["refused_shortfall"] <= 1
                              and not unexpected and p["matches_total"] > 0 and not p["matches_before_their_subject"] else "CHECK")
    if "integrity" in report:
        verdicts["store"] = "consistent" if not report["integrity"].get("problems") else "PROBLEMS"
    verdicts["sensor"] = "ran to the end" if not run.get("stopped_early") and run.get("sensor_exit_code") == 0 else "CHECK"
    report["verdicts"] = verdicts
    lines.append("verdicts %s" % verdicts)
    with open(os.path.join(work, "report.json"), "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=1, default=str)
    with open(os.path.join(work, "report.txt"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--hours", type=float, default=6.0)
    run_parser.add_argument("--work", default="/var/tmp/soak")
    run_parser.add_argument("--sensord", required=True)
    run_parser.add_argument("--ctl", required=True)
    run_parser.add_argument("--signer", required=True)
    run_parser.add_argument("--scale", type=float, default=1.0)
    run_parser.add_argument("--warmup-minutes", type=int, default=20)
    run_parser.add_argument("--no-policy", dest="policy", action="store_false", help="run without a signed local policy")
    load_parser = sub.add_parser("load")
    load_parser.add_argument("--scale", type=float, default=1.0)
    analyze_parser = sub.add_parser("analyze")
    analyze_parser.add_argument("work")
    analyze_parser.add_argument("--warmup-minutes", type=int, default=20)
    args = parser.parse_args()
    if args.command == "load":
        return load(args)
    if args.command == "analyze":
        return analyze(argparse.Namespace(work=args.work, warmup_minutes=args.warmup_minutes))
    os.makedirs(args.work, exist_ok=True)
    return Soak(args).run()


if __name__ == "__main__":
    sys.exit(main())
