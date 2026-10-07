#!/usr/bin/env python3
"""Loopback TCP connection storm at a controlled rate, for tests/perf/run_netstorm.sh.

usage: netstorm.py --rate CONNS_PER_SECOND --seconds N [--procs K]

Starts K worker processes. Each one runs its own listener (a thread) and a client loop: open a connection, send 100
bytes, read 100 bytes back, close. A single shared server tops out near 2000 connections a second in Python; a
listener per worker lets K workers reach K times the single-process rate (about 5000 a second each on the dev VM).
--rate is the total aimed at, shared evenly (0 = as fast as possible). Every connection is four network events for a
sensor that watches connect, accept and both closes. Prints one JSON object with the rate actually reached; it does
not talk to the sensor.
"""
import argparse
import json
import multiprocessing
import socket
import threading
import time


def serve(listener, stop):
    listener.settimeout(0.2)
    while not stop.is_set():
        try:
            peer, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        try:
            peer.recv(100)
            peer.sendall(b"y" * 100)
        except OSError:
            pass
        peer.close()


def worker(per_proc_rate, seconds, result):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(512)
    port = listener.getsockname()[1]
    stop = threading.Event()
    thread = threading.Thread(target=serve, args=(listener, stop), daemon=True)
    thread.start()
    count = errors = 0
    start = time.perf_counter()
    deadline = start + seconds
    while time.perf_counter() < deadline:
        if per_proc_rate:
            due = start + count / per_proc_rate
            now = time.perf_counter()
            if due > now:
                time.sleep(due - now)
        try:
            peer = socket.create_connection(("127.0.0.1", port), timeout=5)
            peer.sendall(b"x" * 100)
            peer.recv(100)
            peer.close()
            count += 1
        except OSError:
            errors += 1
    stop.set()
    listener.close()
    result.put((count, errors))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rate", type=float, default=0.0)
    parser.add_argument("--seconds", type=float, default=10.0)
    parser.add_argument("--procs", type=int, default=2)
    args = parser.parse_args()

    result = multiprocessing.Queue()
    started = time.perf_counter()
    workers = [multiprocessing.Process(target=worker, args=(args.rate / args.procs if args.rate else 0.0, args.seconds, result))
               for _ in range(args.procs)]
    for process in workers:
        process.start()
    totals = [result.get() for _ in workers]
    elapsed = time.perf_counter() - started
    for process in workers:
        process.join()
    connections = sum(count for count, _ in totals)
    print(json.dumps({"procs": args.procs, "target_rate": args.rate, "seconds": round(elapsed, 2), "connections": connections,
                      "conns_per_s": round(connections / elapsed, 1), "errors": sum(errors for _, errors in totals)}))


if __name__ == "__main__":
    main()
