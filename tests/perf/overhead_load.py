#!/usr/bin/env python3
"""Workload generator for tests/perf/run_overhead.sh: times the three paths a sensor sits on.

usage: overhead_load.py [--execs N] [--conns N] [--opens N] [--rounds N] [--dir PATH]

Prints one JSON object: the median over the rounds of the wall time per operation, in microseconds, for
  exec  posix_spawn of /bin/true and wait (fork + exec + exit seen by the process provider)
  tcp   a loopback connection: connect, 100 bytes each way, close both ends (connect, accept, two closes)
  file  open and close of an existing file (what the file provider sees on a watched mount)
Run it with and without the sensor and compare; it does not talk to the sensor itself.
"""
import argparse
import json
import os
import socket
import statistics
import threading
import time


def exec_round(count):
    start = time.perf_counter()
    for _ in range(count):
        pid = os.posix_spawn("/bin/true", ["true"], os.environ)
        os.waitpid(pid, 0)
    return (time.perf_counter() - start) / count * 1e6


def tcp_round(count):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(128)
    port = server.getsockname()[1]
    done = threading.Event()

    def serve():
        while not done.is_set():
            try:
                peer, _ = server.accept()
            except OSError:
                return
            peer.recv(100)
            peer.sendall(b"y" * 100)
            peer.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    start = time.perf_counter()
    for _ in range(count):
        client = socket.create_connection(("127.0.0.1", port))
        client.sendall(b"x" * 100)
        client.recv(100)
        client.close()
    elapsed = time.perf_counter() - start
    done.set()
    server.close()
    return elapsed / count * 1e6


def file_round(count, directory):
    path = os.path.join(directory, "overhead-probe")
    with open(path, "wb") as handle:
        handle.write(b"probe")
    start = time.perf_counter()
    for _ in range(count):
        os.close(os.open(path, os.O_RDONLY))
    elapsed = time.perf_counter() - start
    os.unlink(path)
    return elapsed / count * 1e6


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execs", type=int, default=1500)
    parser.add_argument("--conns", type=int, default=3000)
    parser.add_argument("--opens", type=int, default=200000)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--dir", default="/var/tmp")
    args = parser.parse_args()
    exec_round(50)  # warm the page cache
    result = {
        "exec_us": statistics.median(exec_round(args.execs) for _ in range(args.rounds)),
        "tcp_us": statistics.median(tcp_round(args.conns) for _ in range(args.rounds)),
        "file_us": statistics.median(file_round(args.opens, args.dir) for _ in range(args.rounds)),
    }
    print(json.dumps({key: round(value, 2) for key, value in result.items()}))


if __name__ == "__main__":
    main()
