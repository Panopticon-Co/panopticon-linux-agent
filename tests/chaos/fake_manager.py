#!/usr/bin/env python3
"""Fault-injecting stand-in for the Manager's Linux ingest route, for chaos tests only.

It speaks exactly the contract the sensor uplink checks (ADR 018): POST
/api/v2/linux-endpoint/records with an NDJSON body, answered with
{batch_id, received, accepted, duplicates, rejected[]}. It stores every line it accepts in an
append-only store file (so it survives being killed) and deduplicates by (seq, sha256(line)).
A different payload under an already stored seq is kept and reported by analyze.py as a conflict.

Fault injection: the file given by --mode-file is re-read on every request. The first word is the
mode, the optional second word its argument:
  ok                  normal
  drop_ack N          store the batch, then close the connection without answering, N times
  http503             answer 503 and store nothing
  slow S              store the batch, wait S seconds, then answer
  bad_ack             store the batch, answer 200 with counts that do not add up
  reject N            reject the first line of the batch (not stored) N times
Counters reset whenever the content of the mode file changes.
"""
import argparse
import hashlib
import json
import os
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class State:
    def __init__(self, store_path, mode_path, token):
        self.lock = threading.Lock()
        self.mode_path = mode_path
        self.token = token
        self.seen = {}  # seq -> set of digests
        self.requests = 0
        self.mode_text = None
        self.used = 0
        if os.path.exists(store_path):
            with open(store_path, "r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    self.seen.setdefault(row["seq"], set()).add(row["digest"])
        self.store = open(store_path, "a", encoding="utf-8", buffering=1)

    def mode(self):
        try:
            with open(self.mode_path, "r", encoding="utf-8") as handle:
                text = handle.read().strip() or "ok"
        except OSError:
            text = "ok"
        if text != self.mode_text:
            self.mode_text = text
            self.used = 0
        parts = text.split()
        return parts[0], (float(parts[1]) if len(parts) > 1 else 0.0)


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def reply(self, code, body):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            if self.path != "/api/v2/linux-endpoint/records":
                return self.reply(404, {"error": "not found"})
            if self.headers.get("Authorization") != "Bearer " + state.token:
                return self.reply(401, {"error": "unauthorized"})
            batch = self.headers.get("X-Panopticon-Batch-Id", "")
            with state.lock:
                state.requests += 1
                mode, argument = state.mode()
                if mode == "http503":
                    return self.reply(503, {"error": "unavailable"})
                lines = [line for line in body.decode("utf-8", "replace").split("\n") if line]
                accepted = duplicates = 0
                rejected = []
                if mode == "reject" and state.used < argument:
                    state.used += 1
                    rejected.append({"line": 1, "reason": "chaos_rejected", "detail": "fault injection"})
                for index, line in enumerate(lines, start=1):
                    if any(entry["line"] == index for entry in rejected):
                        continue
                    try:
                        seq = json.loads(line)["seq"]
                    except (ValueError, KeyError, TypeError):
                        rejected.append({"line": index, "reason": "not_json"})
                        continue
                    digest = hashlib.sha256(line.encode()).hexdigest()
                    if digest in state.seen.get(seq, set()):
                        duplicates += 1
                        continue
                    state.seen.setdefault(seq, set()).add(digest)
                    state.store.write(json.dumps({"rx": time.time(), "batch": batch, "seq": seq, "digest": digest, "line": line}) + "\n")
                    accepted += 1
                answer = {"batch_id": batch, "received": len(lines), "accepted": accepted, "duplicates": duplicates, "rejected": rejected}
                if mode == "bad_ack":
                    answer["accepted"] += 1
                if mode == "drop_ack" and state.used < argument:
                    state.used += 1
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
            if mode == "slow":
                time.sleep(argument)
            self.reply(200, answer)

        def do_GET(self):
            self.reply(404, {"error": "not found"})

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--store", required=True)
    parser.add_argument("--mode-file", required=True)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    state = State(args.store, args.mode_file, args.token)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(state))
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print("fake manager listening on", args.port, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
