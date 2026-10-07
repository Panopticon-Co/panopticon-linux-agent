#!/usr/bin/env python3
"""Command-delivering stand-in for the Manager, for the command-authorization end-to-end tests only.

It extends tests/chaos/fake_manager.py (record ingest with strict acks) with the three routes the sensor's
command channel uses (ADR 024):

  GET  /api/v1/agents/<agent>/commands?delivery_mode=durable   {"commands": [...]}
  POST /api/v1/agents/<agent>/commands/<id>/accept
  POST /api/v1/agents/<agent>/command-results

Commands are read, as raw text, from the NDJSON file given by --commands on every poll, so a test can append a
signed, forged, tampered or malformed line at any time. A command whose id was accepted is not delivered again,
as the real Manager behaves, unless the first word of --redeliver-file is "yes" (a replaying or buggy Manager).
Every accept and every result is appended to --events as one JSON line.
"""
import argparse
import json
import os
import ssl
import sys
import threading
import time
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "chaos"))
import fake_manager  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--store", required=True)
    parser.add_argument("--mode-file", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--commands", required=True)
    parser.add_argument("--events", required=True)
    parser.add_argument("--redeliver-file", default="")
    parser.add_argument("--wire-log")
    parser.add_argument("--compact-store", action="store_true", help="store only the envelope of event records")
    args = parser.parse_args()

    state = fake_manager.State(args.store, args.mode_file, args.token, args.wire_log, args.compact_store)
    base = fake_manager.make_handler(state)
    lock = threading.Lock()
    # Accepted ids survive a restart, as they do in the real Manager's database.
    accepted = set()
    if os.path.exists(args.events):
        with open(args.events, "r", encoding="utf-8") as handle:
            for row in handle:
                try:
                    identifier = json.loads(row).get("accept")
                except ValueError:
                    continue
                if identifier:
                    accepted.add(identifier)
    events = open(args.events, "a", encoding="utf-8", buffering=1)

    def redeliver():
        try:
            with open(args.redeliver_file, "r", encoding="utf-8") as handle:
                return handle.read().split()[:1] == ["yes"]
        except (OSError, IndexError):
            return False

    def command_id(line):
        try:
            return json.loads(line).get("command_id")
        except (ValueError, AttributeError):
            return None

    class Handler(base):
        def authorized(self):
            if self.headers.get("Authorization") != "Bearer " + args.token:
                self.reply(401, {"error": "unauthorized"})
                return False
            return True

        def do_GET(self):
            path = self.path.split("?")[0]
            if not (path.startswith("/api/v1/agents/") and path.endswith("/commands")):
                return self.reply(404, {"error": "not found"})
            if not self.authorized():
                return
            try:
                with open(args.commands, "r", encoding="utf-8") as handle:
                    lines = [line.strip() for line in handle if line.strip()]
            except OSError:
                lines = []
            with lock:
                again = redeliver()
                fresh = [line for line in lines if again or command_id(line) not in accepted]
            return self.reply(200, ('{"commands":[' + ",".join(fresh) + "]}").encode())

        def do_POST(self):
            path = self.path.split("?")[0]
            if not path.startswith("/api/v1/agents/"):
                return super().do_POST()
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            if not self.authorized():
                return
            if "/commands/" in path and path.endswith("/accept"):
                identifier = path.split("/commands/")[1].rsplit("/accept", 1)[0]
                with lock:
                    accepted.add(identifier)
                    events.write(json.dumps({"rx": time.time(), "accept": identifier}) + "\n")
                return self.reply(200, {"command_id": identifier, "status": "ACCEPTED"})
            if path.endswith("/command-results"):
                try:
                    result = json.loads(body)
                except ValueError:
                    return self.reply(422, {"error": "not json"})
                with lock:
                    events.write(json.dumps({"rx": time.time(), "result": result}) + "\n")
                return self.reply(200, {"result_id": result.get("result_id")})
            return self.reply(404, {"error": "not found"})

    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print("fake command manager listening on", args.port, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
