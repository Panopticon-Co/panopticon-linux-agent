#!/usr/bin/env python3
"""Writes conformance vectors for another implementation of the command signing input (ADR 025).

Every vector is computed by the sensor itself: `panopticon-command-signer input` prints the exact bytes the sensor
verifies, and `sign` signs them with a throwaway key whose public point is included. The Manager's tests
(tests/test_command_signing.py in panopticon-manager) check its Python signing input against these bytes and verify
these signatures, so the two implementations cannot drift apart unnoticed.

usage: command_signing_vectors.py <panopticon-command-signer> <output.json>
"""
import base64
import json
import os
import subprocess
import sys
import tempfile

COMMON = {"agent_id": "agent-vectors", "host_id": "host-vectors", "schema_version": "1"}
BOOT = "boot_" + "a1" * 32

VECTORS = [
    ("kill_process_utc_microseconds", {"command_id": "cmd-v1", "correlation_id": "corr-v1", "action": "KILL_PROCESS",
                                       "created_at": "2026-10-07T12:00:00.123456+00:00", "expires_at": "2026-10-07T12:05:00+00:00",
                                       "target": {"pid": 4242, "start_time_ticks": 987654321}}),
    ("collect_process_info_z_and_offset", {"command_id": "cmd-v2", "correlation_id": "corr-v2", "action": "COLLECT_PROCESS_INFO",
                                           "created_at": "2026-10-07T12:00:00Z", "expires_at": "2026-10-07T17:35:00+05:30",
                                           "target": {"pid": 1, "start_time_ticks": 1}}),
    ("quarantine_file_unicode_path", {"command_id": "cmd-v3", "correlation_id": "corr-v3", "action": "QUARANTINE_FILE",
                                      "created_at": "2026-10-07T12:00:00+00:00", "expires_at": "2026-10-07T12:10:00-04:00",
                                      "target": {"path": "/tmp/évil ☃.bin"}}),
    ("collect_file_separator_characters", {"command_id": "cmd-v4", "correlation_id": "corr-v4", "action": "COLLECT_FILE",
                                           "created_at": "2026-10-07T12:00:00+00:00", "expires_at": "2026-10-07T12:10:00+00:00",
                                           "target": {"path": "/tmp/a:12:b\nc"}}),
    ("isolate_host_without_target", {"command_id": "cmd-v5", "correlation_id": "corr-v5", "action": "ISOLATE_HOST",
                                     "created_at": "2026-10-07T12:00:00+00:00", "expires_at": "2026-10-07T12:10:00+00:00", "target": {}}),
    ("boot_bound_process_schema_2", {"command_id": "cmd-v6", "correlation_id": "corr-v6", "action": "KILL_PROCESS", "schema_version": "2",
                                     "created_at": "2026-10-07T12:00:00+00:00", "expires_at": "2026-10-07T12:10:00+00:00",
                                     "target": {"pid": 77, "start_time_ticks": "18446744073709551615", "boot_id": BOOT}}),
]


def run(signer, verb, argument, text):
    done = subprocess.run([signer, verb, argument], input=text.encode(), capture_output=True, check=False)
    if done.returncode != 0:
        sys.exit(f"{verb} failed: {done.stderr.decode().strip()} for {text}")
    return done.stdout.decode()


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    signer, output = sys.argv[1], sys.argv[2]
    with tempfile.TemporaryDirectory() as scratch:
        key = os.path.join(scratch, "vectors.key")
        point_b64 = run(signer, "keygen", key, "").split()[0]
        vectors = []
        for name, fields in VECTORS:
            command = {**COMMON, **fields}
            text = json.dumps(command, ensure_ascii=False, separators=(",", ":"))
            vectors.append({"name": name, "command": command, "signing_input": run(signer, "input", "-", text),
                            "signed": json.loads(run(signer, "sign", key, text))})
    assert len(base64.b64decode(point_b64)) == 65
    document = {"generated_by": "panopticon-linux-agent tests/e2e/command_signing_vectors.py (panopticon-command-signer)",
                "public_key": point_b64, "vectors": vectors}
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=1)
        handle.write("\n")
    print(f"{len(vectors)} vectors -> {output}")


if __name__ == "__main__":
    main()
