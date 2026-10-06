#!/usr/bin/env python3
"""Hostile but parseable command lines for tests/e2e/run_command_chaos_e2e.sh.

usage: hostile_commands.py list
       hostile_commands.py <case> <agent-id> <host-id>   (prints one NDJSON line for the fake Manager)

Every line is valid JSON on its own, because the fake Manager wraps the lines in {"commands":[...]}. The cases are
about what the sensor does with content, not about transport: none is signed, so none may ever run, and none may
stop the sensor from answering the signed canary that follows.
"""
import json
import sys


def command(agent, host, **over):
    base = {"command_id": "h", "schema_version": "1", "agent_id": agent, "host_id": host, "action": "KILL_PROCESS",
            "expires_at": "2099-01-01T00:00:00Z", "created_at": "2020-01-01T00:00:00Z",
            "target": {"pid": 1, "start_time_ticks": 1}, "correlation_id": "c"}
    base.update(over)
    return base


def cases(agent, host):
    deep = "[" * 20000 + "]" * 20000
    return {
        "big-correlation": lambda: json.dumps(command(agent, host, command_id="hostile-big", correlation_id="x" * 2_000_000)),
        "big-target-path": lambda: json.dumps(command(agent, host, command_id="hostile-path", action="QUARANTINE_FILE",
                                                      target={"path": "/" + "a/" * 200_000})),
        "deep-nesting": lambda: '{"command_id":"hostile-deep","target":' + deep + "}",
        "pid-absurd": lambda: json.dumps(command(agent, host, command_id="hostile-pid", target={"pid": 10**40, "start_time_ticks": 1})),
        "pid-negative": lambda: json.dumps(command(agent, host, command_id="hostile-neg", target={"pid": -1, "start_time_ticks": -1})),
        "pid-fractional": lambda: json.dumps(command(agent, host, command_id="hostile-frac", target={"pid": 1.5, "start_time_ticks": 2.5})),
        "pid-string": lambda: json.dumps(command(agent, host, command_id="hostile-str", target={"pid": "1", "start_time_ticks": "1"})),
        "target-null": lambda: json.dumps(command(agent, host, command_id="hostile-null", target=None)),
        "action-lowercase": lambda: json.dumps(command(agent, host, command_id="hostile-low", action="kill_process")),
        "action-nul": lambda: json.dumps(command(agent, host, command_id="hostile-nul", action="KILL_PROCESS\u0000")),
        "action-unknown": lambda: json.dumps(command(agent, host, command_id="hostile-unk", action="FORMAT_DISK")),
        "duplicate-keys": lambda: '{"command_id":"hostile-dup","action":"COLLECT_PROCESS_INFO","action":"KILL_PROCESS",'
                                  '"schema_version":"1","agent_id":"%s","host_id":"%s","expires_at":"2099-01-01T00:00:00Z",'
                                  '"target":{"pid":1,"start_time_ticks":1},"correlation_id":"c"}' % (agent, host),
        "id-too-long": lambda: json.dumps(command(agent, host, command_id="i" * 129)),
        "id-control": lambda: json.dumps(command(agent, host, command_id="a\u0000b\nc\"d")),
        "id-empty": lambda: json.dumps(command(agent, host, command_id="")),
        "id-path": lambda: json.dumps(command(agent, host, command_id="../../etc/passwd")),
        "empty-object": lambda: "{}",
        "empty-array-entry": lambda: "[]",
        "number-entry": lambda: "7",
        "string-entry": lambda: json.dumps("KILL_PROCESS"),
        "null-entry": lambda: "null",
        "unicode-surrogate": lambda: '{"command_id":"hostile-sur' + chr(92) + 'ud800","action":"KILL_PROCESS"}',
        "extra-members": lambda: json.dumps(command(agent, host, command_id="hostile-extra", unexpected={"a": [1, 2, 3]}, sudo=True)),
    }


def main(argv):
    if len(argv) == 2 and argv[1] == "list":
        print("\n".join(cases("a", "h")))
        return 0
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    table = cases(argv[2], argv[3])
    if argv[1] not in table:
        print("unknown case", argv[1], file=sys.stderr)
        return 2
    sys.stdout.write(table[argv[1]]() + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
