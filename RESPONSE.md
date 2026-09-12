# Response boundary

The future Response Engine authorizes commands; this agent must only authenticate, validate,
target-check, replay-check, dispatch a closed action set, execute, receipt, and audit.

The implemented command gate validates a version `1` internal command's ID, host, agent, expiry,
and duplicate ID. It rejects unsupported actions and protects PID 1. It does not authenticate a
remote command, persist replay state, or execute an operating-system action. Therefore no remote
command receiver is exposed and no response action is claimed.
