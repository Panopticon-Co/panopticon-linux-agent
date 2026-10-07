#!/usr/bin/env python3
"""Checks what the fake Manager stored against the delivery guarantees of the sensor.

usage: analyze.py <store.ndjson> [--min-seq N] [--require-through N] [--allow-gaps] [--count-exec name,name] [--json]

Exit status is non-zero when:
  * one seq was stored with two different payloads (conflict), or
  * more seqs are missing between the first and last stored seq than the sensor reported as lost
    (a silent gap). Reported loss is the larger of the `wal` loss records seen and the cumulative
    `wal.dropped_records` of the latest health record (a loss record lives in the same WAL and can
    itself be dropped by a later quota loss; the cumulative counter survives in the newest health
    record), plus `manager_rejected` records. Valid for one sensor process: the counter restarts
    with the process. The check is on totals because a loss record follows the loss it describes.
"""
import datetime
import json
import sys


def parse_time(text):
    return datetime.datetime.strptime(text[:26].rstrip("Z"), "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=datetime.timezone.utc).timestamp()


def main():
    path = sys.argv[1]
    allow_gaps = "--allow-gaps" in sys.argv
    as_json = "--json" in sys.argv
    min_seq = 1
    require_through = 0
    if "--require-through" in sys.argv:
        require_through = int(sys.argv[sys.argv.index("--require-through") + 1])
    if "--min-seq" in sys.argv:
        min_seq = int(sys.argv[sys.argv.index("--min-seq") + 1])
    rows = {}
    conflicts = []
    types = {}
    wal_loss_total = 0
    health_dropped = 0
    write_failed = 0
    skewed_events = 0
    other_loss = {}
    loss_details = []
    batches = set()
    count_exec = {}
    if "--count-exec" in sys.argv:
        count_exec = {name: 0 for name in sys.argv[sys.argv.index("--count-exec") + 1].split(",")}
    with open(path, "r", encoding="utf-8") as handle:
        for text in handle:
            row = json.loads(text)
            seq = row["seq"]
            batches.add(row["batch"])
            if seq in rows and rows[seq] != row["digest"]:
                conflicts.append(seq)
            rows[seq] = row["digest"]
            record = json.loads(row["line"])
            kind = record.get("type")
            types[kind] = types.get(kind, 0) + 1
            if record.get("record_type") == "event":
                # `time` is the kernel's event time on the sensor's clock, `observed_time` is the wall clock
                # when the sensor read it; they differ by more than seconds only if the sensor's clock
                # offset is stale (a clock step it has not noticed) or the sensor is far behind.
                lag = abs(parse_time(record["time"]) - parse_time(record["observed_time"]))
                skewed_events += 1 if lag > 5.0 else 0
            if kind == "process.exec" and record.get("process", {}).get("name") in count_exec:
                count_exec[record["process"]["name"]] += 1
            if kind == "health":
                health_dropped = max(health_dropped, record.get("health", {}).get("wal", {}).get("dropped_records", 0))
            if kind == "loss":
                body = record.get("loss", {})
                stage = body.get("stage")
                write_failed += body.get("by_type", {}).get("write_failed", 0)
                if stage == "wal":
                    wal_loss_total += body.get("count", 0)
                else:
                    other_loss[stage] = other_loss.get(stage, 0) + body.get("count", 0)
                loss_details.append({"seq": seq, "stage": stage, "count": body.get("count"), "detail": body.get("detail", "")})
    seqs = sorted(s for s in rows if s >= min_seq)
    missing = []
    if seqs:
        present = set(seqs)
        missing = [s for s in range(seqs[0], seqs[-1] + 1) if s not in present]
    ranges = []
    start = prev = None
    for s in missing:
        if start is None:
            start = prev = s
        elif s == prev + 1:
            prev = s
        else:
            ranges.append([start, prev])
            start = prev = s
    if start is not None:
        ranges.append([start, prev])
    problems = []
    if conflicts:
        problems.append("conflicting payloads for seq %s" % conflicts[:5])
    absent = [s for s in range(1, require_through + 1) if s not in rows]
    if absent:
        problems.append("%d of the first %d seqs (declared durable before the crash) are absent, first %s" % (len(absent), require_through, absent[:5]))
    accounted = max(wal_loss_total, health_dropped) + other_loss.get("manager_rejected", 0)
    if missing and not allow_gaps and len(missing) > accounted:
        problems.append("%d missing seqs but only %d reported as lost" % (len(missing), accounted))
    report = {
        "stored": len(seqs),
        "first_seq": seqs[0] if seqs else None,
        "last_seq": seqs[-1] if seqs else None,
        "missing": len(missing),
        "required_through": require_through,
        "required_absent": len(absent),
        "missing_ranges": ranges[:20],
        "wal_loss_reported": wal_loss_total,
        "health_dropped_max": health_dropped,
        "accounted": accounted,
        "write_failed_reported": write_failed,
        "skewed_events": skewed_events,
        "exec_named": count_exec,
        "other_loss_reported": other_loss,
        "conflicts": conflicts,
        "batches": len(batches),
        "types": types,
        "loss_records": loss_details[:20],
        "problems": problems,
    }
    print(json.dumps(report, indent=None if as_json else 2))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
