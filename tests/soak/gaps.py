#!/usr/bin/env python3
"""Lists the moments a soak run's sensor was late or shed load, so they can be set beside what else was running.

For a finished soak work directory it prints every interval between two health records longer than the nominal
interval plus one second, and every loss record, with the UTC time of day. The soak report summarises these as a
cadence verdict and a loss total; this shows when they happened.

usage: python3 tests/soak/gaps.py [work-dir]        (default /var/tmp/soak; reads store.ndjson)
"""
import datetime
import json
import re
import sys

NOMINAL_SECONDS = 10


def parse_time(text):
    # Python 3.10 reads at most microseconds.
    return datetime.datetime.fromisoformat(re.sub(r"(\.\d{6})\d*", r"\1", text.replace("Z", "+00:00"))).timestamp()


def clock(value):
    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).strftime("%H:%M:%S")


def main():
    work = sys.argv[1] if len(sys.argv) > 1 else "/var/tmp/soak"
    health, losses = [], []
    with open(work + "/store.ndjson", "rb") as handle:
        for row in handle:
            if b"health" not in row and b"loss" not in row:
                continue
            try:
                record = json.loads(json.loads(row)["line"])
            except (ValueError, KeyError):
                continue
            kind = record.get("record_type")
            if kind == "health":
                health.append(parse_time(record["time"]))
            elif kind == "loss":
                body = record.get("loss", {})
                losses.append((parse_time(record["time"]), body.get("stage"), body.get("count")))
    health.sort()
    print("health records: %d" % len(health))
    print("health intervals above %d s (UTC time the interval ended, seconds):" % (NOMINAL_SECONDS + 1))
    for before, after in zip(health, health[1:]):
        if after - before > NOMINAL_SECONDS + 1:
            print("  %s %.1f" % (clock(after), after - before))
    print("loss records (UTC time, stage, events):")
    for when, stage, count in sorted(losses):
        print("  %s %s %s" % (clock(when), stage, count))


if __name__ == "__main__":
    main()
