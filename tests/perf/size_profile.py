#!/usr/bin/env python3
"""Measures what the sensor actually emits: record sizes by type, envelope against payload, the largest
members, repetition, WAL and wire rates, and what compression would buy and cost.

usage: size_profile.py <store.ndjson> [--wire wire.ndjson] [--start EPOCH --end EPOCH] [--drop-port P] [--json] [--top N]

Input is the store of tests/chaos/fake_manager.py (one row per accepted record: rx, batch, seq, digest, line)
and optionally its --wire-log. Sizes are bytes of the record line exactly as the sensor serialized it (the WAL
payload and the wire body are the same bytes). --start/--end select the window by receive time (epoch seconds),
so that startup state snapshots can be reported apart from steady-state traffic.
"""
import json
import subprocess
import sys
import tempfile
import time
import zlib

ENVELOPE = ("schema_version", "record_type", "id", "seq", "type", "time", "observed_time", "host", "sensor",
            "provenance", "unavailable")
WAL_FRAME_BYTES = 20  # wal_header_bytes


def pct(values, q):
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(q / 100.0 * (len(ordered) - 1))))
    return ordered[index]


def stats(sizes):
    return {"n": len(sizes), "bytes": sum(sizes), "mean": round(sum(sizes) / len(sizes), 1) if sizes else 0,
            "p50": pct(sizes, 50), "p95": pct(sizes, 95), "p99": pct(sizes, 99), "max": max(sizes) if sizes else 0}


def compact(value):
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def member_bytes(record):
    """Bytes each top-level member costs inside the line (key, colon and value)."""
    return {key: len(json.dumps(key).encode()) + 1 + compact(value) for key, value in record.items()}


def walk(value, prefix, depth, out):
    if isinstance(value, dict) and depth > 0:
        for key, inner in value.items():
            name = prefix + "." + key
            out[name] = out.get(name, 0) + len(json.dumps(key).encode()) + 1 + compact(inner)
            walk(inner, name, depth - 1, out)


def classify(record):
    kind = record.get("record_type")
    if kind == "event" and record.get("type", "").startswith("state."):
        return "state"
    return kind or "unknown"


def compression(batches):
    """Per-batch (what an uplink would send) and whole-stream ratios, with CPU time per MB."""
    bodies = ["\n".join(lines).encode() + b"\n" for lines in batches]
    raw = sum(len(body) for body in bodies)
    result = {"raw_bytes": raw, "batches": len(bodies), "batch_bytes": stats([len(body) for body in bodies])}
    for level in (1, 6):
        started = time.process_time()
        packed = sum(len(zlib.compress(body, level)) for body in bodies)
        spent = time.process_time() - started
        result["zlib%d_per_batch" % level] = {"bytes": packed, "ratio": round(raw / packed, 2),
                                              "cpu_ms_per_mb": round(spent * 1000 / (raw / 1e6), 1)}
    joined = b"".join(bodies)
    whole = len(zlib.compress(joined, 6))
    result["zlib6_whole_stream"] = {"bytes": whole, "ratio": round(raw / whole, 2)}
    try:
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(joined)
            path = handle.name
        for level in (1, 3, 9):
            started = time.time()
            out = subprocess.run(["zstd", "-%d" % level, "-q", "-c", path], capture_output=True, check=True).stdout
            spent = time.time() - started
            result["zstd%d_whole_stream" % level] = {"bytes": len(out), "ratio": round(raw / len(out), 2),
                                                     "wall_ms_per_mb": round(spent * 1000 / (raw / 1e6), 1)}
        packed = 0
        sample_bodies = bodies[:200]
        for body in sample_bodies:
            packed += len(subprocess.run(["zstd", "-3", "-q", "-c"], input=body, capture_output=True, check=True).stdout)
        sample = sum(len(body) for body in sample_bodies)
        result["zstd3_per_batch_sample"] = {"batches": len(sample_bodies), "ratio": round(sample / packed, 2)}
    except (OSError, subprocess.CalledProcessError) as error:
        result["zstd"] = "unavailable: %s" % error
    return result


def drop_self(record, port):
    """True for events caused by the test Manager on this same machine (its accepts and its own activity)."""
    if record.get("record_type") != "event":
        return False
    net = record.get("network") or {}
    if port and port in ((net.get("local") or {}).get("port"), (net.get("remote") or {}).get("port")):
        return True
    return any("fake_manager.py" in arg for arg in (record.get("process") or {}).get("args", []))


def repetition(records):
    """How much of the process and parent context repeats earlier records exactly, and how much would remain
    if only the keys that changed since the previous record of the same entity were written."""
    out = {}
    for member in ("process", "parent"):
        seen = set()
        last = {}
        total = repeat = delta = count = 0
        for record in records:
            if record.get("record_type") != "event" or member not in record:
                continue
            obj = record[member]
            text = json.dumps(obj, separators=(",", ":"), sort_keys=True)
            size = len(text.encode())
            total += size
            count += 1
            if text in seen:
                repeat += size
            seen.add(text)
            key = obj.get("entity_id")
            previous = last.get(key) if key else None
            if previous is None:
                delta += size
            else:
                delta += compact({k: v for k, v in obj.items() if previous.get(k) != v})
            if key:
                last[key] = obj
        out[member] = {"records": count, "bytes": total, "exact_repeat_bytes": repeat,
                       "exact_repeat_pct": round(100.0 * repeat / max(1, total), 1),
                       "entity_delta_bytes": delta, "entity_delta_pct_of_bytes": round(100.0 * delta / max(1, total), 1),
                       "distinct": len(seen)}
    return out


def dictionary_experiment(lines, sample=600):
    """Per-record compression (what a single-record batch or a WAL frame would get), with and without a zstd
    dictionary trained on other records of the same run."""
    result = {}
    if len(lines) < 400:
        return {"skipped": "fewer than 400 records"}
    train = lines[0::2][:3000]
    test = lines[1::2][:sample]
    with tempfile.TemporaryDirectory() as directory:
        for index, text in enumerate(train):
            with open("%s/t%05d" % (directory, index), "w", encoding="utf-8") as handle:
                handle.write(text)
        dictionary = directory + "/dict"
        try:
            subprocess.run(["zstd", "--train", "-q", "-r", directory, "-o", dictionary, "--maxdict=32768"],
                           capture_output=True, check=True)
        except (OSError, subprocess.CalledProcessError) as error:
            return {"skipped": "zstd --train failed: %s" % error}
        raw = packed_plain = packed_zlib = packed_dict = 0
        started = time.time()
        for text in test:
            data = text.encode()
            raw += len(data)
            packed_zlib += len(zlib.compress(data, 6))
            packed_plain += len(subprocess.run(["zstd", "-3", "-q", "-c"], input=data, capture_output=True, check=True).stdout)
            packed_dict += len(subprocess.run(["zstd", "-3", "-q", "-c", "-D", dictionary], input=data, capture_output=True, check=True).stdout)
        result = {"records": len(test), "raw_mean": round(raw / len(test)), "dictionary_bytes": len(open(dictionary, "rb").read()),
                  "zlib6_mean": round(packed_zlib / len(test)), "zstd3_mean": round(packed_plain / len(test)),
                  "zstd3_dict_mean": round(packed_dict / len(test)),
                  "zstd3_dict_ratio": round(raw / packed_dict, 2)}
    return result


def main():
    argv = sys.argv[1:]
    path = argv[0]
    as_json = "--json" in argv
    top = int(argv[argv.index("--top") + 1]) if "--top" in argv else 12
    wire_path = argv[argv.index("--wire") + 1] if "--wire" in argv else None
    start = float(argv[argv.index("--start") + 1]) if "--start" in argv else None
    end = float(argv[argv.index("--end") + 1]) if "--end" in argv else None
    drop_port = int(argv[argv.index("--drop-port") + 1]) if "--drop-port" in argv else 0

    rows = []
    with open(path, "r", encoding="utf-8") as handle:
        for text in handle:
            row = json.loads(text)
            if start is not None and row["rx"] < start:
                continue
            if end is not None and row["rx"] > end:
                continue
            if drop_port and drop_self(json.loads(row["line"]), drop_port):
                continue
            rows.append(row)
    sizes_all, by_type, by_class = [], {}, {}
    envelope_total = payload_total = 0
    envelope_by_member, payload_by_member, detail = {}, {}, {}
    batches = {}
    receive_times = []
    for row in rows:
        line = row["line"]
        size = len(line.encode("utf-8"))
        record = json.loads(line)
        kind = record.get("type", "?")
        cls = classify(record)
        sizes_all.append(size)
        by_type.setdefault(kind, []).append(size)
        by_class.setdefault(cls, []).append(size)
        batches.setdefault(row["batch"], []).append(line)
        for key, value in member_bytes(record).items():
            if key in ENVELOPE:
                envelope_total += value
                envelope_by_member[key] = envelope_by_member.get(key, 0) + value
            else:
                payload_total += value
                payload_by_member[key] = payload_by_member.get(key, 0) + value
        if cls == "event":
            for key, value in record.items():
                if key not in ENVELOPE:
                    walk(value, key, 2, detail)
        receive_times.append(row["rx"])
    total = sum(sizes_all)
    duration = (max(receive_times) - min(receive_times)) if len(receive_times) > 1 else 0.0
    report = {
        "records": stats(sizes_all),
        "by_class": {key: stats(value) for key, value in sorted(by_class.items())},
        "by_type": {key: stats(value) for key, value in sorted(by_type.items(), key=lambda item: -sum(item[1]))},
        "envelope_vs_payload": {
            "envelope_bytes": envelope_total, "payload_bytes": payload_total,
            "envelope_share_pct": round(100.0 * envelope_total / max(1, envelope_total + payload_total), 1),
            "envelope_by_member": dict(sorted(envelope_by_member.items(), key=lambda item: -item[1])),
            "payload_by_member": dict(sorted(payload_by_member.items(), key=lambda item: -item[1])),
        },
        "largest_event_members": dict(sorted(detail.items(), key=lambda item: -item[1])[:top * 3]),
        "window_seconds": round(duration, 1),
        "rates": {
            "records_per_s": round(len(rows) / duration, 2) if duration else None,
            "wal_bytes_per_s": round((total + WAL_FRAME_BYTES * len(rows)) / duration, 1) if duration else None,
            "payload_bytes_per_s": round(total / duration, 1) if duration else None,
            "wal_overhead_bytes_per_record": WAL_FRAME_BYTES,
        },
        "compression": compression(list(batches.values())),
        "repetition": repetition([json.loads(row["line"]) for row in rows]),
        "per_record_compression": dictionary_experiment([row["line"] for row in rows if not json.loads(row["line"]).get("type", "").startswith("state.")]),
    }
    if wire_path:
        wire = []
        with open(wire_path, "r", encoding="utf-8") as handle:
            for text in handle:
                entry = json.loads(text)
                if (start is None or entry["rx"] >= start) and (end is None or entry["rx"] <= end):
                    wire.append(entry)
        body = sum(entry["body_bytes"] for entry in wire)
        head = sum(entry["header_bytes"] for entry in wire)
        report["wire"] = {"requests": len(wire), "connections": len({entry.get("conn") for entry in wire}), "body_bytes": body, "http_header_bytes": head,
                          "bytes_per_s": round((body + head) / duration, 1) if duration else None,
                          "mean_records_per_request": round(len(rows) / max(1, len(wire)), 1),
                          "content_encodings": sorted({entry.get("encoding", "") for entry in wire}),
                          "note": "HTTP only; TLS record overhead (about 22 bytes per 16 KB record) and TCP/IP headers excluded"}
    if as_json:
        print(json.dumps(report))
        return 0

    r = report["records"]
    print("== records: n=%d total=%.2f MB mean=%.0f p50=%d p95=%d p99=%d max=%d window=%.0fs" % (
        r["n"], r["bytes"] / 1e6, r["mean"], r["p50"], r["p95"], r["p99"], r["max"], duration))
    print("\n== by class")
    for key, value in report["by_class"].items():
        print("  %-9s n=%-7d bytes=%-10d share=%5.1f%% mean=%-8.0f p50=%-7d p95=%-7d p99=%-7d max=%d" % (
            key, value["n"], value["bytes"], 100.0 * value["bytes"] / max(1, total), value["mean"], value["p50"], value["p95"], value["p99"], value["max"]))
    print("\n== by type (largest total first)")
    for key, value in list(report["by_type"].items())[:top * 2]:
        print("  %-28s n=%-7d bytes=%-10d share=%5.1f%% mean=%-8.0f p50=%-7d p95=%-7d p99=%-7d max=%d" % (
            key, value["n"], value["bytes"], 100.0 * value["bytes"] / max(1, total), value["mean"], value["p50"], value["p95"], value["p99"], value["max"]))
    e = report["envelope_vs_payload"]
    print("\n== envelope vs payload (all records): envelope=%d payload=%d (envelope %.1f%%)" % (e["envelope_bytes"], e["payload_bytes"], e["envelope_share_pct"]))
    for key, value in e["envelope_by_member"].items():
        print("  envelope %-16s %10d  %5.1f%% of all bytes  %.0f B/record" % (key, value, 100.0 * value / max(1, total), value / max(1, r["n"])))
    for key, value in list(e["payload_by_member"].items())[:top]:
        print("  payload  %-16s %10d  %5.1f%% of all bytes" % (key, value, 100.0 * value / max(1, total)))
    print("\n== largest members inside event payloads (depth 2)")
    for key, value in list(report["largest_event_members"].items())[:top * 2]:
        print("  %-40s %10d" % (key, value))
    print("\n== rates over %.0f s: %s" % (duration, json.dumps(report["rates"])))
    if "wire" in report:
        print("== wire: %s" % json.dumps(report["wire"]))
    print("\n== compression")
    print(json.dumps(report["compression"], indent=1))
    print("== repetition of process / parent context")
    print(json.dumps(report["repetition"], indent=1))
    print("== per-record compression, zstd dictionary")
    print(json.dumps(report["per_record_compression"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
