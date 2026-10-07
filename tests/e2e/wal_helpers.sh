# Helpers shared by the end-to-end scripts that read what a sensord wrote to its WAL. Source it; set WAL to the
# directory that holds the *.log files before calling anything.
#
#   dump                          tamper.integrity, policy.match and health records as JSON lines (kind, seq, ...)
#   wait_for <seconds> <expr>     polls until the python expression over `rows` (the dump) is true
#   count <expr>                  prints a python expression over `rows`

dump() {
  python3 - "$WAL" <<'PY'
import glob, json, sys
dec = json.JSONDecoder(); recs = {}
for f in sorted(glob.glob(sys.argv[1] + "/*.log")):
    data = open(f, "rb").read().decode("latin-1"); i = 0
    while True:
        i = data.find('{"schema_version"', i)
        if i < 0: break
        try: obj, end = dec.raw_decode(data, i)
        except ValueError: i += 1; continue
        i = end; recs[obj["seq"]] = obj
for seq in sorted(recs):
    r = recs[seq]
    if r["type"] == "tamper.integrity":
        print(json.dumps({"kind": "tamper", "seq": seq, **r["tamper"], "process": r.get("process"), "unavailable": r.get("unavailable"), "record": r}))
    elif r["type"] == "policy.match":
        print(json.dumps({"kind": "match", "seq": seq, **r["policy"], "process": r.get("process"), "record": r}))
    elif r["type"] == "health":
        p = [x for x in r["health"]["providers"] if x["name"] == "integrity"]
        q = [x for x in r["health"]["providers"] if x["name"] == "policy"]
        print(json.dumps({"kind": "health", "seq": seq, "status": r["health"]["status"], "integrity": p[0] if p else None, "policy": q[0] if q else None, "time": r["time"]}))
PY
}

wait_for() {
  local limit=$1 predicate=$2 waited=0
  while [ "$waited" -lt "$limit" ]; do
    if dump | python3 -c "import sys, json
rows = [json.loads(l) for l in sys.stdin]
sys.exit(0 if ($predicate) else 1)"; then return 0; fi
    sleep 2; waited=$((waited + 2))
  done
  return 1
}

count() {
  dump | python3 -c "import sys, json
rows = [json.loads(l) for l in sys.stdin]
print($1)"
}
