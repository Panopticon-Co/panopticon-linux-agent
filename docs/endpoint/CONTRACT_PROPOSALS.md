# Linux endpoint record: contract change proposals

**Status:** proposals only. Nothing here is implemented in the sensor, and nothing has been written into
`panopticon-contracts` (which the Linux endpoint does not own). Each item says what the sensor can emit today, what
is missing from the contract, and what the sensor would do once the contract allows it.

**Update (2026-10-07):** the `policy.match` and `policy.change` records (ADR 032) and the S13 records the sensor
already wrote (process `stdio`, `interpreter` and `script`, `process.signal`, `network.raw_socket`, `network.close`
byte counts, `container.started` and `container.stopped`) were adopted into the schema in `panopticon-contracts`
`d81b6f1` (branch `feat/linux-endpoint-record`) with valid and invalid fixtures made from real captures, and the
Manager accepts them in `68be0e8` (branch `feat/linux-command-signing`). Items below that name these types are
done; the rest are still proposals.

Read against `feat/linux-endpoint-record` of `panopticon-contracts`
(`schema/linux-endpoint/1.0.schema.json`, `docs/LINUX_ENDPOINT_RECORD_1.md`, head `241e315`).

## 1. Document the loss stages the sensor really emits (no schema change)

`Loss.stage` is a free string, so the schema already accepts every value below. What is missing is the record
document, which lists `kernel`, `queue`, `wal`, `governor`, `transport` and `manager_rejected` only.

| Stage | Meaning | Count is |
|---|---|---|
| `kernel` | events the kernel or a probe dropped before the sensor read them | exact for eBPF ring buffers; unknown for netlink sources |
| `queue` | the bounded in-process queue was full | exact |
| `refused` | a provider refused to hand an event to a full queue instead of blocking | exact |
| `governor` | the rate governor shed events on purpose | exact |
| `wal` | durable log loss; `detail` says `removed`, `corrupt_segment`, `quota` or `write_failed` | records |
| `manager_rejected` | the Manager refused records | records |
| `sensor_gap` | the previous sensor process did not shut down cleanly; **count is always 1 (one blind interval), not a number of events**; `detail` carries the last time the sensor was known alive, the restart time, the blind seconds and whether the boot id changed | intervals |
| `provider_gap` | a kernel hook of a running sensor was removed from outside it and the sensor attached it again; **count is always 1 (one blind interval per hook), not a number of events**; `detail` names the provider, the hook and its capability, and carries the last time it was verified attached, the time it was found missing, the time it was attached again, the attempts and the blind milliseconds | intervals |

Proposal: add the rows to the table in `LINUX_ENDPOINT_RECORD_1.md`, and state that `by_type` is empty for
`sensor_gap` and `provider_gap`. Consumers must not add either count to an event-loss total. Real-VM evidence:
the chaos `kill9` scenario (14 kills, 14 `sensor_gap` records, 0 records missing); for `provider_gap`, 18 hook
links of a running sensor closed by a `close()` injected with gdb gave 18 `provider_gap` records and 18 restored
links (S13.16 in IMPLEMENTATION_STATUS.md).

`transport` is in the contract document but the sensor does not emit it (checked in `src/`); delivery failures stay
in uplink state. Either drop it from the document or keep it reserved.

## 2. `tamper.*` records (new event types)

The sensor cannot report these today. A record type would need to exist first.

| Proposed type | Source | Why it matters |
|---|---|---|
| `tamper.attach` | a `ptrace` attach to the sensor pid, or a `process_vm_writev` against it | root can close the sensor's BPF link fds by injection; this is the only way to blind it from outside on 5.15 (`bpftool link detach` is refused, checked on the VM) |
| `tamper.link_lost` | an attachment self-check (per-link `bpf_obj_get_info_by_fd`, compared with the recorded id and type) | the sensor learns its own hook is gone |
| `tamper.config_changed` | the trust check (ADR 031) rejects a changed key list or CA bundle at reload | evidence of an attempt to replace the command trust anchor |

Proposed body: `{ "subject": "sensor"|"config"|"keyring"|"link", "actor": ProcessRef, "detail": string<=512 }`,
closed (`additionalProperties: false`), with `process` required for `tamper.attach`.

The sensor already records foreign `bpf()` loads as `kernel.bpf_load` with a `Bpf` body. That body has no field for
"this is a tamper attempt"; that judgement stays a Detection concern.

Not built either way: the sensor-side detection. It needs an eBPF `ptrace` hook scoped to the sensor's own pid and
the fd self-check, and is blocked only on the type existing.

## 3. U1 `library.load`

The sensor can see file-backed `PROT_EXEC` mappings with an fentry on `security_mmap_file`. The `Module` body in the
schema describes **kernel** modules (`name`, `size`, `state`), so it must not be reused. Proposal:
`library.load` with body `{ "path": string, "inode": integer, "device": integer, "hash": Hash? }` plus the
`process` that mapped it. Dedup is per (process, inode), so volume is bounded by distinct libraries per process.

## 4. W1 unix sockets

`state.unix_sockets` is a state item. The schema says state items other than processes are open objects documented in
the telemetry catalog, so **no schema change is needed**, only an entry in the catalog. Listed here so the Manager
side knows the name before it appears.

## 5. AO2 `evidence.package_verify`

`dpkg --verify` / md5sums comparison on demand, as the result of a collection command. Proposal: a new `evidence.*`
family whose body is `{ "package": string, "mismatches": [ { "path": string, "kind": "content"|"mode"|"owner"|"missing" } ] }`
with a bounded array (for example 256), plus a `truncated` flag. Not implemented in the sensor.

## 6. Compatibility notes

* All proposals add types or documentation; none changes an existing field, so `1.0` consumers that ignore
  unknown types keep working. Consumers that validate `type` against a closed list would need the new names first.
* The envelope `type` pattern `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?$` already admits every name above.
* Per project policy the schema is not changed casually: any accepted item needs the schema, a valid and an invalid
  fixture, the record document, and the sensor serializer and its tests in one change.
