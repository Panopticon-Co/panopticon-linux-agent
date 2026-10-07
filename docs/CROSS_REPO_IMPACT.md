# Cross-repository impact

The Linux endpoint depends on other Panopticon repositories only through **published contracts**; no repository
imports another's source. Branch names below are the ones that exist on GitHub at handoff time; none of the
contracts or Manager branches has been merged into those repositories' default branches by this work.

| Repository | What the Linux endpoint needs from it | Where it lives now | State |
| --- | --- | --- | --- |
| `panopticon-contracts` | **Linux endpoint record 1.0** JSON Schema, human spec (`docs/LINUX_ENDPOINT_RECORD_1.md`), valid and invalid fixtures, validator `scripts/validate_linux_endpoint.py` | branch `feat/linux-endpoint-record` (HEAD `2a8e847`; the default branch is `master`) | Complete for every record type the sensor writes, including `tamper.integrity` (`manifest_rollback`) and running-process `policy.match`. Validator: 77 valid / 73 invalid fixtures, 0 failures. Awaiting review and merge by the contracts owners |
| `panopticon-manager` | Ingest of record 1.0 over HTTPS, acknowledgement cursor, **command signing** (ES256) and the command/result endpoints | branch `feat/linux-command-signing` (HEAD `9effe68`; contains `feat/linux-endpoint-ingest`) | Manager vendors a copy of the schema (`manager/wire/linux_endpoint_1_0.schema.json`) that **must be kept byte-for-byte in sync with contracts**; it was out of date once and would have rejected `tamper.integrity`. Suite: 176 passed, 1 skipped |
| `panopticon-detection-engine` | Nothing yet | – | Intentionally not integrated; see [HANDOFF](HANDOFF.md#integration-boundaries) |
| `panopticon-agent` (Windows) | Nothing shared | – | Independent; no common code |
| `panopticon-diagrams` | Linux diagrams | – | Not updated by this work |

Changing a record: edit the schema and fixtures in contracts, copy the schema into the Manager's `wire/`, add or
update a Manager fixture (its `id` must be recomputed with `wire.expected_id`; `host.boot_id` and `sensor.id` must
match the other fixtures or the cursor test fails), update the serializer here, and run the validator against a real
sensor's NDJSON. Do not change the schema casually: `additionalProperties` is false.

The foundation agent's schema 0.4 (`linux_procfs`) belongs to the earlier, separate contract and is unchanged.
