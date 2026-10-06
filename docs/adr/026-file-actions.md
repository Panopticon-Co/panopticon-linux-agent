# ADR 026: File actions (COLLECT_FILE, QUARANTINE_FILE)

**Status:** Accepted (implemented; unit tested; real-VM verification recorded under "Verified")
**Date:** 2026-10-07

## Context

ADR 024 gave the command channel a closed action vocabulary and two process actions. File response is the next
most requested capability: "tell me what this file is" and "get it out of the way". Both take a *path* from the
Manager. Between the moment the Manager (or an analyst) looked at a file and the moment the endpoint acts, an
unprivileged local user can rename, replace or symlink anything they can write to. The sensor runs as root, so a
naive `open(path)` / `rename(path, ...)` is a confused-deputy primitive: "make root read, move or delete the file
I point this name at". The design has to make that impossible, not unlikely.

## Decision

1. **Descriptors, never names.**
   * The path must be absolute and already normal: no `.`, `..`, empty components (`//`) or trailing slash
     (`invalid_target`). The sensor does not normalise on the Manager's behalf, because a normalised path is a
     different path from the one that was authorised and signed (ADR 025 signs the text).
   * Every directory on the way is opened with `openat(O_PATH|O_DIRECTORY|O_NOFOLLOW)` from the previous
     descriptor. A symlink anywhere on the way is `path_symlink`; it is never followed.
   * The leaf is opened `O_PATH|O_NOFOLLOW`; its type comes from `fstat` of that descriptor. A symlink leaf is
     reported by COLLECT_FILE (with its target text) and refused by QUARANTINE_FILE. Directories, FIFOs, devices
     and sockets are `not_a_file` and are **never opened for reading** (a FIFO open would block, a device open
     can have side effects).
   * Contents are read through `/proc/self/fd/<n>` of the descriptor already examined, after re-checking
     `(st_dev, st_ino)`; a change is `target_changed`. Hashing has a time budget and a size bound
     (`budget_exceeded`, `file_too_large`) so a huge or slow file cannot stall the command thread.
2. **COLLECT_FILE** is read-only: type, size, mode, owner, times and the SHA-256, as `detail` (at most 400
   bytes). It is not limited by the roots, because it changes nothing. **Content never leaves the endpoint**:
   there is no contract object for file content, and evidence of a file is its hash. Hard links are reported
   (`other_links=N`).
3. **QUARANTINE_FILE** moves one regular file into a store, after recording what it was.
   * Eligibility: under one of `response_file_roots` (lexical prefix on whole components, so `/srv/data2` is not
     under `/srv/data`), and not protected. Protected, always: `/proc`, `/sys`, `/dev`, `/boot`, the quarantine
     store, the sensor's own executable, init's executable, and the sensor's own state (configuration, identity,
     CA bundle, signing keys, ledger, WAL and command WAL), which `sensord` adds from its resolved
     configuration. A protected target is `target_protected`; outside the roots is `outside_roots`.
   * Store: a directory owned by the sensor's euid, mode 0700 (anything else is `store_insecure`), default
     `<wal_path>.quarantine`, overridable with `response_quarantine_dir`. Blobs are `<command_id>` with mode
     0400; a metadata file `<command_id>.json` (original path as text and as hex, size, mode, owner, times,
     SHA-256, link count, device and inode) is written **before** the move, so an interrupted quarantine leaves
     the record. Quotas: entries, bytes and a free-space reserve (`quarantine_full`, `no_space`). A reused
     command id is `store_conflict`, never an overwrite.
   * Move: `renameat2(RENAME_NOREPLACE)` between the two directory descriptors. After the rename the stored
     inode is compared with the examined one; if the name had been swapped in the meantime the file is moved
     back (`target_changed`) and nothing is lost.
   * Across filesystems (`EXDEV`): copy into a `*.part` file, `fsync`, **re-open read-only and re-hash** (a
     write-only descriptor cannot prove what is on disk), identity check, then `unlinkat` the original.
     Leftover `*.part` files from a crash are removed before each quarantine.
   * `dry_run` does every check and the hash, then stops (`dry_run`); the file is untouched.
4. **Configuration cannot leave quarantine implicit.** `response_file_roots` (comma-separated absolute paths,
   no `..`, never `/`, no duplicates) is required to list QUARANTINE_FILE in `response_actions`, and listing
   QUARANTINE_FILE requires roots. Either alone is a configuration error, not a silent no-op.
   `response_actions` is now validated against the implemented set, so a mistyped or unimplemented action fails
   at start.
5. **Everything else is ADR 024/025.** Signature, boot and expiry, policy mode, allow-list and rate come first;
   the ledger records intent before the executor runs and the result after; the `response.action` audit record
   carries the outcome and reason. A redelivered command never moves a second file (the new file that now has
   the old name survives).

## Rejected alternatives

* **Resolving with `realpath` and then acting on the string.** The classic race; the answer is stale before it
  is used.
* **`O_NOFOLLOW` on the leaf only.** A symlinked parent directory is just as good for an attacker.
* **Deleting instead of quarantining.** Irreversible, and no evidence is kept. Quarantine keeps the bytes under
  a root-only store; a delete action can be added later with the same descriptor core.
* **Uploading file content for COLLECT_FILE.** No contract object, a data-leak surface, and a size problem.
  Hash plus metadata is the first useful step; upload is a Manager/contract decision.
* **A `chattr`/xattr-based quarantine in place.** Does not survive on every filesystem and leaves the file
  executable by path for anyone who clears the flag.

## Residual risks and limits

* **Cross-filesystem copy path.** Between the identity check and `unlinkat`, a name can still be swapped in a
  window of microseconds; the unlink then removes the *new* name's inode. The same-filesystem path is verified
  and restored; the copy path is only partly mitigated. Quarantine inside the same filesystem as the roots
  (set `response_quarantine_dir` accordingly) avoids it.
* **No restore action.** The 7-action vocabulary has no RESTORE. Restoring is a local, root-only operation on
  the store for now. A signed RESTORE_FILE would need the same design and a contract change.
* **No content upload** (see above).
* **No deterministic TOCTOU unit test.** The swap-and-restore branch is covered by the identity checks, not by
  a test that wins the race.
* **Hard links.** Quarantining one name leaves other links to the same inode; the count is reported.
* **Root on the endpoint** can read or empty the store; outside this boundary (SECURITY_MODEL).
* The ledger-loss caveat of ADR 025 applies: inside the validity window a still-valid signed quarantine could
  run again, against whatever now holds that name. The identity and hash in the metadata make a repeat visible.

## Verified

Unit (`panopticon-file-action-tests`, 11 tests): collect of regular and empty files with known SHA-256;
refusals for relative, `..`, trailing-slash, `//`, `.`, root, missing, directory, FIFO and over-size targets;
symlink leaf and symlinked parent; time budget; quarantine refusals (unconfigured, no roots, outside roots,
name-prefix sibling, `/proc`, protected path, the store itself, symlink, directory, the sensor's own
executable); dry run; move with mode 0400, 0700 store, metadata and reused id (`store_conflict`); hard link
count; store quotas; insecure store; cross-filesystem copy (tmpfs to disk) with `*.part` cleanup. Config rules
in `command_tests`.

Real VM (Ubuntu 22.04, kernel 5.15, root, TLS fake Manager, signed commands,
`tests/e2e/run_command_auth_e2e.sh`, 51 checks including the 25 of ADR 025): signed COLLECT_FILE reports the
hash and mode; unsigned, action-tampered and retargeted quarantines are refused; a path outside the roots, the
sensor's keyring and identity, a symlink, a path through a symlinked directory and a `..` path are all
refused with the file still in place and unchanged; a signed quarantine moves the file (blob content equal,
modes 400 and 700, metadata names the original path and hash); redelivery and a restart do not run it again
and a new file created at the same path survives; a quarantine from `/run` (tmpfs) to the store (disk) copies
then removes; every action is audited as `response.action`; a `dry_run` sensor collects but verifies the
quarantine without moving.
