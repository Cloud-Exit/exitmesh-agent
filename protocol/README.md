# ExitMesh History Protocol

|Path|Contents|
|---|---|
|`SPEC.md`|The normative specification (EMHP v1).|
|`cddl/emhp-v1.cddl`|CDDL for every record and body, the hash inputs, the frame payload, and the export header.|
|`reference/emhp.py`|Language-neutral reference oracle, Python 3 standard library only.|
|`reference/test_emhp.py`|Oracle unit tests and the Python runner over every vector file.|
|`vectors/*.json`|Language-neutral test vectors. Every implementation MUST pass all of them.|
|`genvectors/`|Deterministic Go generator of `vectors/` (fixed identities, times, and PRNG seeds).|

## Running

```sh
go test ./pkg/protocol/                                   # Go runner (vectors_test.go) and fuzz seeds
python3 -m unittest discover -s protocol/reference -v     # Python oracle and runner
go run ./protocol/genvectors                              # regenerate protocol/vectors
go run ./protocol/genvectors -check                       # fail if the committed vectors are stale
go test ./pkg/protocol/ -run '^$' -fuzz FuzzDecode        # also FuzzFold
```

Run all commands from the repository root. Regeneration is byte for byte reproducible, and `go test ./protocol/genvectors` fails when the committed files differ from the generator output. The generator checks every vector against `pkg/protocol` while writing it; the Python oracle verifies them independently.

## Oracle acceptance rules

`emhp.decode_record` accepts exactly what `pkg/protocol.Decode` accepts and returns the same rejection code. Beyond the CDDL, a reader enforces:

- Strict CBOR: any violation of SPEC 3.1 or 3.2 (including simple values other than `false`, `true`, `null`, and map keys that are arrays, maps, or integers below -2^63) is `malformed`; an input above 4 MiB is `too_large` before parsing.
- Envelope and body maps have only unsigned integer keys (`malformed` otherwise). An unknown key below 1000 is `unsupported_field`, as are protocol versions other than 1, unknown record types, and any extension key inside an op or inside the scope status of a `scope-set` op.
- A present optional key with a zero or empty value is `malformed`, as are unsorted or duplicate resources, edges, capabilities, finding resources, and range findings, ops of a range body out of canonical order, and the empty strings the CDDL marks `.size (1..)` outside ops (resource uid and kind, scope keys, finding identity and provenance strings).
- Inside ops these rules yield `invalid_op`: empty uid, kind, edge endpoint, edge type, or scope key, an unknown op kind, empty `changes`, an unknown delete reason, a scope state above 2, two ops for one key, and a delta without ops.
- `null` or an out-of-range integer inside a field value, and a non-text key in a nested value map, are `invalid_value`; a non-text key at the top of a field map is `malformed`.
- Chain rules of SPEC 4.1 checkable on one record (including incarnation 0) are `invalid_chain`; a checkpoint whose content does not hash to its state hash is `invalid_state_hash`.
- Extension key values are preserved as bytes and not validated as field values. A checkpoint's scope status may carry extension keys; they do not enter state or the state hash.

Codes are checked in the order of `pkg/protocol`: strict CBOR, envelope fields, body, unknown envelope keys, then record validation.

## Vector files

All byte strings, hashes, and 16-byte identifiers are lowercase hex. Integers are JSON numbers (exact up to 2^64-1). Record types are named `checkpoint`, `delta`, `range`, `finding`.

A `pad` object, where present, extends the decoded `hex` bytes with `byte` (one hex byte) repeated until the input is `length` bytes long. It keeps multi-megabyte inputs small.

### encoding.json

```
{ "description": str,
  "values":  [ { "name": str, "value": typed, "hex": str } ],
  "records": [ { "name": str, "hex": str, "pad"?: pad, "type": str, "seq": int, "record_hash": str } ],
  "chains":  [ { "name": str, "target_id": str, "epoch": str, "writer_id": str, "genesis": str,
                 "records": [ { "hex": str, "type": str, "seq": int, "record_hash": str, "chain_hash": str } ] } ] }
typed = {"uint": decimal} | {"nint": decimal} | {"float": 16 hex digits of the IEEE 754 double}
      | {"text": str} | {"bytes": hex} | {"bool": bool} | {"null": true}
      | {"array": [typed]} | {"map": [[typed key, typed value]]}
```

`values`: encoding the typed value deterministically yields `hex`, and strictly decoding `hex` then re-encoding yields `hex`. Map pairs are listed unsorted. `records`: each input decodes and validates, with the given type, sequence, and record hash. `chains`: records appended in order to a chain whose parent-0 hash is `genesis` produce the listed chain hashes.

### rejection.json

```
{ "description": str, "vectors": [ { "name": str, "hex": str, "pad"?: pad, "error": code } ] }
code = "malformed" | "too_large" | "unsupported_field" | "invalid_value" | "invalid_chain" | "invalid_op" | "invalid_state_hash"
```

Decoding the input as one record fails with `error`.

### fold.json

```
{ "description": str,
  "vectors": [ { "name": str, "prefix": [hex], "run": [hex], "error"?: "fold",
                 "expect"?: { "span": [a, b], "range_body": hex, "ops": int, "finding_seqs": [int], "flags": int,
                              "uncertain": [[start, end]], "state_before": hash, "state_after": hash,
                              "range_record": hex, "range_chain_hash": hash } } ] }
```

`prefix` is the chain from sequence 1 to a-1 and `run` the records a through b. With `error`, folding `run` fails with that code (`prefix` may be empty). With `expect`: the state after replaying `prefix` hashes to `state_before`; folding `run` yields a range body whose deterministic encoding is `range_body`, with the listed span, op count, preserved finding sequences, flags, and intervals; applying the folded ops to the state at a-1, and replaying `run`, both give `state_after`. `range_record` is the range record at b whose envelope copies `target_id`, `epoch`, `writer_id`, `incarnation`, `time`, and `schema` from the last run record, with `parent` a-1 (the first run record's parent) and the last run record's `base`; `range_chain_hash` is its chain hash after `prefix`.

### reconstruction.json

```
{ "description": str,
  "vectors": [ { "name": str, "records": [hex],
                 "states": [ { "seq": int, "state_hash": hash | "unavailable" } ],
                 "chain_hashes": [ { "seq": int, "chain_hash": hash } ],
                 "boundaries": [ { "seq": int, "expected": hash, "got": hash } ],
                 "unavailable": [[from, to]],
                 "error": null | { "index": int, "code": code } } ] }
```

Records are decoded and replayed in order, starting a chain for the first record's target, epoch, and writer, until the first failure. `error` names the index of the first record that fails to decode, link (SPEC 4.1), or apply (SPEC 4.3), and its code. `states` lists every sequence from 1 to the replayed head: the state hash there, or `unavailable` strictly inside a range span. `chain_hashes` lists each replayed record's chain hash. `boundaries` lists checkpoints other than the first whose `state-hash` (`expected`) differs from the replayed state at their parent (`got`); reconstruction continues from the checkpoint content. `unavailable` lists the spans a through b-1 of replayed range records.

### ids.json

```
{ "description": str,
  "finding_ids":   [ { "target_id": str, "dedup_key": str, "first_seen": int, "finding_id": str } ],
  "query_hashes":  [ { "language": str, "query": str, "source": str, "query_hash": hash } ],
  "genesis":       [ { "target_id": str, "epoch": str, "writer_id": str, "genesis": hash } ],
  "chain_links":   [ { "prev": hash, "record_hash": hash, "chain_hash": hash } ],
  "record_hashes": [ { "hex": str, "record_hash": hash } ],
  "state_hashes":  [ { "name": "empty", "state_hash": hash } ] }
```

Each entry is the SPEC 6.2 or 7 function of its inputs.

### ownership.json

```
{ "description": str,
  "vectors": [ { "name": str, "credential_valid": bool,
                 "state": { "target_type": "kubernetes" | "host", "revoked": bool, "conflict": bool,
                            "pending_binding": bool, "enrolled_machine_id": str, "open_epoch": id | null,
                            "epochs": [ { "id": id, "owner": id, "open": bool, "head": point, "chain_hashes": [point] } ],
                            "retired": [id], "highest_incarnation": [ { "writer_id": id, "incarnation": int } ],
                            "active": null | { "session_id": str, "writer_id": id, "incarnation": int } },
                 "hello": { "writer_id": id, "incarnation": int, "epoch": id,
                            "epoch_open": null | { "reason": str, "prev_epoch": id | null, "prev_head": int | null },
                            "last_committed": null | point, "machine_id": str },
                 "expect": { "row": int, "accept": bool, "code": str, "outcome": "" | "resume" | "opened",
                             "open_epoch": bool, "close_epoch": id | null, "retire_writer": id | null,
                             "supersede": bool, "set_conflict": bool, "clear_binding": bool,
                             "audit": bool, "alarm": bool } } ] }
point = { "seq": int, "chain_hash": hash }
```

Evaluating the SPEC 8.3 table for `hello` against `state` gives `expect`. An epoch's committed chain hash at a sequence is known only if listed in its `chain_hashes`; an unknown one is a mismatch for row 9. `supersede` on row 10 and 12 means an active session of the same writer with a lower incarnation; on rows 13 and 14 it means any active session. Every rejection is audited; rows 12 to 14 are audited; rows 3, 8, and 15 raise an alarm.
