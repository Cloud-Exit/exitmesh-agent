// Package client implements the transport-agnostic writer session of the History Protocol
// (protocol/SPEC.md sections 8 and 9): hello, resume and drain, windowed replay, acknowledgements,
// divergence handling with rebaseline, and the reverse MCP channel.
//
// # Store contract
//
// The client drives a durable spool through the Store interface. It mirrors the subset of
// internal/spool used by the writer session; *spool.Spool is adapted to it by a thin wrapper
// because Store.Do passes the Tx interface rather than a concrete transaction type.
//
//   - WriterID and Incarnation are fixed for the lifetime of the handle. The incarnation is
//     incremented and made durable before the handle is returned.
//   - Identity returns the enrolled target, credential, and machine ID; SetIdentity persists a
//     replacement durably before returning (credential rotation and de-enrollment use it).
//   - Epoch returns the current epoch and its chain position (the highest sequence ever assigned
//     is Chain.Head). OpenEpoch starts a new epoch: entries above prevHead must have been
//     discarded first, the remaining entries of the previous epoch are dropped, and LastCommitted
//     resets. MarkRegistered records that the control plane accepted the epoch.
//   - Do holds the sequence lock for the duration of fn. Every append happens inside Do through
//     Tx.Append, which assigns the next envelope, encodes the record, and links its chain hash.
//     Appends become durable when fn returns nil; if fn fails, its appends are discarded.
//   - Entries(from) returns copies of the spooled entries with Seq >= from in chain order, or a
//     bounded prefix of them holding at least one entry. A range record produced by coalescing
//     appears once, at the end of its span.
//   - MarkTransmitted moves entries to TransmittedUnconfirmed durably and fails with ErrNotSpooled,
//     marking nothing, if any sequence is no longer spooled. Transmitted entries never change.
//   - Commit is cumulative: it verifies the chain hash at seq, deletes every entry at or below it,
//     and records the committed head. A chain hash that differs from the writer's, a sequence above
//     the highest assigned, or a sequence inside a coalesced span returns ErrDivergence.
//   - DiscardAbove deletes every entry above seq; it precedes OpenEpoch during a rebaseline.
//   - Notify is signaled after appends and commits.
//   - SetHalted records a stop code for this writer process; Do refuses to run while halted.
//
// MemStore is a goroutine-safe in-memory Store with the full semantics above, for tests.
package client
