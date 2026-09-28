# Log collection contract

This document fixes how the agent reads log files: which files it opens, how it follows rotation, how it reassembles and bounds lines, how it names streams, how it persists positions, and how it discloses gaps. It covers PRD L1, L2, L3, and L8 and the on-demand read of I1a. The implementation lives in `internal/telemetry/logs`: `Tailer` for pod logs, `FileTailer` for host files, and `ReadRange` for investigation reads.

## Which streams are read

A stream is read only when the active stream filter accepts it. The filter is derived from the active LogQL rules (`rules/logql` `Program.Matches`) and is evaluated on stream labels before any file of the stream is opened, so logs of unselected namespaces, workloads, and containers are never opened, parsed, or buffered.

- Until the first filter is installed, nothing is read and persisted positions are left untouched. This keeps positions across a restart while the bundle loads.
- The filter is re-evaluated for every stream whenever rules change. A stream that stops being selected has its files closed and its persisted positions deleted.
- A pod stream is selected when the filter accepts it with `stream="stdout"` or with `stream="stderr"`. Lines of the other CRI stream are dropped after the tag is read, before reassembly.

## Pod log identity mapping

The node agent reads `/var/log/pods/<namespace>_<pod>_<uid>/<container>/<N>.log`, where `N` is the container restart count. Directory names map to labels as follows:

|Label|Source|
|---|---|
|`namespace`|first `_` separated field of the pod directory|
|`pod`|second field|
|`pod_uid`|third field; it distinguishes a recreated pod with the same name|
|`container`|container directory name|
|`stream`|`stdout` or `stderr`, from each line|
|`node`|the node the agent runs on|
|workload labels|returned by the enrichment function from the local pod watch (for example `workload`, `workload_kind`); they never override the labels above|

Kubernetes forbids `_` in namespace and pod names, so the split is unambiguous. When the pod watch does not know a pod yet, the stream waits up to one minute (`EnrichWait`) for enrichment before it is evaluated with the directory labels alone. When enrichment later disappears (the pod left the watch while files remain), the last known labels are kept. All files `N.log` of a container directory form one stream and are read in order of `N`.

Host files are streams labeled `filename` (the absolute path) plus the static host labels. Only files under the administrator allowlist (`host.logFiles`) are discovered; directories are walked to depth 3 and names that look rotated (`.1`, `.gz`, `-20260901`, `.old`) are not streams of their own.

## Rotation

Files are identified by device and inode, never by name, and each open file keeps its descriptor until it is fully read.

Kubelet rotation renames `N.log` to `N.log.<YYYYMMDD-hhmmss>`, the runtime reopens a new `N.log`, and older rotated files are compressed to `.gz` and later deleted.

- A renamed file is recognized by inode. Its remainder, including bytes the runtime writes before it reopens, is read before the new `N.log`, so lines stay in order.
- A new `N.log` in a stream that is already tailed is read from offset zero.
- When a rotated file is compressed and removed while tailed, the remainder is read through the open descriptor; the `.gz` file is not read.
- On restart, a persisted file that is no longer present is looked up among the stream's `.gz` files. A `.gz` file is read only when its decompressed first bytes match the persisted fingerprint, which proves the saved offset belongs to it; reading then starts at that offset.
- On restart, uncompressed rotated files newer than the last rotation seen before the restart are read from zero. Compressed rotated files newer than that, whose offset cannot belong to any persisted file, are not read and are reported as `missed_rotation`.

Host files follow rename-and-create (logrotate default): when the path points to a new inode, the old descriptor is kept and read until the file stops growing for `RotatedIdle` (30 s) or is unlinked, then closed. On restart the old inode is searched among siblings (`<name>.1`, `<name>-<date>`) and `.gz` siblings are matched by fingerprint as above. `copytruncate` is detected as a truncation (below).

## Line formats and multiline records

Each physical line is parsed as one of:

- CRI: `<RFC 3339 timestamp> <stream> <tag> <content>`, where the tag is `P` (partial) or `F` (full).
- docker json-file: `{"log":"...","stream":"...","time":"..."}`; a `log` value without a trailing newline is partial.

Partial records of one CRI stream are joined until the next full record, and the line carries the timestamp of its first part. A partial group is carried across a rotation boundary within the stream. Joining is capped at `MaxLineBytes` (64 KiB): further parts are discarded and the line is flagged truncated. Physical lines that match neither format are counted as unparsed and dropped.

Application multiline records (stack traces, pretty-printed JSON) are not joined: every newline-terminated record written by the container is its own line. LogQL rules match individual lines.

Host file lines are raw text; a trailing carriage return is removed and the time is the read time.

## Oversized lines

A physical line is buffered up to a physical cap (`2 * MaxLineBytes + 1024` for pod logs, `MaxLineBytes` for host files); the rest of the physical line is discarded up to its newline while its last 512 bytes are kept, so a cut docker json line still yields its stream and time. The delivered text is at most `MaxLineBytes` and carries `Truncated: true`. Truncation never loses the following line.

## Positions and restart

For each stream the agent persists, in the node key-value store (`kv.Store`), per file: device, inode, last name, consumed offset, size, and a fingerprint (hash of the first 1 KiB). Positions are written in one batch per checkpoint (every 10 s) and on shutdown; a checkpoint writes only streams whose positions changed.

- The consumed offset is always at a line boundary. While a partial group is open, the file also records where the group began for each CRI stream. A restart re-reads from the earliest group start, feeds only the open group's records back into reassembly, and skips every line delivered before the checkpoint, so reassembled lines are neither duplicated nor lost.
- If the file where an open group began is gone at restart, the rest of the group is delivered flagged truncated.
- Lines delivered after the last checkpoint are delivered again after a crash (at least once between checkpoints). A graceful stop delivers each line exactly once.
- A stream seen for the first time when the agent starts, or selected again after a filter change, starts at the end of its current file; history is not backfilled. Streams created after the agent started are read from the start.
- Positions carry no log content. Pending partial content is never persisted.

## Gap disclosure

Gaps are reported as events (`Event{Kind, Path, Labels, Time, LostBytes, Detail}`), counted in `Stats().Gaps`, and never silently absorbed. `LostBytes` is `-1` when the amount is unknown.

|Kind|Meaning|
|---|---|
|`truncated`|a tailed file shrank below the read offset, or its first bytes changed (copytruncate or rewrite); reading restarts at zero and bytes written before the truncation and not yet read are lost|
|`offset_beyond_size`|at restart the persisted file is present with a matching fingerprint but is shorter than the saved offset; reading restarts at zero|
|`missed_rotation`|at restart a persisted file is gone and no `.gz` file matches its fingerprint, or a compressed rotated file appeared while the agent was not tailing; `LostBytes` is the known unread size when available|
|`read_error`|a file could not be opened, read, or checkpointed|

## On-demand reads

`ReadRange` serves investigation reads of streams no rule tails. It applies the stream selector the same way, reads current, rotated, and compressed files whose modification time is not before the range start (newest file first), reassembles partials within a file, keeps lines whose time is in `[from, to]`, and returns them oldest first with the newest last. It is bounded by `MaxLines` (5000), `MaxBytes` of returned text (4 MiB), and `MaxScanBytes` read from disk (256 MiB): when a line or byte limit is hit the oldest matching lines are dropped and the result is marked `Truncated` with the number omitted; when the scan budget is hit the result is marked `ScanLimited`. It persists nothing and keeps nothing after it returns.
