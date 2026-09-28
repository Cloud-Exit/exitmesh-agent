// Package hostfacts collects normalized Linux host state, reports per-fact availability, and tracks it as protocol ops.
package hostfacts

import (
	"sort"
	"strings"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Resource kinds.
const (
	KindOS          = "host/OS"
	KindKernel      = "host/Kernel"
	KindCPU         = "host/CPU"
	KindMemory      = "host/Memory"
	KindBlockDevice = "host/BlockDevice"
	KindFilesystem  = "host/Filesystem"
	KindMount       = "host/Mount"
	KindInterface   = "host/Interface"
	KindSocket      = "host/Socket"
	KindUnit        = "host/Unit"
	KindTimer       = "host/Timer"
	KindPackage     = "host/Package"
	KindProcess     = "host/Process"
)

// Edge types.
const (
	EdgeMainProcess  = "main_process"
	EdgeDevice       = "device"
	EdgeFilesystem   = "filesystem"
	EdgePartitionOf  = "partition_of"
	EdgeProvidesUnit = "provides_unit"
	EdgeProcess      = "process"
	EdgeUnit         = "unit"
	EdgeTriggers     = "triggers"
)

// Reason codes carried in scope statuses and socket fields.
const (
	ReasonSourceAbsent    = "source_absent"
	ReasonPermission      = "permission_denied"
	ReasonDBus            = "dbus_unavailable"
	ReasonReadFailed      = "read_failed"
	ReasonOtherUserFD     = "other_user_fd"
	ReasonOwnerNotFound   = "owner_not_found"
	ReasonDependency      = "dependency_unavailable"
	ReasonProcessVanished = "process_vanished"
	ReasonCapacityDenied  = "capacity_permission_denied"
)

// Status is the availability of one cataloged fact or edge in one collection.
type Status struct {
	State  protocol.ScopeState
	Reason string
}

// Snapshot is the result of one collection before diffing.
type Snapshot struct {
	Resources map[string]protocol.Resource
	Edges     map[protocol.EdgeKey]map[string]any
	Status    map[string]Status
}

func newSnapshot() *Snapshot {
	return &Snapshot{Resources: map[string]protocol.Resource{}, Edges: map[protocol.EdgeKey]map[string]any{}, Status: map[string]Status{}}
}

func (s *Snapshot) add(uid, kind, name string, fields map[string]any) {
	s.Resources[uid] = protocol.Resource{UID: uid, Kind: kind, Name: clean(name), Fields: fields}
}

func (s *Snapshot) edge(from, typ, to string) {
	s.Edges[protocol.EdgeKey{From: from, Type: typ, To: to}] = map[string]any{}
}

func (s *Snapshot) set(id string, st protocol.ScopeState, reason string) {
	s.Status[id] = Status{State: st, Reason: reason}
}

func (s *Snapshot) ok(id string) { s.set(id, protocol.ScopeComplete, "") }

func (s *Snapshot) unavailable(id, reason string) { s.set(id, protocol.ScopeUnavailable, reason) }

// tally accumulates per-item outcomes into a fact status.
type tally struct {
	ok      int
	reasons map[string]int
}

func (t *tally) good() { t.ok++ }

func (t *tally) bad(reason string) {
	if t.reasons == nil {
		t.reasons = map[string]int{}
	}
	t.reasons[reason]++
}

func (t *tally) status() Status {
	if len(t.reasons) == 0 {
		return Status{State: protocol.ScopeComplete}
	}
	keys := make([]string, 0, len(t.reasons))
	for k := range t.reasons {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if t.reasons[keys[i]] != t.reasons[keys[j]] {
			return t.reasons[keys[i]] > t.reasons[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if t.ok == 0 {
		return Status{State: protocol.ScopeUnavailable, Reason: keys[0]}
	}
	return Status{State: protocol.ScopePartial, Reason: keys[0]}
}

func clean(s string) string { return strings.ToValidUTF8(s, "�") }

func strList(in []string) []any {
	s := append([]string(nil), in...)
	sort.Strings(s)
	out := make([]any, 0, len(s))
	for i, v := range s {
		if i > 0 && v == s[i-1] {
			continue
		}
		out = append(out, clean(v))
	}
	return out
}

func uid(kind string, parts ...string) string {
	k := "host:" + strings.ToLower(strings.TrimPrefix(kind, "host/"))
	if len(parts) == 0 {
		return k
	}
	return k + ":" + clean(strings.Join(parts, "|"))
}

// ScopeKey returns the scope key of a cataloged fact or edge.
func ScopeKey(id string) string { return "host/" + id }
