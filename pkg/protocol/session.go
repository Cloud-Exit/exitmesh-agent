package protocol

import "encoding/json"

// JSON-RPC method names of the tunnel binding (SPEC 9.4).
const (
	MethodHello            = "history.hello"
	MethodSummary          = "history.summary"
	MethodAck              = "history.ack"
	MethodReject           = "history.reject"
	MethodSuperseded       = "session.superseded"
	MethodBundleFetch      = "bundle.fetch"
	MethodBundleAvailable  = "bundle.available"
	MethodHealth           = "agent.health"
	MethodAudit            = "investigation.audit"
	MethodDeenroll         = "target.deenroll"
	MethodDeenrolled       = "target.deenrolled"
	MethodCredentialRotate = "credential.rotate"
	MethodInitialize       = "initialize"
	MethodPing             = "ping"
	MethodToolsList        = "tools/list"
	MethodToolsCall        = "tools/call"
)

// Hello decisions and rejection codes (SPEC 8.3).
const (
	DecisionResume = "resume"
	DecisionOpened = "opened"

	CodeUnauthorized        = "unauthorized"
	CodeIdentityConflict    = "identity_conflict"
	CodeWriterRetired       = "writer_retired"
	CodeEpochClosed         = "epoch_closed"
	CodeNotOwner            = "not_owner"
	CodeStaleIncarnation    = "stale_incarnation"
	CodeDivergence          = "divergence"
	CodeInvalidHello        = "invalid_hello"
	CodeUnsupportedProtocol = "unsupported_protocol"
)

// JSON-RPC error codes used on the tunnel.
const (
	RPCParseError     = -32700
	RPCInvalidRequest = -32600
	RPCMethodNotFound = -32601
	RPCInvalidParams  = -32602
	RPCInternalError  = -32603
	RPCUnauthorized   = -32001
	RPCForbidden      = -32002
	RPCHistoryReject  = -32010
)

// Target types.
const (
	TargetKubernetes = "kubernetes"
	TargetHost       = "host"
)

// Binary frame constants (SPEC 9.3).
const (
	FrameRecordBatch  byte = 0x01
	CompressionNone   byte = 0x00
	CompressionZstd   byte = 0x01
	MaxFramePayload        = 16 << 20
	DefaultWindowSize      = 8 << 20
	TunnelSubprotocol      = "exitmesh.v1"
	TunnelPath             = "/agent/v1/tunnel"
	EnrollPath             = "/agent/v1/enroll"
)

// RPCMessage is a JSON-RPC 2.0 request, notification, or response.
type RPCMessage struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *RPCError        `json:"error,omitempty"`
}

// RPCError is a JSON-RPC error object; Data.Code carries the protocol code.
type RPCError struct {
	Code    int           `json:"code"`
	Message string        `json:"message"`
	Data    *RPCErrorData `json:"data,omitempty"`
}

// RPCErrorData carries the product-level error code.
type RPCErrorData struct {
	Code string `json:"code"`
}

func (e *RPCError) Error() string {
	if e.Data != nil && e.Data.Code != "" {
		return e.Data.Code + ": " + e.Message
	}
	return e.Message
}

// AgentInfo is reported on every connect (PRD U1).
type AgentInfo struct {
	Version           string `json:"version"`
	Protocol          int    `json:"protocol"`
	Schema            int    `json:"schema"`
	Engine            int    `json:"engine"`
	Role              string `json:"role"`
	Platform          string `json:"platform,omitempty"`
	KubernetesVersion string `json:"kubernetes_version,omitempty"`
	OS                string `json:"os,omitempty"`
}

// EpochOpen declares that the hello opens a new epoch.
type EpochOpen struct {
	Reason    string   `json:"reason"`
	PrevEpoch *EpochID `json:"prev_epoch,omitempty"`
	PrevHead  *uint64  `json:"prev_head,omitempty"`
}

// Epoch-open reasons.
const (
	OpenInitial      = "initial"
	OpenRebaseline   = "rebaseline"
	OpenWriterChange = "writer_change"
)

// ChainPoint is a sequence and its chain hash.
type ChainPoint struct {
	Seq       uint64 `json:"seq"`
	ChainHash Hash   `json:"chain_hash"`
}

// HelloParams opens a history session.
type HelloParams struct {
	TargetID      string      `json:"target_id"`
	TargetType    string      `json:"target_type"`
	WriterID      WriterID    `json:"writer_id"`
	Incarnation   uint64      `json:"incarnation"`
	Epoch         EpochID     `json:"epoch"`
	EpochOpen     *EpochOpen  `json:"epoch_open"`
	LastCommitted *ChainPoint `json:"last_committed"`
	MachineID     string      `json:"machine_id,omitempty"`
	Agent         AgentInfo   `json:"agent"`
}

// Compat is the control plane's compatibility verdict (PRD U2, U3).
type Compat struct {
	Status         string `json:"status"`
	MinimumVersion string `json:"minimum_version,omitempty"`
	LatestVersion  string `json:"latest_version,omitempty"`
	Message        string `json:"message,omitempty"`
}

// Compatibility statuses.
const (
	CompatOK              = "ok"
	CompatUpdateAvailable = "update_available"
	CompatOutdated        = "outdated"
	CompatUnsupported     = "unsupported"
)

// HelloResult accepts a history session.
type HelloResult struct {
	Decision      string     `json:"decision"`
	SessionID     string     `json:"session_id"`
	Epoch         EpochID    `json:"epoch"`
	Head          ChainPoint `json:"head"`
	WindowBytes   int64      `json:"window_bytes"`
	MaxFrameBytes int64      `json:"max_frame_bytes"`
	Compat        Compat     `json:"compat"`
}

// Lifecycle states in a summary.
const (
	LifecycleFiring   = "firing"
	LifecycleResolved = "resolved"
	LifecycleStale    = "stale"
)

// SummaryEntry is one finding in a lifecycle summary (PRD 7.7).
type SummaryEntry struct {
	FindingID      string `json:"finding_id"`
	DedupKey       string `json:"dedup_key"`
	State          string `json:"state"`
	FirstSeen      uint64 `json:"first_seen"`
	LastTransition uint64 `json:"last_transition"`
	EvalTime       uint64 `json:"eval_time"`
	RuleID         string `json:"rule_id,omitempty"`
	BundleVersion  string `json:"bundle_version,omitempty"`
	Severity       string `json:"severity"`
}

// SummaryParams is the finding lifecycle summary at the replay watermark.
type SummaryParams struct {
	Epoch     EpochID        `json:"epoch"`
	Watermark uint64         `json:"watermark"`
	Head      uint64         `json:"head"`
	Entries   []SummaryEntry `json:"entries"`
}

// AckParams reports the committed head.
type AckParams struct {
	Epoch     EpochID `json:"epoch"`
	Seq       uint64  `json:"seq"`
	ChainHash Hash    `json:"chain_hash"`
}

// RejectParams reports a rejected record.
type RejectParams struct {
	Epoch   EpochID `json:"epoch"`
	Seq     uint64  `json:"seq"`
	Code    string  `json:"code"`
	Message string  `json:"message,omitempty"`
}

// SupersededParams closes a superseded session.
type SupersededParams struct {
	SessionID string `json:"session_id"`
}

// BundleAvailableParams announces a new target bundle version.
type BundleAvailableParams struct {
	Version    string `json:"version"`
	TargetType string `json:"target_type"`
}

// BundleFetchParams requests the assigned rule bundle.
type BundleFetchParams struct {
	TargetType string `json:"target_type"`
	Have       string `json:"have"`
}

// BundleFetchResult carries a signed bundle and the latest key manifest.
type BundleFetchResult struct {
	Version     string `json:"version"`
	Bundle      []byte `json:"bundle"`
	Signature   []byte `json:"signature"`
	KeyManifest []byte `json:"key_manifest"`
	// KeyManifestChain holds earlier manifests in ascending sequence so a writer that only trusts an older root can follow rotations.
	KeyManifestChain [][]byte `json:"key_manifest_chain,omitempty"`
}

// CredentialRotateParams delivers a rotated credential.
type CredentialRotateParams struct {
	Credential   string `json:"credential"`
	CredentialID string `json:"credential_id"`
}

// DeenrollParams requests explicit de-enrollment.
type DeenrollParams struct {
	Reason string `json:"reason"`
}

// EnrollRequest exchanges an enrollment token for a credential (SPEC 9.2).
type EnrollRequest struct {
	Token      string    `json:"token"`
	WriterID   WriterID  `json:"writer_id"`
	TargetType string    `json:"target_type"`
	MachineID  string    `json:"machine_id,omitempty"`
	Hostname   string    `json:"hostname,omitempty"`
	Agent      AgentInfo `json:"agent"`
}

// EnrollResponse returns the target identity and credential.
type EnrollResponse struct {
	TargetID     string `json:"target_id"`
	Credential   string `json:"credential"`
	CredentialID string `json:"credential_id"`
}
