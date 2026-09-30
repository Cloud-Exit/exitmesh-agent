package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Transport dials a control plane session.
type Transport interface {
	Dial(ctx context.Context) (Conn, error)
}

// Request is an incoming JSON-RPC request or notification.
type Request struct {
	Method       string
	Params       json.RawMessage
	Notification bool
}

// Handler serves incoming requests and notifications; a *protocol.RPCError is sent as-is, other errors as internal errors.
type Handler func(ctx context.Context, req *Request) (any, error)

// Conn is one bidirectional JSON-RPC session with binary record frames.
type Conn interface {
	Call(ctx context.Context, method string, params, result any) error
	Notify(ctx context.Context, method string, params any) error
	SendBinary(ctx context.Context, frame []byte) error
	Handle(h Handler)
	// Done is closed after the session ends and no Handler invocation is running.
	Done() <-chan struct{}
	Close() error
}

// CaptureTx is the transaction handed to Hooks inside Store.Do.
type CaptureTx interface {
	Tx
	// Reason is the checkpoint reason the hook must emit.
	Reason() protocol.CheckpointReason
	// Epoch is the epoch being appended to.
	Epoch() EpochState
	// Committed is the committed head H; a replay summary covers findings touched above it.
	Committed() uint64
}

// Hooks connects the session to the writer's state, findings, rules, and investigation tools.
type Hooks interface {
	// CaptureReplay appends only the replay anchor (reason 5) and returns the lifecycle summary as of it (SPEC 8.4 step 3).
	CaptureReplay(tx CaptureTx) (protocol.SummaryParams, error)
	// Rebaseline appends the full checkpoint that starts a new epoch.
	Rebaseline(tx CaptureTx) error
	BundleAvailable(protocol.BundleAvailableParams)
	Tools() []Tool
	Tool(ctx context.Context, name string, args json.RawMessage) (any, error)
	Health() any
}

// AppendCheckpoint appends a checkpoint of st with the reason of tx and, at sequence 1, the previous epoch and head.
func AppendCheckpoint(tx CaptureTx, st *protocol.State, iv protocol.Interval, capabilities []string) (*Entry, error) {
	ep := tx.Epoch()
	return tx.Append(protocol.TypeCheckpoint, func(env protocol.Envelope) (*protocol.Record, error) {
		ck := st.Checkpoint(tx.Reason(), iv, capabilities)
		if env.Seq == 1 {
			ck.PrevEpoch, ck.PrevHead = ep.PrevEpoch, ep.PrevHead
		}
		return &protocol.Record{Envelope: env, Checkpoint: ck}, nil
	})
}

// MCP message shapes served over the reverse channel (SPEC 9.4, 9.5).
const MCPProtocolVersion = "2025-06-18"

// Tool describes one investigation tool.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// ToolsListResult is the tools/list result.
type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

// CallToolParams is the tools/call request.
type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// Content is one MCP content block.
type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// CallToolResult is the MCP tools/call result.
type CallToolResult struct {
	Content           []Content       `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	IsError           bool            `json:"isError"`
}

// InitializeResult is the MCP initialize result.
type InitializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      ServerInfo     `json:"serverInfo"`
}

// ServerInfo names the MCP server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ToolResult converts a tool outcome into an MCP CallToolResult.
func ToolResult(v any, err error) CallToolResult {
	if err != nil {
		return CallToolResult{Content: []Content{{Type: "text", Text: err.Error()}}, IsError: true}
	}
	b, merr := json.Marshal(v)
	if merr != nil {
		return CallToolResult{Content: []Content{{Type: "text", Text: fmt.Sprintf("encode result: %v", merr)}}, IsError: true}
	}
	res := CallToolResult{Content: []Content{{Type: "text", Text: string(b)}}}
	if len(b) > 0 && b[0] == '{' {
		res.StructuredContent = b
	}
	return res
}

// RPCErrorCode returns the protocol code carried by a JSON-RPC error, or "".
func RPCErrorCode(err error) string {
	var re *protocol.RPCError
	if errors.As(err, &re) && re.Data != nil {
		return re.Data.Code
	}
	return ""
}
