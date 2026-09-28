// Command releaseinfo prints the protocol, schema, and rule engine versions for release notes as KEY=VALUE lines.
package main

import (
	"fmt"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func main() {
	fmt.Printf("EXITMESH_PROTOCOL_VERSION=%d\n", protocol.Version)
	fmt.Printf("EXITMESH_SCHEMA_VERSION=%d\n", protocol.SchemaVersion)
	fmt.Printf("EXITMESH_ENGINE_VERSION=%d\n", bundle.EngineVersion)
}
