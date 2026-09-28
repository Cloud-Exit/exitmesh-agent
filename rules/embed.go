// Package rules embeds the default ExitMesh rule bundle sources, one directory per target type.
package rules

import "embed"

// FS holds kubernetes/ and host/, each a bundle directory in the layout of docs/bundle-format.md.
//
//go:embed kubernetes host
var FS embed.FS
