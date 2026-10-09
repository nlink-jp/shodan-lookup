package mcp

import _ "embed"

//go:embed usage.md
var usageDoc string

// UsageDoc returns the embedded manual — what get_usage answers with, and the
// canonical reference for this server's tools. The mcp-tactics skill documents
// no parameters by design, so this is what an agent reads before its first call.
func UsageDoc() string { return usageDoc }
