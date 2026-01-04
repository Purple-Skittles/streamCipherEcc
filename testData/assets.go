package keys

import "embed"

//go:embed *.key
var TestKeyFiles embed.FS
