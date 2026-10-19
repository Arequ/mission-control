// Package openapi serves the embedded OpenAPI document.
package openapi

import _ "embed"

// Spec is the OpenAPI 3 description of /api/v1 and the osquery TLS routes.
//
//go:embed openapi.yaml
var Spec []byte
