package logs

import (
	"fmt"
	"regexp"
	"strings"
)

// placeholderRE matches the only three tokens a device-scoped view may bind.
var placeholderRE = regexp.MustCompile(`\{\{\s*(serial|hostname|hardware_uuid)\s*\}\}`)

// anyPlaceholder finds every {{...}} so unknown names fail closed.
var anyPlaceholder = regexp.MustCompile(`\{\{([^{}]*)\}\}`)

// Substitute replaces {{serial}}, {{hostname}}, and {{hardware_uuid}} with
// quoted KQL literals. Values are escaped. Anything left that looks like a
// placeholder is an error. The raw value is never concatenated into the query.
func Substitute(kql string, bind Bind) (string, error) {
	if strings.Contains(kql, "{{") && strings.Contains(kql, "}}") {
		for _, m := range anyPlaceholder.FindAllStringSubmatch(kql, -1) {
			name := strings.TrimSpace(m[1])
			switch name {
			case "serial", "hostname", "hardware_uuid":
			default:
				return "", fmt.Errorf("unknown KQL placeholder {{%s}}", name)
			}
		}
	}
	if !strings.Contains(kql, "{{") {
		return kql, nil
	}
	var bad error
	out := placeholderRE.ReplaceAllStringFunc(kql, func(match string) string {
		name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(match, "{{"), "}}"))
		var value string
		switch name {
		case "serial":
			value = bind.Serial
		case "hostname":
			value = bind.Hostname
		case "hardware_uuid":
			value = bind.HardwareUUID
		default:
			bad = fmt.Errorf("unknown KQL placeholder {{%s}}", name)
			return match
		}
		quoted, err := quoteKQL(value)
		if err != nil {
			bad = err
			return match
		}
		return quoted
	})
	if bad != nil {
		return "", bad
	}
	if strings.Contains(out, "{{") || strings.Contains(out, "}}") {
		return "", fmt.Errorf("KQL still contains a placeholder after substitution")
	}
	return out, nil
}

// quoteKQL returns a double-quoted KQL literal. The result is one token.
func quoteKQL(s string) (string, error) {
	if len(s) > 512 {
		return "", fmt.Errorf("placeholder value is too long")
	}
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			if r < 0x20 || r == 0x7f {
				return "", fmt.Errorf("placeholder value contains a control character")
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

// UsesPlaceholder reports whether kql binds a device field.
func UsesPlaceholder(kql string) bool {
	return placeholderRE.MatchString(kql)
}
