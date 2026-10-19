package logs

import (
	"bytes"
	"encoding/json"
	"strings"
)

// SortOrd is a lexicographic encoding of an Elasticsearch sort tuple.
// Numeric values compare as integers, so the encoding matches _shard_doc
// order rather than _id order. Empty when the hit has no sort tuple.
func SortOrd(raw json.RawMessage) string {
	if len(raw) == 0 || !json.Valid(raw) {
		return ""
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var arr []any
	if err := dec.Decode(&arr); err != nil || len(arr) == 0 {
		return ""
	}
	var b strings.Builder
	for _, v := range arr {
		b.WriteString(ordPart(v))
		b.WriteByte(0)
	}
	return b.String()
}

func ordPart(v any) string {
	switch t := v.(type) {
	case json.Number:
		return ordNumber(t.String())
	case string:
		return "s" + t
	case bool:
		if t {
			return "b1"
		}
		return "b0"
	default:
		return "z"
	}
}

// ordNumber zero-pads an integer so string order matches numeric order,
// including a leading sign class. Fractional sort values keep their fraction.
func ordNumber(s string) string {
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	whole, frac, _ := strings.Cut(s, ".")
	if whole == "" {
		whole = "0"
	}
	if len(whole) > 24 {
		whole = whole[len(whole)-24:]
	}
	padded := leftPad(whole, 24)
	if len(frac) > 9 {
		frac = frac[:9]
	}
	frac = rightPad(frac, 9)
	if neg {
		// Invert digits so a larger magnitude sorts first among negatives.
		return "0" + invertDigits(padded) + invertDigits(frac)
	}
	return "1" + padded + frac
}

func leftPad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return strings.Repeat("0", n-len(s)) + s
}

func rightPad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat("0", n-len(s))
}

func invertDigits(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= '0' && c <= '9' {
			b[i] = '9' - (c - '0')
		}
	}
	return string(b)
}
