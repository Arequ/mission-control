package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
)

// Canonicalize rewrites decoded YAML/JSON so hashes do not flap between int and
// float64, or between nil and empty maps.
func Canonicalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			return map[string]any{}
		}
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = Canonicalize(val)
		}
		return out
	case []any:
		if t == nil {
			return []any{}
		}
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = Canonicalize(val)
		}
		return out
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		f, err := t.Float64()
		if err != nil {
			return t.String()
		}
		return canonicalizeFloat(f)
	case float64:
		return canonicalizeFloat(t)
	case float32:
		return canonicalizeFloat(float64(t))
	case int:
		return int64(t)
	case int32:
		return int64(t)
	case int64:
		return t
	case uint:
		return int64(t)
	case uint32:
		return int64(t)
	case uint64:
		if t > math.MaxInt64 {
			return fmt.Sprintf("%d", t)
		}
		return int64(t)
	default:
		return v
	}
}

func canonicalizeFloat(f float64) any {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Sprintf("%v", f)
	}
	if f == math.Trunc(f) && f >= math.MinInt64 && f <= math.MaxInt64 {
		return int64(f)
	}
	return f
}

// SpecHash is a stable hash of labels, annotations, and spec.
func SpecHash(r Resource) (string, error) {
	doc := struct {
		Labels      map[string]string `json:"labels,omitempty"`
		Annotations map[string]string `json:"annotations,omitempty"`
		Spec        any               `json:"spec"`
	}{
		Labels:      emptyAsNil(r.Metadata.Labels),
		Annotations: emptyAsNil(r.Metadata.Annotations),
		Spec:        Canonicalize(r.Spec),
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func emptyAsNil(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return m
}

func decodeSpec(spec map[string]any, dest any) error {
	b, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return err
	}
	return nil
}

func specMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	canon, ok := Canonicalize(raw).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("spec did not encode as an object")
	}
	return canon, nil
}
