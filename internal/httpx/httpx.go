// Package httpx holds small JSON helpers shared by the API and osquery handlers.
package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// WriteJSON writes a JSON response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes the standard API error envelope.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

// ReadJSON decodes a request body. When strict is set, unknown fields fail.
func ReadJSON(r *http.Request, limit int64, dest any, strict bool) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, limit))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(dest); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing data")
		}
		if !errors.Is(err, io.EOF) {
			return err
		}
	}
	return nil
}
