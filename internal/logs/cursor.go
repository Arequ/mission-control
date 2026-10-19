package logs

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type pageCursor struct {
	V          int         `json:"v"`
	From       int64       `json:"a"`
	To         int64       `json:"b"`
	Dev        string      `json:"d,omitempty"`
	High       []cursorPos `json:"h"`
	Low        *storedKey  `json:"l,omitempty"`
	N          int         `json:"n"`
	MoreBefore bool        `json:"mb,omitempty"`
}

type cursorPos struct {
	I     int             `json:"i"`
	Seen  bool            `json:"z,omitempty"`
	Empty bool            `json:"e,omitempty"`
	T     int64           `json:"t,omitempty"`
	Q     int64           `json:"q,omitempty"`
	ID    string          `json:"id,omitempty"`
	Sort  json.RawMessage `json:"s,omitempty"`
	Pit   string          `json:"p,omitempty"`
}

type storedKey struct {
	T    int64           `json:"t"`
	S    int             `json:"s"`
	Q    int64           `json:"q"`
	ID   string          `json:"id"`
	Sort json.RawMessage `json:"u,omitempty"`
}

func (p cursorPos) key() Key {
	return Key{Time: time.Unix(0, p.T).UTC(), Source: p.I, Seq: p.Q, Tie: p.ID}
}

func posFrom(h Hit) cursorPos {
	return cursorPos{
		I: h.Source, Seen: true, T: h.Time.UnixNano(), Q: h.Seq, ID: h.Tie, Sort: h.Sort, Pit: h.Pit,
	}
}

// Same reports whether the two keys are the same line. Times compare as instants.
func (k Key) Same(o Key) bool {
	return k.Time.Equal(o.Time) && k.Source == o.Source && k.Seq == o.Seq && k.Tie == o.Tie
}

func (k storedKey) key() Key {
	return Key{Time: time.Unix(0, k.T).UTC(), Source: k.S, Seq: k.Q, Tie: k.ID}
}

func storeKey(h Hit) storedKey {
	return storedKey{T: h.Time.UnixNano(), S: h.Source, Q: h.Seq, ID: h.Tie, Sort: h.Sort}
}

func encodeCursor(c pageCursor) (string, error) {
	c.V = 1
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	if len(b) > 32<<10 {
		return "", fmt.Errorf("cursor is too large")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeCursor(s string) (pageCursor, error) {
	if s == "" {
		return pageCursor{}, fmt.Errorf("cursor is empty")
	}
	if len(s) > 48<<10 {
		return pageCursor{}, fmt.Errorf("cursor is too large")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return pageCursor{}, fmt.Errorf("cursor is invalid")
	}
	var c pageCursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return pageCursor{}, fmt.Errorf("cursor is invalid")
	}
	if c.V != 1 {
		return pageCursor{}, fmt.Errorf("cursor is invalid")
	}
	return c, nil
}

type lineRef struct {
	V    int             `json:"v"`
	S    int             `json:"s"`
	T    int64           `json:"t"`
	Q    int64           `json:"q"`
	ID   string          `json:"id"`
	Sort json.RawMessage `json:"sort,omitempty"`
	Pit  string          `json:"p,omitempty"`
}

func (r lineRef) key() Key {
	return Key{Time: time.Unix(0, r.T).UTC(), Source: r.S, Seq: r.Q, Tie: r.ID}
}

func encodeLine(h Hit) string {
	b, _ := json.Marshal(lineRef{V: 1, S: h.Source, T: h.Time.UnixNano(), Q: h.Seq, ID: h.Tie, Sort: h.Sort, Pit: h.Pit})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeLine(s string) (lineRef, error) {
	if s == "" || len(s) > 16<<10 {
		return lineRef{}, fmt.Errorf("line id is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return lineRef{}, fmt.Errorf("line id is invalid")
	}
	var r lineRef
	if err := json.Unmarshal(raw, &r); err != nil || r.V != 1 {
		return lineRef{}, fmt.Errorf("line id is invalid")
	}
	return r, nil
}
