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
	// Seen is the identity of lines already returned inside the open page.
	// Tail re-reads that range on a fresh point-in-time and drops these so a
	// line ingested late, with a timestamp inside the page, is returned once.
	Seen []seenRef `json:"seen,omitempty"`
}

type seenRef struct {
	S  int    `json:"s"`
	T  int64  `json:"t"`
	Q  int64  `json:"q"`
	ID string `json:"id"`
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
	return Key{Time: time.Unix(0, p.T).UTC(), Source: p.I, Seq: p.Q, Tie: p.ID, Ord: SortOrd(p.Sort)}
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
	return Key{Time: time.Unix(0, k.T).UTC(), Source: k.S, Seq: k.Q, Tie: k.ID, Ord: SortOrd(k.Sort)}
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
	// Point-in-time ids plus the open page's line identities.
	const maxCursor = 256 << 10
	if len(b) > maxCursor && len(c.Seen) > 0 {
		c.Seen = trimSeen(c.Seen, len(c.Seen)/2)
		return encodeCursor(c)
	}
	if len(b) > maxCursor {
		return "", fmt.Errorf("cursor is too large")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeCursor(s string) (pageCursor, error) {
	if s == "" {
		return pageCursor{}, fmt.Errorf("cursor is empty")
	}
	if len(s) > 384<<10 {
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
	return Key{Time: time.Unix(0, r.T).UTC(), Source: r.S, Seq: r.Q, Tie: r.ID, Ord: SortOrd(r.Sort)}
}

const maxSeen = 1500

func seenOf(hits []Hit) []seenRef {
	out := make([]seenRef, len(hits))
	for i, h := range hits {
		out[i] = seenRef{S: h.Source, T: h.Time.UnixNano(), Q: h.Seq, ID: h.Tie}
	}
	return out
}

func seenToken(s int, t, q int64, id string) string {
	return fmt.Sprintf("%d\x1f%d\x1f%d\x1f%s", s, t, q, id)
}

func trimSeen(in []seenRef, n int) []seenRef {
	if n < 0 {
		n = 0
	}
	if len(in) <= n {
		return in
	}
	// Keep the newest identities. Tail's floor is the oldest one retained,
	// so dropping these also stops the re-read from walking the whole window.
	cp := append([]seenRef(nil), in...)
	sortSeen(cp)
	return cp[:n]
}

func sortSeen(in []seenRef) {
	// Newest first. A tiny insertion sort keeps this package off "sort" for a short list,
	// but the cap is 1500, so use the standard library via a local comparison.
	for i := 1; i < len(in); i++ {
		j := i
		for j > 0 && seenNewer(in[j], in[j-1]) {
			in[j], in[j-1] = in[j-1], in[j]
			j--
		}
	}
}

func seenNewer(a, b seenRef) bool {
	if a.T != b.T {
		return a.T > b.T
	}
	if a.S != b.S {
		return a.S > b.S
	}
	if a.Q != b.Q {
		return a.Q > b.Q
	}
	return a.ID > b.ID
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
