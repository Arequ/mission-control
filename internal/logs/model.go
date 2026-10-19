// Package logs runs predefined log views. A view is a named set of Elastic
// queries. The result is raw message lines merged in timestamp order.
package logs

import (
	"context"
	"encoding/json"
	"time"
)

const (
	// MaxPage is the most lines one response may contain.
	MaxPage = 2000
	// MaxViewLines is the largest max_lines a view may set.
	MaxViewLines = 100000
	// MaxSources is the most indexes one view may read.
	MaxSources = 8
	// MaxContext is the most lines of context on either side of an anchor.
	MaxContext = 200
	// MaxSameInstant caps how many equal-timestamp hits are inspected
	// when a reverse search_after cursor is not available.
	MaxSameInstant = 1000
	// MaxScan bounds how many raw hits one source read will walk while
	// filtering timestamps, seen lines, or a renewed point-in-time. Past this
	// the read fails instead of silently dropping the rest.
	MaxScan = 8000
	// QueryTimeout bounds one run, tail, or context call.
	QueryTimeout = 20 * time.Second
)

// Source is one index inside a view. Index is its position, which is part of
// the merge order when timestamps are equal.
type Source struct {
	Index          int
	Label          string
	Color          string
	IndexPattern   string
	KQL            string
	MessageField   string
	TimestampField string
	FileField      string
	HostField      string
	SequenceField  string
}

// View is a named log view with its secrets already resolved.
type View struct {
	ID           string
	Name         string
	TimeZone     string
	MaxLines     int
	DeviceScoped bool
	Sources      []Source
	// ReaderName is "seed" or "elastic".
	ReaderName string
	ElasticURL string
	APIKey     string
}

// Bind is the device record substituted into KQL placeholders.
type Bind struct {
	Serial       string
	Hostname     string
	HardwareUUID string
}

// Key is the total order of a line: time, then source, then offset, then the
// Elasticsearch sort tuple, then the tie id.
type Key struct {
	Time   time.Time
	Source int
	Seq    int64
	Tie    string
	// Ord is the sortable encoding of the Elasticsearch sort tuple. When both
	// keys have one, it decides ties the same way _shard_doc does. Identity
	// stays on Tie so a line id does not change when a point-in-time is renewed.
	Ord string
}

// Before reports whether k sorts before o.
func (k Key) Before(o Key) bool {
	if !k.Time.Equal(o.Time) {
		return k.Time.Before(o.Time)
	}
	if k.Source != o.Source {
		return k.Source < o.Source
	}
	if k.Seq != o.Seq {
		return k.Seq < o.Seq
	}
	if k.Ord != "" && o.Ord != "" && k.Ord != o.Ord {
		return k.Ord < o.Ord
	}
	return k.Tie < o.Tie
}

// Hit is one log line from a single source, already ordered inside that source.
type Hit struct {
	Source int
	Time   time.Time
	Seq    int64
	Tie    string
	// Sort is the Elasticsearch sort tuple. Forward pagination passes it back
	// as search_after. Nil for readers that compare Key instead.
	Sort json.RawMessage
	File string
	Host string
	Msg  string
	// Pit is the Elasticsearch point-in-time this hit was read from.
	Pit string
}

// Key returns the merge key for h.
func (h Hit) Key() Key {
	return Key{Time: h.Time, Source: h.Source, Seq: h.Seq, Tie: h.Tie, Ord: SortOrd(h.Sort)}
}

// Line is a merged log line returned by the API.
type Line struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Color     string    `json:"color"`
	File      string    `json:"file"`
	Host      string    `json:"host"`
	Message   string    `json:"message"`
}

// Page is one window of a merged view.
type Page struct {
	Lines         []Line    `json:"lines"`
	Cursor        string    `json:"cursor,omitempty"`
	HasMoreBefore bool      `json:"has_more_before"`
	HasMoreAfter  bool      `json:"has_more_after"`
	Truncated     bool      `json:"truncated"`
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
}

// Context is the anchor line with neighbors from every source.
type Context struct {
	Lines []Line `json:"lines"`
	Focus int    `json:"focus"`
}

// SearchRequest asks one source for a bounded, ordered set of hits.
type SearchRequest struct {
	Source   Source
	KQL      string
	Location *time.Location
	Host     string
	From     time.Time
	To       time.Time
	Limit    int
	// After, when set, keeps hits strictly after this key. Elastic also sends AfterSort.
	After     *Key
	AfterSort json.RawMessage
	// Before, when set, keeps the closest hits strictly before this key.
	Before     *Key
	BeforeSort json.RawMessage
	// Desc selects the newest Limit hits in the range. Before implies the same
	// tail selection. Results are still returned oldest-first.
	Desc bool
	// PIT is an Elasticsearch point-in-time to reuse. Empty opens a new one.
	PIT string
	// Returned is the set of tie ids already shown for this source. A renewed
	// point-in-time cannot resume on _shard_doc, so these ids are how a page
	// boundary avoids repeating lines whose new shard order moved.
	Returned []string
}

// Result is one source page. PIT is empty for readers that do not use Elasticsearch.
type Result struct {
	Hits []Hit
	PIT  string
	// Renewed is true when the point-in-time expired and the hits were read
	// from a new snapshot. Their sort tuples are not comparable with the cursor.
	Renewed bool
}

// Reader reads one source. Implementations must honor Limit and the key bounds
// exactly: missing a hit or returning a hit on the wrong side of After/Before
// breaks the merge.
type Reader interface {
	Search(ctx context.Context, req SearchRequest) (Result, error)
}
