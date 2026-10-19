package logs

import (
	"context"
	"sort"
)

// Memory is an in-memory reader. Hits must already carry their source index.
type Memory struct {
	Hits []Hit
}

// Search returns the oldest or closest hits that match the request bounds.
func (m Memory) Search(_ context.Context, req SearchRequest) (Result, error) {
	return m.search(req)
}

func (m Memory) search(req SearchRequest) (Result, error) {
	var out []Hit
	for _, h := range m.Hits {
		if h.Source != req.Source.Index {
			continue
		}
		if h.Time.Before(req.From) || !h.Time.Before(req.To) {
			continue
		}
		if req.After != nil && !req.After.Before(h.Key()) {
			continue
		}
		if req.Before != nil && !h.Key().Before(*req.Before) {
			continue
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key().Before(out[j].Key()) })
	if req.Limit > 0 && len(out) > req.Limit {
		if req.Desc || req.Before != nil {
			out = out[len(out)-req.Limit:]
		} else {
			out = out[:req.Limit]
		}
	}
	return Result{Hits: out}, nil
}
