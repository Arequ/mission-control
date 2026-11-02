package logs

import "container/heap"

// Merge combines per-source batches that are each already in key order.
// The result is the total order: timestamp, source, sequence, tie.
func Merge(batches [][]Hit) []Hit {
	h := &hitHeap{}
	for b, batch := range batches {
		if len(batch) == 0 {
			continue
		}
		heap.Push(h, heapItem{hit: batch[0], batch: b, i: 0})
	}
	out := make([]Hit, 0)
	for h.Len() > 0 {
		item := heap.Pop(h).(heapItem)
		out = append(out, item.hit)
		next := item.i + 1
		batch := batches[item.batch]
		if next < len(batch) {
			heap.Push(h, heapItem{hit: batch[next], batch: item.batch, i: next})
		}
	}
	return out
}

type heapItem struct {
	hit   Hit
	batch int
	i     int
}

type hitHeap []heapItem

func (h hitHeap) Len() int { return len(h) }

func (h hitHeap) Less(i, j int) bool {
	return h[i].hit.Key().Before(h[j].hit.Key())
}

func (h hitHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *hitHeap) Push(x any) { *h = append(*h, x.(heapItem)) }

func (h *hitHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}
