package config

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// BuildPlan diffs desired against current. Desired resources must already be
// validated; invalid specs produce a poorer diff but are still compared.
func BuildPlan(desired []Resource, current []Resource, opts ApplyOptions) (Plan, error) {
	managedBy := opts.ManagedBy
	if managedBy == "" {
		managedBy = ManagedByConfig
	}
	currentByID := make(map[string]Resource, len(current))
	for _, r := range current {
		currentByID[r.ID().Key()] = r
	}
	seen := map[string]bool{}
	var changes []Change
	summary := PlanSummary{}

	for _, d := range desired {
		id := d.ID()
		d.Metadata.Namespace = id.Namespace
		d.Status = nil
		hash, err := SpecHash(d)
		if err != nil {
			return Plan{}, fmt.Errorf("hash %s: %w", id, err)
		}
		seen[id.Key()] = true
		next := d
		next.Status = &Status{
			ManagedBy:  managedBy,
			SpecHash:   hash,
			SourcePath: d.SourcePath,
		}
		existing, ok := currentByID[id.Key()]
		if !ok {
			summary.Create++
			changes = append(changes, Change{
				Op:        OpCreate,
				Kind:      id.Kind,
				Namespace: id.Namespace,
				Name:      id.Name,
				Resource:  &next,
			})
			continue
		}
		prevHash := ""
		prevManaged := ManagedByConfig
		if existing.Status != nil {
			prevHash = existing.Status.SpecHash
			if existing.Status.ManagedBy != "" {
				prevManaged = existing.Status.ManagedBy
			}
		}
		if prevHash == hash && prevManaged == managedBy {
			summary.Unchanged++
			if opts.Verbose {
				changes = append(changes, Change{
					Op:        OpUnchanged,
					Kind:      id.Kind,
					Namespace: id.Namespace,
					Name:      id.Name,
				})
			}
			continue
		}
		summary.Update++
		diff := Diff(existing, d)
		if prevManaged != managedBy {
			diff = append(diff, fmt.Sprintf("status.managedBy: %s -> %s", prevManaged, managedBy))
		}
		changes = append(changes, Change{
			Op:        OpUpdate,
			Kind:      id.Kind,
			Namespace: id.Namespace,
			Name:      id.Name,
			Diff:      diff,
			Resource:  &next,
		})
	}

	if opts.Prune {
		for _, existing := range current {
			id := existing.ID()
			if seen[id.Key()] {
				continue
			}
			managed := ManagedByConfig
			if existing.Status != nil && existing.Status.ManagedBy != "" {
				managed = existing.Status.ManagedBy
			}
			if managed != ManagedByConfig {
				continue
			}
			summary.Delete++
			changes = append(changes, Change{
				Op:        OpDelete,
				Kind:      id.Kind,
				Namespace: id.Namespace,
				Name:      id.Name,
			})
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Kind != changes[j].Kind {
			return changes[i].Kind < changes[j].Kind
		}
		if changes[i].Namespace != changes[j].Namespace {
			return changes[i].Namespace < changes[j].Namespace
		}
		if changes[i].Name != changes[j].Name {
			return changes[i].Name < changes[j].Name
		}
		return changes[i].Op < changes[j].Op
	})
	return Plan{Changes: changes, Summary: summary}, nil
}

// Applicable returns create, update, and delete changes.
func Applicable(plan Plan) []Change {
	out := make([]Change, 0, len(plan.Changes))
	for _, c := range plan.Changes {
		if c.Op == OpCreate || c.Op == OpUpdate || c.Op == OpDelete {
			out = append(out, c)
		}
	}
	return out
}

// PlanAgainst loads current resources and builds a plan.
func PlanAgainst(ctx context.Context, st ResourceStore, desired []Resource, opts ApplyOptions) (Plan, error) {
	current, err := st.ListResources(ctx)
	if err != nil {
		return Plan{}, err
	}
	return BuildPlan(desired, current, opts)
}

// Apply computes a plan and persists create, update, and delete changes.
func Apply(ctx context.Context, st ResourceStore, desired []Resource, opts ApplyOptions) (Plan, error) {
	plan, err := PlanAgainst(ctx, st, desired, opts)
	if err != nil {
		return Plan{}, err
	}
	if err := st.ApplyChanges(ctx, Applicable(plan)); err != nil {
		return plan, err
	}
	return plan, nil
}

// Diff returns human-readable field changes from existing to desired.
func Diff(existing, desired Resource) []string {
	var lines []string
	diffValue("spec", existing.Spec, desired.Spec, &lines)
	diffValue("metadata.labels", stringMap(existing.Metadata.Labels), stringMap(desired.Metadata.Labels), &lines)
	diffValue("metadata.annotations", stringMap(existing.Metadata.Annotations), stringMap(desired.Metadata.Annotations), &lines)
	if len(lines) > 40 {
		extra := len(lines) - 40
		lines = append(lines[:40], fmt.Sprintf("... %d more changes", extra))
	}
	return lines
}

func stringMap(m map[string]string) any {
	if len(m) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func diffValue(path string, a, b any, out *[]string) {
	a = Canonicalize(a)
	b = Canonicalize(b)
	if jsonEqual(a, b) {
		return
	}
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		keys := make(map[string]struct{}, len(am)+len(bm))
		for k := range am {
			keys[k] = struct{}{}
		}
		for k := range bm {
			keys[k] = struct{}{}
		}
		ordered := make([]string, 0, len(keys))
		for k := range keys {
			ordered = append(ordered, k)
		}
		sort.Strings(ordered)
		for _, k := range ordered {
			next := path + "." + k
			_, aHas := am[k]
			_, bHas := bm[k]
			if !aHas {
				*out = append(*out, fmt.Sprintf("%s: (added) %s", next, formatValue(bm[k])))
				continue
			}
			if !bHas {
				*out = append(*out, fmt.Sprintf("%s: %s -> (removed)", next, formatValue(am[k])))
				continue
			}
			diffValue(next, am[k], bm[k], out)
		}
		return
	}
	as, aok := a.([]any)
	bs, bok := b.([]any)
	if aok && bok {
		n := len(as)
		if len(bs) > n {
			n = len(bs)
		}
		for i := 0; i < n; i++ {
			var av, bv any
			if i < len(as) {
				av = as[i]
			}
			if i < len(bs) {
				bv = bs[i]
			}
			if i >= len(as) {
				*out = append(*out, fmt.Sprintf("%s[%d]: (added) %s", path, i, formatValue(bv)))
				continue
			}
			if i >= len(bs) {
				*out = append(*out, fmt.Sprintf("%s[%d]: %s -> (removed)", path, i, formatValue(av)))
				continue
			}
			diffValue(fmt.Sprintf("%s[%d]", path, i), av, bv, out)
		}
		return
	}
	*out = append(*out, fmt.Sprintf("%s: %s -> %s", path, formatValue(a), formatValue(b)))
}

func jsonEqual(a, b any) bool {
	ab, aerr := json.Marshal(a)
	bb, berr := json.Marshal(b)
	if aerr != nil || berr != nil {
		return false
	}
	return string(ab) == string(bb)
}

func formatValue(v any) string {
	if v == nil {
		return "null"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	if len(b) > 180 {
		return string(b[:180]) + "…"
	}
	return string(b)
}
