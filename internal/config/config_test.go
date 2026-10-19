package config

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestExampleConfigValid(t *testing.T) {
	resources, diags, err := LoadPath("../../examples/config")
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) > 0 {
		for _, d := range diags {
			t.Errorf("%s %s %s: %s", d.Path, d.Kind, d.Field, d.Message)
		}
	}
	if len(resources) < 8 {
		t.Fatalf("expected the example set, got %d resources", len(resources))
	}
	kinds := map[string]int{}
	for _, r := range resources {
		kinds[r.Kind]++
		if r.Metadata.Namespace != "default" {
			t.Errorf("%s namespace = %s", r.ID(), r.Metadata.Namespace)
		}
		if r.Status != nil {
			t.Errorf("loader should strip status for %s", r.ID())
		}
	}
	for _, kind := range []string{KindOsqueryPack, KindOsqueryQuery, KindLabel, KindMunkiCatalog, KindMunkiManifest, KindMunkiPkgInfo, KindAutoPkgRepo, KindAutoPkgPipeline, KindRole} {
		if kinds[kind] == 0 {
			t.Errorf("example config missing %s", kind)
		}
	}
}

func TestValidateRejectsUnknownFieldAndBadQuery(t *testing.T) {
	docs := []byte(`
apiVersion: missioncontrol.io/v1
kind: Label
metadata:
  name: Bad_Name
spec:
  query: DELETE FROM users
  interval: 0
  surprise: true
`)
	resources, err := Parse("bad.yaml", docs)
	if err != nil {
		t.Fatal(err)
	}
	diags := Validate(resources)
	if len(diags) < 2 {
		t.Fatalf("expected several diagnostics, got %#v", diags)
	}
	blob := fmt.Sprint(diags)
	if !strings.Contains(blob, "metadata.name") || !strings.Contains(blob, "surprise") {
		t.Fatalf("diagnostics = %#v", diags)
	}

	badQuery, err := Parse("query.yaml", []byte(`
apiVersion: missioncontrol.io/v1
kind: OsqueryQuery
metadata:
  name: ports
spec:
  query: DELETE FROM listening_ports
  interval: 0
`))
	if err != nil {
		t.Fatal(err)
	}
	qdiags := Validate(badQuery)
	qblob := fmt.Sprint(qdiags)
	if !strings.Contains(qblob, "SELECT") || !strings.Contains(qblob, "interval") {
		t.Fatalf("query diagnostics = %#v", qdiags)
	}
}

func TestHashStableAcrossNumberTypes(t *testing.T) {
	a := Resource{
		APIVersion: APIVersion,
		Kind:       KindOsqueryQuery,
		Metadata:   Metadata{Name: "ports", Namespace: "default"},
		Spec: map[string]any{
			"query":    "SELECT * FROM listening_ports;",
			"interval": int(60),
		},
	}
	b := Resource{
		APIVersion: APIVersion,
		Kind:       KindOsqueryQuery,
		Metadata:   Metadata{Name: "ports", Namespace: "default"},
		Spec: map[string]any{
			"query":    "SELECT * FROM listening_ports;",
			"interval": float64(60),
		},
	}
	Validate([]Resource{a})
	// Validate mutates a copy only if we pass a slice of the variable. Re-run properly.
	ra := []Resource{a}
	rb := []Resource{b}
	if d := Validate(ra); len(d) > 0 {
		t.Fatal(d)
	}
	if d := Validate(rb); len(d) > 0 {
		t.Fatal(d)
	}
	ha, err := SpecHash(ra[0])
	if err != nil {
		t.Fatal(err)
	}
	hb, err := SpecHash(rb[0])
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("hash mismatch\n%s\n%s", ha, hb)
	}
}

func TestPlanCreateUpdatePrune(t *testing.T) {
	desired, diags, err := LoadPath("../../examples/config")
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	plan, err := BuildPlan(desired, nil, ApplyOptions{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.Create != len(desired) || plan.Summary.Update != 0 || plan.Summary.Delete != 0 {
		t.Fatalf("summary = %+v", plan.Summary)
	}

	current := make([]Resource, len(desired))
	copy(current, desired)
	for i := range current {
		hash, err := SpecHash(current[i])
		if err != nil {
			t.Fatal(err)
		}
		current[i].Status = &Status{ManagedBy: ManagedByConfig, SpecHash: hash, Generation: 1}
	}
	// Change one query interval and drop one resource from desired.
	changed := append([]Resource{}, desired[:len(desired)-1]...)
	found := false
	for i := range changed {
		if changed[i].Kind != KindOsqueryQuery {
			continue
		}
		spec := cloneSpec(changed[i].Spec)
		spec["interval"] = int64(120)
		changed[i].Spec = spec
		found = true
		break
	}
	if !found {
		t.Fatal("example config has no OsqueryQuery")
	}
	plan, err = BuildPlan(changed, current, ApplyOptions{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.Update != 1 || plan.Summary.Delete != 1 {
		t.Fatalf("summary = %+v changes=%+v", plan.Summary, plan.Changes)
	}
	if plan.Summary.Create != 0 {
		t.Fatalf("unexpected creates: %+v", plan.Summary)
	}

	// Without prune, the missing resource stays.
	plan, err = BuildPlan(changed, current, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.Delete != 0 {
		t.Fatalf("prune disabled but delete=%d", plan.Summary.Delete)
	}

	// API-managed resources are not pruned.
	extra := current[0]
	extra.Metadata.Name = "hand-made"
	extra.Status = &Status{ManagedBy: ManagedByAPI, SpecHash: "x", Generation: 3}
	plan, err = BuildPlan(desired, append(current, extra), ApplyOptions{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range plan.Changes {
		if c.Op == OpDelete && c.Name == "hand-made" {
			t.Fatal("pruned an API-managed resource")
		}
	}
}

func cloneSpec(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func TestApplyMemoryRoundTrip(t *testing.T) {
	desired, diags, err := LoadPath("../../examples/config")
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	st := &memStore{}
	plan, err := Apply(context.Background(), st, desired, ApplyOptions{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.Create == 0 {
		t.Fatal("expected creates")
	}
	again, err := Apply(context.Background(), st, desired, ApplyOptions{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	if again.Summary.Create != 0 || again.Summary.Update != 0 || again.Summary.Delete != 0 {
		t.Fatalf("second apply not stable: %+v", again.Summary)
	}
	if again.Summary.Unchanged != len(desired) {
		t.Fatalf("unchanged = %d, want %d", again.Summary.Unchanged, len(desired))
	}
}

type memStore struct {
	resources []Resource
}

func (m *memStore) ListResources(ctx context.Context) ([]Resource, error) {
	return append([]Resource{}, m.resources...), nil
}

func (m *memStore) ApplyChanges(ctx context.Context, changes []Change) error {
	index := map[string]int{}
	for i, r := range m.resources {
		index[r.ID().Key()] = i
	}
	for _, c := range changes {
		key := ResourceID{Kind: c.Kind, Namespace: c.Namespace, Name: c.Name}.Key()
		switch c.Op {
		case OpDelete:
			if i, ok := index[key]; ok {
				m.resources = append(m.resources[:i], m.resources[i+1:]...)
				index = map[string]int{}
				for i, r := range m.resources {
					index[r.ID().Key()] = i
				}
			}
		case OpCreate, OpUpdate:
			r := *c.Resource
			if r.Status == nil {
				r.Status = &Status{}
			}
			if i, ok := index[key]; ok {
				gen := int64(1)
				if m.resources[i].Status != nil {
					gen = m.resources[i].Status.Generation + 1
				}
				r.Status.Generation = gen
				m.resources[i] = r
			} else {
				r.Status.Generation = 1
				m.resources = append(m.resources, r)
				index[key] = len(m.resources) - 1
			}
		}
	}
	return nil
}
