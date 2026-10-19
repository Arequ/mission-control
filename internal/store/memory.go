package store

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/config"
	"github.com/google/uuid"
)

// Memory is an in-process Store used by tests and the config engine.
type Memory struct {
	mu           sync.Mutex
	tokens       map[string]auth.Principal // hash -> principal
	tokenName    map[string]string         // name -> hash
	devices      map[string]Device
	byNode       map[string]string
	apps         map[string][]App
	results      map[string][]QueryResult
	resources    map[string]config.Resource
	queries      map[string]*LiveQuery
	runners      map[string]Runner
	runnerByHash map[string]string
	jobs         map[string]Job
	jobOrder     []string
}

// NewMemory returns an empty store.
func NewMemory() *Memory {
	return &Memory{
		tokens:       map[string]auth.Principal{},
		tokenName:    map[string]string{},
		devices:      map[string]Device{},
		byNode:       map[string]string{},
		apps:         map[string][]App{},
		results:      map[string][]QueryResult{},
		resources:    map[string]config.Resource{},
		queries:      map[string]*LiveQuery{},
		runners:      map[string]Runner{},
		runnerByHash: map[string]string{},
		jobs:         map[string]Job{},
	}
}

func (m *Memory) EnsureToken(_ context.Context, name, token, role string) error {
	if !auth.ValidRole(role) {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.tokenName[name]; ok {
		delete(m.tokens, old)
	}
	hash := auth.Hash(token)
	m.tokens[hash] = auth.Principal{ID: name, Name: name, Role: role}
	m.tokenName[name] = hash
	return nil
}

func (m *Memory) AuthenticateToken(_ context.Context, token string) (auth.Principal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.tokens[auth.Hash(token)]
	if !ok {
		return auth.Principal{}, ErrUnauthorized
	}
	return p, nil
}

func (m *Memory) CreateToken(_ context.Context, name, role string) (string, auth.Principal, error) {
	if !auth.ValidRole(role) || strings.TrimSpace(name) == "" {
		return "", auth.Principal{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tokenName[name]; ok {
		return "", auth.Principal{}, ErrConflict
	}
	token, err := auth.NewSecret("mc_")
	if err != nil {
		return "", auth.Principal{}, err
	}
	p := auth.Principal{ID: uuid.NewString(), Name: name, Role: role}
	hash := auth.Hash(token)
	m.tokens[hash] = p
	m.tokenName[name] = hash
	return token, p, nil
}

func (m *Memory) EnrollDevice(_ context.Context, nodeKey string, incoming Device) (Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	var existing *Device
	if incoming.HardwareSerial != "" {
		for id, d := range m.devices {
			if d.HardwareSerial == incoming.HardwareSerial {
				dd := d
				existing = &dd
				_ = id
				break
			}
		}
	}
	if existing == nil && incoming.HostIdentifier != "" {
		for _, d := range m.devices {
			if d.HostIdentifier == incoming.HostIdentifier {
				dd := d
				existing = &dd
				break
			}
		}
	}
	var d Device
	if existing == nil {
		d = incoming
		d.ID = uuid.NewString()
		d.EnrolledAt = now
		if d.Labels == nil {
			d.Labels = []string{}
		}
		if d.Hostname == "" {
			d.Hostname = d.HostIdentifier
		}
	} else {
		delete(m.byNode, existing.NodeKeyHash)
		d = *existing
		MergeIdentity(&d, incoming)
	}
	d.NodeKeyHash = auth.Hash(nodeKey)
	d.UpdatedAt = now
	d.LastSeenAt = &now
	m.devices[d.ID] = d
	m.byNode[d.NodeKeyHash] = d.ID
	return publicDevice(d), nil
}

func (m *Memory) DeviceByNodeKey(_ context.Context, nodeKey string) (Device, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byNode[auth.Hash(nodeKey)]
	if !ok {
		return Device{}, false, nil
	}
	return publicDevice(m.devices[id]), true, nil
}

func (m *Memory) TouchDevice(_ context.Context, id, configHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now().UTC()
	d.LastSeenAt = &now
	d.UpdatedAt = now
	if configHash != "" {
		d.ConfigHash = configHash
	}
	m.devices[id] = d
	return nil
}

func (m *Memory) ApplyInventory(_ context.Context, id string, patch Device, snapshots map[string]json.RawMessage, apps *[]App, labels []LabelUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return ErrNotFound
	}
	MergeIdentity(&d, patch)
	if len(snapshots) > 0 {
		if d.Inventory == nil {
			d.Inventory = map[string]json.RawMessage{}
		}
		for k, v := range snapshots {
			d.Inventory[k] = append(json.RawMessage(nil), v...)
		}
	}
	for _, label := range labels {
		d.Labels = ApplyLabel(d.Labels, label)
	}
	now := time.Now().UTC()
	d.UpdatedAt = now
	d.LastSeenAt = &now
	m.devices[id] = d
	if apps != nil {
		copied := append([]App{}, (*apps)...)
		m.apps[id] = copied
	}
	return nil
}

func (m *Memory) ListDevices(_ context.Context, filter DeviceFilter) ([]Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	q := strings.ToLower(strings.TrimSpace(filter.Query))
	var out []Device
	for _, d := range m.devices {
		if q != "" {
			blob := strings.ToLower(strings.Join([]string{d.Hostname, d.ComputerName, d.HardwareSerial, d.PrimaryUser, d.HardwareModel, d.OSVersion}, " "))
			if !strings.Contains(blob, q) {
				continue
			}
		}
		pub := publicDevice(d)
		pub.Inventory = nil
		out = append(out, pub)
	}
	sort.Slice(out, func(i, j int) bool {
		ti, tj := time.Time{}, time.Time{}
		if out[i].LastSeenAt != nil {
			ti = *out[i].LastSeenAt
		}
		if out[j].LastSeenAt != nil {
			tj = *out[j].LastSeenAt
		}
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		return out[i].Hostname < out[j].Hostname
	})
	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	if filter.Offset > len(out) {
		return []Device{}, nil
	}
	out = out[filter.Offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) GetDevice(_ context.Context, id string) (Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return Device{}, ErrNotFound
	}
	return publicDevice(d), nil
}

func (m *Memory) ListApps(_ context.Context, deviceID string) ([]App, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.devices[deviceID]; !ok {
		return nil, ErrNotFound
	}
	apps := append([]App{}, m.apps[deviceID]...)
	sort.Slice(apps, func(i, j int) bool {
		if apps[i].Name != apps[j].Name {
			return apps[i].Name < apps[j].Name
		}
		return apps[i].Version < apps[j].Version
	})
	return apps, nil
}

func (m *Memory) ListResults(_ context.Context, deviceID string, limit int) ([]QueryResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.devices[deviceID]; !ok {
		return nil, ErrNotFound
	}
	rows := append([]QueryResult{}, m.results[deviceID]...)
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].CollectedAt.After(rows[j].CollectedAt)
	})
	if limit <= 0 {
		limit = 50
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

func (m *Memory) AddResult(_ context.Context, deviceID string, result QueryResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.devices[deviceID]; !ok {
		return ErrNotFound
	}
	m.results[deviceID] = append(m.results[deviceID], result)
	return nil
}

func (m *Memory) AppCounts(_ context.Context, limit int) ([]AppCount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	counts := map[string]map[string]struct{}{}
	for deviceID, apps := range m.apps {
		seen := map[string]bool{}
		for _, app := range apps {
			if app.Name == "" || seen[app.Name] {
				continue
			}
			seen[app.Name] = true
			if counts[app.Name] == nil {
				counts[app.Name] = map[string]struct{}{}
			}
			counts[app.Name][deviceID] = struct{}{}
		}
	}
	out := make([]AppCount, 0, len(counts))
	for name, devices := range counts {
		out = append(out, AppCount{Name: name, Devices: len(devices)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Devices != out[j].Devices {
			return out[i].Devices > out[j].Devices
		}
		return out[i].Name < out[j].Name
	})
	if limit <= 0 {
		limit = 8
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) FleetSummary(ctx context.Context, expected map[string]string) (FleetSummary, error) {
	devices, err := m.ListDevices(ctx, DeviceFilter{Limit: 100000})
	if err != nil {
		return FleetSummary{}, err
	}
	// ListDevices hides inventory, which Summarize does not need, but it also
	// clears nothing else. Config hashes are preserved.
	apps, err := m.AppCounts(ctx, 8)
	if err != nil {
		return FleetSummary{}, err
	}
	return Summarize(devices, apps, expected, time.Now().UTC()), nil
}

func (m *Memory) ListResources(_ context.Context) ([]config.Resource, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]config.Resource, 0, len(m.resources))
	for _, r := range m.resources {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID().Key() < out[j].ID().Key()
	})
	return out, nil
}

func (m *Memory) ApplyChanges(_ context.Context, changes []config.Change) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for _, c := range changes {
		key := (config.ResourceID{Kind: c.Kind, Namespace: c.Namespace, Name: c.Name}).Key()
		switch c.Op {
		case config.OpDelete:
			delete(m.resources, key)
		case config.OpCreate, config.OpUpdate:
			if c.Resource == nil {
				return ErrInvalid
			}
			r := *c.Resource
			if r.Status == nil {
				r.Status = &config.Status{}
			}
			if prev, ok := m.resources[key]; ok && prev.Status != nil {
				r.Status.Generation = prev.Status.Generation + 1
			} else {
				r.Status.Generation = 1
			}
			r.Status.AppliedAt = &now
			if r.Status.ManagedBy == "" {
				r.Status.ManagedBy = config.ManagedByConfig
			}
			r.Status.SourcePath = r.SourcePath
			m.resources[key] = r
		}
	}
	return nil
}

func (m *Memory) CreateLiveQuery(_ context.Context, sql, createdBy string, deviceIDs []string) (LiveQuery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(deviceIDs) == 0 {
		for id := range m.devices {
			deviceIDs = append(deviceIDs, id)
		}
	}
	q := &LiveQuery{
		ID:        uuid.NewString(),
		SQL:       sql,
		CreatedBy: createdBy,
		CreatedAt: time.Now().UTC(),
	}
	for _, id := range deviceIDs {
		d, ok := m.devices[id]
		if !ok {
			return LiveQuery{}, ErrNotFound
		}
		q.Targets = append(q.Targets, LiveTarget{DeviceID: id, Hostname: d.Hostname, Status: "pending"})
	}
	sort.Slice(q.Targets, func(i, j int) bool { return q.Targets[i].Hostname < q.Targets[j].Hostname })
	m.queries[q.ID] = q
	return *q, nil
}

func (m *Memory) ListLiveQueries(_ context.Context) ([]LiveQuery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LiveQuery, 0, len(m.queries))
	for _, q := range m.queries {
		out = append(out, *q)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) GetLiveQuery(_ context.Context, id string) (LiveQuery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	q, ok := m.queries[id]
	if !ok {
		return LiveQuery{}, ErrNotFound
	}
	return *q, nil
}

func (m *Memory) PendingQueries(_ context.Context, deviceID string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	for _, q := range m.queries {
		for _, t := range q.Targets {
			if t.DeviceID == deviceID && t.Status == "pending" {
				out[q.ID] = q.SQL
			}
		}
	}
	return out, nil
}

func (m *Memory) WriteQueryResults(_ context.Context, deviceID string, results map[string]json.RawMessage, statuses map[string]int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := map[string]struct{}{}
	for id := range results {
		ids[id] = struct{}{}
	}
	for id := range statuses {
		ids[id] = struct{}{}
	}
	for id := range ids {
		q, ok := m.queries[id]
		if !ok {
			continue
		}
		for i := range q.Targets {
			if q.Targets[i].DeviceID != deviceID {
				continue
			}
			code := statuses[id]
			q.Targets[i].OSQueryStatus = &code
			if raw, ok := results[id]; ok {
				q.Targets[i].Results = append(json.RawMessage(nil), raw...)
			}
			if code == 0 {
				q.Targets[i].Status = "complete"
			} else {
				q.Targets[i].Status = "error"
			}
		}
	}
	return nil
}

func (m *Memory) CreateRunner(_ context.Context, name string, labels map[string]string) (Runner, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.runners {
		if r.Name == name {
			return Runner{}, ErrConflict
		}
	}
	token, err := auth.NewSecret("mcr_")
	if err != nil {
		return Runner{}, err
	}
	runner := Runner{
		ID:        uuid.NewString(),
		Name:      name,
		Labels:    labels,
		CreatedAt: time.Now().UTC(),
		Token:     token,
	}
	stored := runner
	stored.Token = ""
	m.runners[runner.ID] = stored
	m.runnerByHash[auth.Hash(token)] = runner.ID
	return runner, nil
}

func (m *Memory) AuthenticateRunner(_ context.Context, token string) (Runner, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.runnerByHash[auth.Hash(token)]
	if !ok {
		return Runner{}, ErrUnauthorized
	}
	return m.runners[id], nil
}

func (m *Memory) HeartbeatRunner(_ context.Context, id string, hb RunnerHeartbeat) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runners[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now().UTC()
	r.LastSeenAt = &now
	if hb.AutoPkgVersion != "" {
		r.AutoPkgVersion = hb.AutoPkgVersion
	}
	if hb.OSVersion != "" {
		r.OSVersion = hb.OSVersion
	}
	if hb.Labels != nil {
		r.Labels = hb.Labels
	}
	m.runners[id] = r
	return nil
}

func (m *Memory) ListRunners(_ context.Context) ([]Runner, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Runner, 0, len(m.runners))
	for _, r := range m.runners {
		r.Token = ""
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) CreateJob(_ context.Context, pipeline string, spec map[string]any) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job := Job{
		ID:           uuid.NewString(),
		PipelineName: pipeline,
		Status:       "queued",
		Spec:         spec,
		CreatedAt:    time.Now().UTC(),
	}
	m.jobs[job.ID] = job
	m.jobOrder = append(m.jobOrder, job.ID)
	return job, nil
}

func (m *Memory) ListJobs(_ context.Context) ([]Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Job, 0, len(m.jobs))
	for _, id := range m.jobOrder {
		out = append(out, m.jobs[id])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) GetJob(_ context.Context, id string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok {
		return Job{}, ErrNotFound
	}
	return job, nil
}

func (m *Memory) ClaimJob(_ context.Context, runnerID string) (Job, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.runners[runnerID]; !ok {
		return Job{}, false, ErrNotFound
	}
	for _, id := range m.jobOrder {
		job := m.jobs[id]
		if job.Status != "queued" {
			continue
		}
		now := time.Now().UTC()
		job.Status = "running"
		job.RunnerID = runnerID
		job.StartedAt = &now
		m.jobs[id] = job
		return job, true, nil
	}
	return Job{}, false, nil
}

func (m *Memory) AppendJobLog(_ context.Context, id, runnerID, chunk string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok {
		return ErrNotFound
	}
	if job.RunnerID != runnerID || job.Status != "running" {
		return ErrInvalid
	}
	job.Logs += chunk
	m.jobs[id] = job
	return nil
}

func (m *Memory) FinishJob(_ context.Context, id, runnerID, status, logs string, result map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok {
		return ErrNotFound
	}
	if job.RunnerID != runnerID || job.Status != "running" {
		return ErrInvalid
	}
	if status != "succeeded" && status != "failed" {
		return ErrInvalid
	}
	now := time.Now().UTC()
	job.Status = status
	job.FinishedAt = &now
	if logs != "" {
		job.Logs = logs
	}
	job.Result = result
	m.jobs[id] = job
	return nil
}
