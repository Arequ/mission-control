// Package runneragent implements the mc-runner control loop.
package runneragent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/Arequ/mission-control/internal/model"
)

// Config is how a runner finds the server and autopkg.
type Config struct {
	ServerURL      string
	BootstrapToken string
	Token          string
	Name           string
	Labels         []string
	Pool           string
	Hostname       string
	OSVersion      string
	AutopkgBin     string
	AutopkgVersion string
	SyncRepos      bool
	RepoCache      string
	StatePath      string
	HTTP           *http.Client
}

// Agent is one mc-runner process.
type Agent struct {
	Config Config
	token  string
	id     string
}

type stateFile struct {
	Token string `json:"token"`
	ID    string `json:"id"`
}

// Run registers if needed and polls until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.ensureRegistered(ctx); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = a.heartbeat(ctx)
		if _, err := a.poll(ctx, 20); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
}

// RunJobs completes n jobs and returns. It is the hook tests use.
func (a *Agent) RunJobs(ctx context.Context, n int) error {
	if err := a.ensureRegistered(ctx); err != nil {
		return err
	}
	done := 0
	for done < n {
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = a.heartbeat(ctx)
		ran, err := a.poll(ctx, 2)
		if err != nil {
			return err
		}
		if ran {
			done++
		}
	}
	return nil
}

func (a *Agent) client() *http.Client {
	if a.Config.HTTP != nil {
		return a.Config.HTTP
	}
	return &http.Client{}
}

func (a *Agent) ensureRegistered(ctx context.Context) error {
	if a.token == "" {
		a.token = a.Config.Token
	}
	if a.token == "" {
		a.loadState()
	}
	if a.token != "" {
		if err := a.heartbeat(ctx); err == nil {
			return nil
		}
	}
	return a.register(ctx)
}

func (a *Agent) loadState() {
	if a.Config.StatePath == "" {
		return
	}
	b, err := os.ReadFile(a.Config.StatePath)
	if err != nil {
		return
	}
	var st stateFile
	if json.Unmarshal(b, &st) == nil && st.Token != "" {
		a.token = st.Token
		a.id = st.ID
	}
}

func (a *Agent) saveState() {
	if a.Config.StatePath == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(a.Config.StatePath), 0o700)
	b, _ := json.Marshal(stateFile{Token: a.token, ID: a.id})
	_ = os.WriteFile(a.Config.StatePath, b, 0o600)
}

func (a *Agent) register(ctx context.Context) error {
	var resp struct {
		Token  string       `json:"token"`
		Runner model.Runner `json:"runner"`
	}
	err := a.do(ctx, http.MethodPost, "/api/v1/runners/register", a.Config.BootstrapToken, map[string]any{
		"name":            a.Config.Name,
		"labels":          a.Config.Labels,
		"pool":            a.Config.Pool,
		"hostname":        a.Config.Hostname,
		"os_version":      a.Config.OSVersion,
		"autopkg_version": a.Config.AutopkgVersion,
	}, &resp)
	if err != nil {
		return err
	}
	a.token = resp.Token
	a.id = resp.Runner.ID
	a.saveState()
	return nil
}

func (a *Agent) heartbeat(ctx context.Context) error {
	return a.do(ctx, http.MethodPost, "/api/v1/runners/heartbeat", a.token, map[string]any{
		"hostname":        a.Config.Hostname,
		"os_version":      a.Config.OSVersion,
		"autopkg_version": a.Config.AutopkgVersion,
	}, nil)
}

func (a *Agent) poll(ctx context.Context, waitSeconds int) (bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(waitSeconds+15)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, a.Config.ServerURL+fmt.Sprintf("/api/v1/runners/lease?wait_seconds=%d", waitSeconds), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	res, err := a.client().Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode == http.StatusNoContent {
		return false, nil
	}
	if res.StatusCode >= 300 {
		return false, fmt.Errorf("lease: %d %s", res.StatusCode, body)
	}
	var lease model.Lease
	if err := json.Unmarshal(body, &lease); err != nil {
		return false, err
	}
	if err := a.execute(ctx, lease); err != nil {
		return true, err
	}
	return true, nil
}

func (a *Agent) execute(ctx context.Context, lease model.Lease) error {
	dir, err := os.MkdirTemp("", "mc-job-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	override := filepath.Join(dir, "override.recipe")
	if err := os.WriteFile(override, []byte(lease.Recipe.Override), 0o644); err != nil {
		return err
	}
	trustPath := filepath.Join(dir, "trust.json")
	trust := lease.Recipe.TrustInfo
	if len(trust) == 0 {
		trust = []byte(`{}`)
	}
	if err := os.WriteFile(trustPath, trust, 0o644); err != nil {
		return err
	}
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(lease.TimeoutSeconds)*time.Second)
	defer cancel()
	stopRenew := a.renew(runCtx, lease)
	defer stopRenew()

	if a.Config.SyncRepos {
		cache := a.Config.RepoCache
		if cache == "" {
			cache = filepath.Join(dir, "repos")
		}
		if err := syncRepos(runCtx, cache, lease.Repos); err != nil {
			_ = a.logLine(runCtx, lease.JobID, lease.Attempt, "stderr", "repo sync: "+err.Error())
			_, cerr := a.complete(runCtx, lease.JobID, lease.Attempt, "error", "repo sync: "+err.Error())
			return errors.Join(err, cerr)
		}
	}

	bin := a.Config.AutopkgBin
	if bin == "" {
		bin = "autopkg"
	}
	code, err := a.runCmd(runCtx, lease.JobID, lease.Attempt, bin, []string{"verify-trust-info", "--override", override, "--trust", trustPath})
	if err != nil || code != 0 {
		msg := "verify-trust-info failed"
		if err != nil {
			msg = err.Error()
		}
		_, cerr := a.complete(runCtx, lease.JobID, lease.Attempt, "trust_failed", msg)
		return cerr
	}
	code, err = a.runCmd(runCtx, lease.JobID, lease.Attempt, bin, []string{"run", "--override", override, "--output", out})
	if err != nil || code != 0 {
		msg := "autopkg run failed"
		if err != nil {
			msg = err.Error()
		}
		_, cerr := a.complete(runCtx, lease.JobID, lease.Attempt, "error", msg)
		return cerr
	}
	pkginfoPath := filepath.Join(out, "pkginfo.plist")
	if _, statErr := os.Stat(pkginfoPath); statErr != nil {
		_, cerr := a.complete(runCtx, lease.JobID, lease.Attempt, "no_change", "")
		return cerr
	}
	pkgPath, err := findPkg(out)
	if err != nil {
		_, cerr := a.complete(runCtx, lease.JobID, lease.Attempt, "error", err.Error())
		return cerr
	}
	imported, err := a.upload(runCtx, lease.JobID, lease.Attempt, pkginfoPath, pkgPath)
	if err != nil {
		_, cerr := a.complete(runCtx, lease.JobID, lease.Attempt, "error", err.Error())
		return cerr
	}
	result := "new_version"
	if !imported {
		result = "no_change"
	}
	_, err = a.complete(runCtx, lease.JobID, lease.Attempt, result, "")
	return err
}

func (a *Agent) renew(ctx context.Context, lease model.Lease) func() {
	ctx, cancel := context.WithCancel(ctx)
	interval := time.Duration(lease.LeaseSeconds/3) * time.Second
	if interval < time.Second {
		interval = time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = a.do(ctx, http.MethodPost, "/api/v1/jobs/"+lease.JobID+"/renew", a.token, map[string]any{"attempt": lease.Attempt}, nil)
			}
		}
	}()
	return cancel
}

func (a *Agent) runCmd(ctx context.Context, jobID string, attempt int, bin string, args []string) (int, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, err
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	var wg sync.WaitGroup
	scan := func(stream string, r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			_ = a.logLine(ctx, jobID, attempt, stream, sc.Text())
		}
	}
	wg.Add(2)
	go scan("stdout", stdout)
	go scan("stderr", stderr)
	wg.Wait()
	err = cmd.Wait()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 0, err
}

func findPkg(dir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.pkg"))
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("autopkg produced pkginfo but no package")
	}
	return matches[0], nil
}

func (a *Agent) logLine(ctx context.Context, jobID string, attempt int, stream, line string) error {
	return a.do(ctx, http.MethodPost, "/api/v1/jobs/"+jobID+"/logs", a.token, map[string]any{
		"attempt": attempt,
		"lines":   []map[string]string{{"stream": stream, "line": line}},
	}, nil)
}

func (a *Agent) complete(ctx context.Context, jobID string, attempt int, result, errMsg string) (model.Job, error) {
	var job model.Job
	err := a.do(ctx, http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", a.token, map[string]any{
		"attempt": attempt, "result": result, "error": errMsg,
	}, &job)
	return job, err
}

func (a *Agent) upload(ctx context.Context, jobID string, attempt int, pkginfoPath, pkgPath string) (bool, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("attempt", fmt.Sprintf("%d", attempt)); err != nil {
		return false, err
	}
	if err := addFile(w, "pkginfo", pkginfoPath); err != nil {
		return false, err
	}
	if err := addFile(w, "package", pkgPath); err != nil {
		return false, err
	}
	if err := w.Close(); err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Config.ServerURL+"/api/v1/jobs/"+jobID+"/artifacts", &buf)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", w.FormDataContentType())
	res, err := a.client().Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return false, fmt.Errorf("upload: %d %s", res.StatusCode, body)
	}
	var out model.ImportResult
	if err := json.Unmarshal(body, &out); err != nil {
		return false, err
	}
	return out.Imported, nil
}

func addFile(w *multipart.Writer, field, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	part, err := w.CreateFormFile(field, filepath.Base(path))
	if err != nil {
		return err
	}
	_, err = io.Copy(part, f)
	return err
}

func (a *Agent) do(ctx context.Context, method, path, token string, in any, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.Config.ServerURL+path, body)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := a.client().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d %s", method, path, res.StatusCode, bytes.TrimSpace(b))
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return err
		}
	}
	return nil
}
