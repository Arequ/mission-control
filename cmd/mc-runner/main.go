// Command mc-runner is the Mac-side AutoPkg worker.
//
// It registers with a token issued by the server, polls for jobs, and runs
// autopkg when the binary is on PATH. Trust verification and Munki promotion
// are orchestrated by the server in a later phase; this build records the
// autopkg result and says so in the job log.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/version"
)

func main() {
	fs := flag.NewFlagSet("mc-runner", flag.ContinueOnError)
	server := fs.String("server", env("MC_SERVER", "http://localhost:8080"), "API base URL")
	token := fs.String("token", os.Getenv("MC_RUNNER_TOKEN"), "runner token from POST /api/v1/runners")
	interval := fs.Duration("interval", 15*time.Second, "poll interval")
	once := fs.Bool("once", false, "claim at most one job and exit")
	name := fs.String("name", env("MC_RUNNER_NAME", hostname()), "reported in heartbeat logs only")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *token == "" {
		fmt.Fprintln(os.Stderr, "runner token required (--token or MC_RUNNER_TOKEN)")
		os.Exit(2)
	}
	fmt.Printf("mc-runner %s polling %s as %s\n", version.Version, *server, *name)
	client := &runner{server: strings.TrimRight(*server, "/"), token: *token, name: *name}
	for {
		if err := client.heartbeat(); err != nil {
			fmt.Fprintf(os.Stderr, "heartbeat: %v\n", err)
		}
		job, err := client.claim()
		if err != nil {
			fmt.Fprintf(os.Stderr, "claim: %v\n", err)
		} else if job != nil {
			status, logs, result := execute(*job)
			if err := client.complete(job.ID, status, logs, result); err != nil {
				fmt.Fprintf(os.Stderr, "complete: %v\n", err)
			} else {
				fmt.Printf("job %s %s (%s)\n", job.ID, job.PipelineName, status)
			}
			if *once {
				return
			}
			continue
		}
		if *once {
			fmt.Println("no job queued")
			return
		}
		time.Sleep(*interval)
	}
}

type runner struct {
	server string
	token  string
	name   string
}

type job struct {
	ID           string         `json:"id"`
	PipelineName string         `json:"pipelineName"`
	Spec         map[string]any `json:"spec"`
}

func (c *runner) heartbeat() error {
	return c.do(http.MethodPost, "/api/v1/runner/heartbeat", map[string]any{
		"osVersion": osVersion(),
	}, nil)
}

func (c *runner) claim() (*job, error) {
	var body struct {
		Job *job `json:"job"`
	}
	if err := c.do(http.MethodPost, "/api/v1/runner/jobs/claim", map[string]any{}, &body); err != nil {
		return nil, err
	}
	return body.Job, nil
}

func (c *runner) complete(id, status, logs string, result map[string]any) error {
	return c.do(http.MethodPost, "/api/v1/runner/jobs/"+id+"/complete", map[string]any{
		"status": status,
		"logs":   logs,
		"result": result,
	}, nil)
}

func (c *runner) do(method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.server+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	if out != nil && len(respBody) > 0 {
		return json.Unmarshal(respBody, out)
	}
	return nil
}

func execute(job job) (string, string, map[string]any) {
	recipe, _ := job.Spec["recipe"].(string)
	var buf strings.Builder
	fmt.Fprintf(&buf, "runner=%s pipeline=%s recipe=%s\n", hostname(), job.PipelineName, recipe)
	if repo, _ := job.Spec["repo"].(string); repo != "" {
		fmt.Fprintf(&buf, "repo=%s\n", repo)
	}
	bin, err := exec.LookPath("autopkg")
	if err != nil {
		buf.WriteString("autopkg is not installed on this runner.\n")
		buf.WriteString("Install AutoPkg on a Mac host. Trust verification and Munki promotion are phase 3; this build only runs autopkg and uploads the log.\n")
		return "failed", buf.String(), map[string]any{"error": "autopkg not installed", "promotion": "not_implemented"}
	}
	if recipe == "" {
		buf.WriteString("pipeline spec has no recipe\n")
		return "failed", buf.String(), map[string]any{"error": "missing recipe"}
	}
	cmd := exec.Command(bin, "run", recipe, "-v")
	out, err := cmd.CombinedOutput()
	buf.Write(out)
	if err != nil {
		buf.WriteString("\n" + err.Error() + "\n")
		return "failed", buf.String(), map[string]any{"error": err.Error(), "promotion": "not_implemented"}
	}
	buf.WriteString("\nautopkg exited 0. Catalog promotion is not implemented in this runner build.\n")
	return "succeeded", buf.String(), map[string]any{"autopkg": "ok", "promotion": "not_implemented"}
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "runner"
	}
	return name
}

func osVersion() string {
	b, err := exec.Command("uname", "-sr").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
