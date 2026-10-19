package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/Arequ/mission-control/internal/config"
	"github.com/Arequ/mission-control/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "validate":
		os.Exit(cmdValidate(os.Args[2:]))
	case "plan":
		os.Exit(cmdSync(os.Args[2:], false))
	case "apply":
		os.Exit(cmdSync(os.Args[2:], true))
	case "export":
		os.Exit(cmdExport(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println(version.Version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `mcctl %s — Mission Control config CLI

Usage:
  mcctl validate [-f path]
  mcctl plan     [-f path] [--server url] [--token token] [--prune] [--output text|json]
  mcctl apply    [-f path] [--server url] [--token token] [--prune] [--output text|json]
  mcctl export   [-o dir]  [--server url] [--token token]

Environment:
  MC_CONFIG   default path (examples/config)
  MC_SERVER   default server (http://localhost:8080)
  MC_TOKEN    bearer token
`, version.Version)
}

func cmdValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	path := fs.String("f", env("MC_CONFIG", "examples/config"), "config file or directory")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	resources, diags, err := config.LoadPath(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		return 1
	}
	if len(diags) > 0 {
		printDiags(diags)
		return 1
	}
	fmt.Printf("valid: %d resources\n", len(resources))
	return 0
}

func cmdSync(args []string, apply bool) int {
	name := "plan"
	if apply {
		name = "apply"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	path := fs.String("f", env("MC_CONFIG", "examples/config"), "config file or directory")
	server := fs.String("server", env("MC_SERVER", "http://localhost:8080"), "API base URL")
	token := fs.String("token", os.Getenv("MC_TOKEN"), "bearer token")
	prune := fs.Bool("prune", false, "delete config-managed resources missing from the file set")
	output := fs.String("output", "text", "text or json")
	verbose := fs.Bool("verbose", false, "include unchanged resources")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *token == "" {
		fmt.Fprintln(os.Stderr, "token required (--token or MC_TOKEN)")
		return 2
	}
	resources, diags, err := config.LoadPath(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		return 1
	}
	if len(diags) > 0 {
		printDiags(diags)
		return 1
	}
	endpoint := "/api/v1/config/plan"
	if apply {
		endpoint = "/api/v1/config/apply"
	}
	var plan config.Plan
	if err := post(*server, *token, endpoint, map[string]any{
		"resources": resources,
		"prune":     *prune,
		"verbose":   *verbose,
	}, &plan); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		return 1
	}
	if *output == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(plan)
		return 0
	}
	printPlan(plan)
	return 0
}

func cmdExport(args []string) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	out := fs.String("o", "", "output directory (required)")
	server := fs.String("server", env("MC_SERVER", "http://localhost:8080"), "API base URL")
	token := fs.String("token", os.Getenv("MC_TOKEN"), "bearer token")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "--o and a token are required")
		return 2
	}
	var body struct {
		Resources []config.Resource `json:"resources"`
	}
	if err := get(*server, *token, "/api/v1/config/export", &body); err != nil {
		fmt.Fprintf(os.Stderr, "export: %v\n", err)
		return 1
	}
	if err := config.WriteDir(*out, body.Resources); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		return 1
	}
	fmt.Printf("exported %d resources to %s\n", len(body.Resources), *out)
	return 0
}

func printDiags(diags []config.Diagnostic) {
	for _, d := range diags {
		loc := d.Path
		if d.Field != "" {
			if loc != "" {
				loc += ": "
			}
			loc += d.Field
		}
		if loc == "" {
			fmt.Fprintf(os.Stderr, "error: %s\n", d.Message)
			continue
		}
		fmt.Fprintf(os.Stderr, "%s: %s\n", loc, d.Message)
	}
}

func printPlan(plan config.Plan) {
	fmt.Printf("create %d, update %d, delete %d, unchanged %d\n",
		plan.Summary.Create, plan.Summary.Update, plan.Summary.Delete, plan.Summary.Unchanged)
	if len(plan.Changes) == 0 {
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "OP\tKIND\tNAME\tDETAIL")
	for _, c := range plan.Changes {
		detail := ""
		if len(c.Diff) > 0 {
			detail = strings.Join(c.Diff, "; ")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s/%s\t%s\n", c.Op, c.Kind, c.Namespace, c.Name, detail)
	}
	_ = tw.Flush()
}

func post(server, token, path string, in any, out any) error {
	return do(http.MethodPost, server, token, path, in, out)
}

func get(server, token, path string, out any) error {
	return do(http.MethodGet, server, token, path, nil, out)
}

func do(method, server, token, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimRight(server, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
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
	if out == nil || len(respBody) == 0 {
		return nil
	}
	return json.Unmarshal(respBody, out)
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
