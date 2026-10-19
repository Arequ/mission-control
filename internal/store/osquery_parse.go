package store

import (
	"encoding/json"
	"strconv"
	"strings"
)

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		// osquery sometimes emits NUL inside a column. Postgres rejects that byte.
		return strings.ReplaceAll(t, "\x00", "")
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "1"
		}
		return "0"
	default:
		return ""
	}
}

func firstStr(vals ...any) string {
	for _, v := range vals {
		if s := strings.TrimSpace(asString(v)); s != "" {
			return s
		}
	}
	return ""
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func itoa(n int) string { return strconv.Itoa(n) }

func platformFamily(platform, osName string) string {
	p := strings.ToLower(strings.TrimSpace(platform))
	n := strings.ToLower(osName)
	switch {
	case p == "darwin" || p == "macos" || strings.Contains(n, "mac"):
		return "darwin"
	case p == "windows" || strings.Contains(n, "windows"):
		return "windows"
	case p == "linux" || p == "ubuntu" || p == "rhel" || p == "centos" || p == "debian" || p == "fedora" || p == "arch" || strings.Contains(p, "linux"):
		return "linux"
	default:
		return p
	}
}

func decodeFlex(raw []byte) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func columnMap(v any) map[string]string {
	m := asMap(v)
	if len(m) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		out[k] = asString(val)
	}
	return out
}

type parsedResult struct {
	Name     string
	Action   string
	Columns  map[string]string
	Rows     []map[string]string
	Snapshot bool
	Unix     int64
}

func parseResultLogs(raw json.RawMessage) ([]parsedResult, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	v, err := decodeFlex(raw)
	if err != nil {
		return nil, err
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, errNotArray
	}
	out := make([]parsedResult, 0, len(arr))
	for _, item := range arr {
		obj := asMap(item)
		if obj == nil {
			continue
		}
		pr := parsedResult{
			Name:   firstStr(obj["name"]),
			Action: firstStr(obj["action"]),
			Unix:   atoi64(firstStr(obj["unixTime"], obj["unix_time"])),
		}
		if pr.Action == "" {
			pr.Action = "added"
		}
		if _, ok := obj["snapshot"]; ok {
			pr.Snapshot = true
			switch rows := obj["snapshot"].(type) {
			case []any:
				for _, row := range rows {
					pr.Rows = append(pr.Rows, columnMap(row))
				}
			case nil:
			default:
				return nil, errNotArray
			}
			if pr.Rows == nil {
				pr.Rows = []map[string]string{}
			}
		} else {
			pr.Columns = columnMap(obj["columns"])
		}
		if pr.Name == "" {
			continue
		}
		out = append(out, pr)
	}
	return out, nil
}

type parsedStatus struct {
	Severity string
	Filename string
	Line     int
	Message  string
	Version  string
}

func parseStatusLogs(raw json.RawMessage) ([]parsedStatus, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	v, err := decodeFlex(raw)
	if err != nil {
		return nil, err
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, errNotArray
	}
	out := make([]parsedStatus, 0, len(arr))
	for _, item := range arr {
		obj := asMap(item)
		if obj == nil {
			continue
		}
		msg := firstStr(obj["message"])
		if msg == "" {
			continue
		}
		out = append(out, parsedStatus{
			Severity: firstStr(obj["severity"]),
			Filename: firstStr(obj["filename"]),
			Line:     atoi(firstStr(obj["line"])),
			Message:  msg,
			Version:  firstStr(obj["version"]),
		})
	}
	return out, nil
}

var errNotArray = invalid("expected a JSON array")

func rowsFromJSON(raw []byte) ([]map[string]string, error) {
	if len(raw) == 0 {
		return []map[string]string{}, nil
	}
	var rows []map[string]string
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []map[string]string{}
	}
	return rows, nil
}
