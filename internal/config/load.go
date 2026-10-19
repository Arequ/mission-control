package config

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadPath loads a YAML file or every YAML document under a directory.
// Returned resources are normalized. Diagnostics are validation errors;
// a non-nil error means the path could not be read.
func LoadPath(path string) ([]Resource, []Diagnostic, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		resources, err := LoadFile(path)
		if err != nil {
			return nil, []Diagnostic{{Path: path, Message: err.Error()}}, nil
		}
		return resources, Validate(resources), nil
	}
	return LoadDir(path)
}

// LoadDir walks root for .yaml and .yml files.
func LoadDir(root string) ([]Resource, []Diagnostic, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if name != "." && strings.HasPrefix(name, ".") && path != root {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(name, ".") {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(files)
	var all []Resource
	var diags []Diagnostic
	for _, file := range files {
		resources, err := LoadFile(file)
		if err != nil {
			diags = append(diags, Diagnostic{Path: file, Message: err.Error()})
			continue
		}
		all = append(all, resources...)
	}
	diags = append(diags, Validate(all)...)
	return all, diags, nil
}

// LoadFile parses a single YAML file. Multi-document files are supported.
func LoadFile(path string) ([]Resource, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, fmt.Errorf("file exceeds 1MiB")
	}
	return Parse(path, b)
}

// Parse decodes YAML documents from b.
func Parse(path string, b []byte) ([]Resource, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var out []Resource
	for {
		var r Resource
		err := dec.Decode(&r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if r.APIVersion == "" && r.Kind == "" && r.Metadata.Name == "" && len(r.Spec) == 0 {
			continue
		}
		r.SourcePath = path
		r.Status = nil
		if r.Spec == nil {
			r.Spec = map[string]any{}
		}
		spec, ok := Canonicalize(r.Spec).(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: spec must be a mapping", path)
		}
		r.Spec = spec
		out = append(out, r)
	}
	return out, nil
}

// Marshal encodes resources as a multi-document YAML stream.
// Status and source path are omitted so the result is safe to commit.
func Marshal(resources []Resource) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	for _, r := range resources {
		r.Status = nil
		r.SourcePath = ""
		if err := enc.Encode(r); err != nil {
			_ = enc.Close()
			return nil, err
		}
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteDir writes one file per resource at dir/<kind>/<namespace>/<name>.yaml.
func WriteDir(dir string, resources []Resource) error {
	for _, r := range resources {
		r.Status = nil
		r.SourcePath = ""
		ns := r.Metadata.Namespace
		if ns == "" {
			ns = "default"
		}
		sub := filepath.Join(dir, strings.ToLower(r.Kind), ns)
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		b, err := Marshal([]Resource{r})
		if err != nil {
			return err
		}
		path := filepath.Join(sub, r.Metadata.Name+".yaml")
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}
