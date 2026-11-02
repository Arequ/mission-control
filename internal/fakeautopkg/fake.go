// Package fakeautopkg is a stand-in for autopkg so mc-runner can be tested on Linux.
package fakeautopkg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Main runs the fake autopkg CLI.
func Main(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fake-autopkg verify-trust-info|run ...")
		return 2
	}
	switch args[0] {
	case "verify-trust-info":
		return verify(args[1:])
	case "run":
		return run(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %s\n", args[0])
		return 2
	}
}

func flag(args []string, name string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--"+name {
			return args[i+1]
		}
	}
	return ""
}

func verify(args []string) int {
	overridePath := flag(args, "override")
	trustPath := flag(args, "trust")
	if overridePath == "" || trustPath == "" {
		fmt.Fprintln(os.Stderr, "verify-trust-info requires --override and --trust")
		return 2
	}
	override, err := os.ReadFile(overridePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	trustRaw, err := os.ReadFile(trustPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var trust map[string]any
	if err := json.Unmarshal(trustRaw, &trust); err != nil {
		fmt.Fprintf(os.Stderr, "trust info: %v\n", err)
		return 1
	}
	if fail, _ := trust["fail"].(bool); fail {
		fmt.Fprintln(os.Stderr, "trust verification failed: trust info marked fail")
		return 1
	}
	if exp, _ := trust["expected_override_sha256"].(string); exp != "" {
		sum := sha256.Sum256(override)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(exp, got) {
			fmt.Fprintf(os.Stderr, "trust verification failed: override sha256 %s != %s\n", got, exp)
			return 1
		}
	}
	if parents, ok := trust["parent_recipes"].([]any); ok {
		for _, p := range parents {
			m, _ := p.(map[string]any)
			if m["sha256"] == "invalid" {
				id, _ := m["identifier"].(string)
				fmt.Fprintf(os.Stderr, "trust verification failed: parent %s hash mismatch\n", id)
				return 1
			}
		}
		fmt.Printf("trust verification succeeded for %d parent recipe(s)\n", len(parents))
		return 0
	}
	fmt.Println("trust verification succeeded")
	return 0
}

func run(args []string) int {
	overridePath := flag(args, "override")
	outDir := flag(args, "output")
	if overridePath == "" || outDir == "" {
		fmt.Fprintln(os.Stderr, "run requires --override and --output")
		return 2
	}
	override, err := os.ReadFile(overridePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	text := string(override)
	if strings.Contains(text, "FORCE_ERROR") {
		fmt.Println("autopkg: starting")
		fmt.Fprintln(os.Stderr, "autopkg: forced error")
		return 1
	}
	name := plistString(text, "NAME")
	if name == "" {
		name = "Package"
	}
	version := plistString(text, "VERSION")
	if version == "" {
		version = "1.0.0"
	}
	fmt.Printf("autopkg: processing %s\n", filepath.Base(overridePath))
	fmt.Printf("autopkg: found %s %s\n", name, version)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	filename := name + "-" + version + ".pkg"
	pkg := []byte("fake-pkg " + name + " " + version + "\n")
	if err := os.WriteFile(filepath.Join(outDir, filename), pkg, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	plistDoc := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>name</key>
	<string>%s</string>
	<key>version</key>
	<string>%s</string>
	<key>unattended_install</key>
	<true/>
	<key>installer_item_location</key>
	<string>%s</string>
</dict>
</plist>
`, xmlEscape(name), xmlEscape(version), xmlEscape(filename))
	if err := os.WriteFile(filepath.Join(outDir, "pkginfo.plist"), []byte(plistDoc), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("autopkg: wrote %s\n", filename)
	return 0
}

var plistStringRE = regexp.MustCompile(`<key>([^<]+)</key>\s*<string>([^<]*)</string>`)

func plistString(doc, key string) string {
	for _, m := range plistStringRE.FindAllStringSubmatch(doc, -1) {
		if m[1] == key {
			return m[2]
		}
	}
	return ""
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
