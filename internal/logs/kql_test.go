package logs

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCompileKQLSubset(t *testing.T) {
	q, err := Compile(`event.action: "ProcessRollup2" and process.name: ("curl" or "python3") and not user.name: "root"`, "message")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(q)
	text := string(raw)
	if strings.Contains(text, "query_string") {
		t.Fatalf("query_string leaked into %s", text)
	}
	if !strings.Contains(text, "match_phrase") || !strings.Contains(text, "must_not") || !strings.Contains(text, "should") {
		t.Fatalf("structure: %s", text)
	}
}

func TestQuotedStarIsLiteral(t *testing.T) {
	q, err := Compile(`host.name: "foo* OR host.name:*"`, "message")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(q)
	if strings.Contains(string(raw), "wildcard") {
		t.Fatalf("quoted star became a wildcard: %s", raw)
	}
	phrase := q["match_phrase"].(map[string]any)["host.name"]
	if phrase != "foo* OR host.name:*" {
		t.Fatalf("phrase = %#v", phrase)
	}
}

func TestUnquotedWildcard(t *testing.T) {
	q, err := Compile(`process.name: curl*`, "message")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := q["wildcard"]; !ok {
		t.Fatalf("got %#v", q)
	}
}

func TestFreeTextUsesMessageField(t *testing.T) {
	q, err := Compile(`"install failed"`, "message")
	if err != nil {
		t.Fatal(err)
	}
	if q["match_phrase"].(map[string]any)["message"] != "install failed" {
		t.Fatalf("%#v", q)
	}
}

func TestRejectsQueryStringSyntax(t *testing.T) {
	if _, err := Compile(`host.name:`, "message"); err == nil {
		t.Fatal("expected a parse error")
	}
	if _, err := Compile(`bad-field: "x"`, "message"); err == nil {
		t.Fatal("expected field rejection")
	}
}

func TestSubstituteIsInjectionSafe(t *testing.T) {
	hostile := `foo" OR host.name:* OR host.name:"bar`
	kql, err := Substitute(`host.name: {{hostname}} and event.dataset: "munki"`, Bind{Hostname: hostile})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(kql, "{{") {
		t.Fatal(kql)
	}
	q, err := Compile(kql, "message")
	if err != nil {
		t.Fatal(err, kql)
	}
	raw, _ := json.Marshal(q)
	if strings.Contains(string(raw), "wildcard") || strings.Contains(string(raw), "query_string") {
		t.Fatalf("injection widened the query: %s\ncompiled %s", kql, raw)
	}
	phrase := q["bool"].(map[string]any)["must"].([]any)[0].(map[string]any)["match_phrase"].(map[string]any)["host.name"]
	if phrase != hostile {
		t.Fatalf("phrase %#v", phrase)
	}
}

func TestUnknownPlaceholder(t *testing.T) {
	if _, err := Substitute(`{{user}}`, Bind{}); err == nil {
		t.Fatal("unknown placeholder accepted")
	}
	if _, err := Substitute(`host: {{hostname`, Bind{Hostname: "a"}); err == nil {
		t.Fatal("unclosed placeholder accepted")
	}
}

func TestPlaceholderControlCharacter(t *testing.T) {
	if _, err := Substitute(`host.name: {{hostname}}`, Bind{Hostname: "a\nb"}); err == nil {
		t.Fatal("newline accepted")
	}
}

func TestQuotedPlaceholderOnce(t *testing.T) {
	// The braces are the token. A surrounding quote is the operator's problem;
	// the token itself becomes one quoted literal, and the compiler must see it.
	kql, err := Substitute(`host.name: {{ serial }}`, Bind{Serial: `C02"XYZ`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(kql, "message"); err != nil {
		t.Fatal(err, kql)
	}
}
