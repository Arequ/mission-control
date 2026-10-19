package coverage

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// CompileQuery builds an Elasticsearch query body clause.
// language is "kql" or "dsl". An empty query matches everything in the window.
// DSL must be a JSON object, either a query clause or a search body with "query".
func CompileQuery(language, query, timeField string, since time.Time) (map[string]any, error) {
	var clause map[string]any
	var err error
	switch strings.ToLower(strings.TrimSpace(language)) {
	case "", "kql":
		clause, err = compileKQL(query)
	case "dsl":
		clause, err = compileDSL(query)
	default:
		return nil, fmt.Errorf("query language must be kql or dsl")
	}
	if err != nil {
		return nil, err
	}
	if since.IsZero() || strings.TrimSpace(timeField) == "" {
		return clause, nil
	}
	rangeQ := map[string]any{"range": map[string]any{timeField: map[string]any{"gte": since.UTC().Format(time.RFC3339Nano)}}}
	return map[string]any{"bool": map[string]any{"must": []any{clause, rangeQ}}}, nil
}

func compileDSL(query string) (map[string]any, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return map[string]any{"match_all": map[string]any{}}, nil
	}
	var v any
	if err := json.Unmarshal([]byte(query), &v); err != nil {
		return nil, fmt.Errorf("elasticsearch DSL must be JSON: %w", err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("elasticsearch DSL must be a JSON object")
	}
	if q, ok := obj["query"].(map[string]any); ok {
		return q, nil
	}
	return obj, nil
}

func compileKQL(query string) (map[string]any, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return map[string]any{"match_all": map[string]any{}}, nil
	}
	p := &kqlParser{tokens: lexKQL(query)}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("unexpected %q in KQL", p.peek().text)
	}
	return expr, nil
}

type tokKind int

const (
	tokEOF tokKind = iota
	tokWord
	tokString
	tokColon
	tokLParen
	tokRParen
	tokAnd
	tokOr
	tokNot
)

type token struct {
	kind tokKind
	text string
}

func lexKQL(s string) []token {
	var out []token
	i := 0
	for i < len(s) {
		r := rune(s[i])
		if unicode.IsSpace(r) {
			i++
			continue
		}
		switch s[i] {
		case ':':
			out = append(out, token{tokColon, ":"})
			i++
			continue
		case '(':
			out = append(out, token{tokLParen, "("})
			i++
			continue
		case ')':
			out = append(out, token{tokRParen, ")"})
			i++
			continue
		case '"':
			j := i + 1
			var b strings.Builder
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' && j+1 < len(s) {
					b.WriteByte(s[j+1])
					j += 2
					continue
				}
				b.WriteByte(s[j])
				j++
			}
			if j >= len(s) {
				out = append(out, token{tokWord, s[i:]})
				i = len(s)
				continue
			}
			out = append(out, token{tokString, b.String()})
			i = j + 1
			continue
		}
		j := i
		for j < len(s) && !unicode.IsSpace(rune(s[j])) && !strings.ContainsRune(":()", rune(s[j])) {
			j++
		}
		word := s[i:j]
		kind := tokWord
		switch strings.ToUpper(word) {
		case "AND":
			kind = tokAnd
		case "OR":
			kind = tokOr
		case "NOT":
			kind = tokNot
		}
		out = append(out, token{kind, word})
		i = j
	}
	out = append(out, token{tokEOF, ""})
	return out
}

type kqlParser struct {
	tokens []token
	i      int
}

func (p *kqlParser) peek() token { return p.tokens[p.i] }

func (p *kqlParser) next() token {
	t := p.tokens[p.i]
	if t.kind != tokEOF {
		p.i++
	}
	return t
}

func (p *kqlParser) parseOr() (map[string]any, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	var parts []any
	parts = append(parts, left)
	for p.peek().kind == tokOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		parts = append(parts, right)
	}
	if len(parts) == 1 {
		return left, nil
	}
	return map[string]any{"bool": map[string]any{"should": parts, "minimum_should_match": 1}}, nil
}

func (p *kqlParser) parseAnd() (map[string]any, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	parts := []any{left}
	for {
		k := p.peek().kind
		if k == tokEOF || k == tokOr || k == tokRParen {
			break
		}
		if k == tokAnd {
			p.next()
		}
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		parts = append(parts, right)
	}
	if len(parts) == 1 {
		return left, nil
	}
	return map[string]any{"bool": map[string]any{"must": parts}}, nil
}

func (p *kqlParser) parseNot() (map[string]any, error) {
	if p.peek().kind == tokNot {
		p.next()
		inner, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return map[string]any{"bool": map[string]any{"must_not": []any{inner}}}, nil
	}
	return p.parsePrimary()
}

func (p *kqlParser) parsePrimary() (map[string]any, error) {
	if p.peek().kind == tokLParen {
		p.next()
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("KQL missing closing parenthesis")
		}
		p.next()
		return expr, nil
	}
	return p.parseTerm()
}

func (p *kqlParser) parseTerm() (map[string]any, error) {
	tok := p.next()
	if tok.kind != tokWord && tok.kind != tokString {
		return nil, fmt.Errorf("unexpected %q in KQL", tok.text)
	}
	if tok.kind == tokWord && p.peek().kind == tokColon {
		p.next()
		val := p.next()
		if val.kind != tokWord && val.kind != tokString {
			return nil, fmt.Errorf("KQL field %s needs a value", tok.text)
		}
		if strings.ContainsAny(val.text, "*?") {
			return map[string]any{"wildcard": map[string]any{tok.text: map[string]any{"value": val.text}}}, nil
		}
		return map[string]any{"match_phrase": map[string]any{tok.text: val.text}}, nil
	}
	return map[string]any{"query_string": map[string]any{"query": tok.text}}, nil
}
