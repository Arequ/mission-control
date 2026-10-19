package logs

import (
	"fmt"
	"strings"
	"unicode"
)

// Compile translates a small KQL subset into an Elasticsearch query.
// Field comparisons become match_phrase, or wildcard when the configured
// value itself contains * or ?. Quoted text is always a literal, so a
// substituted device name cannot widen the query. Free text is a match_phrase
// on messageField. There is no query_string pass-through.
func Compile(query, messageField string) (map[string]any, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return map[string]any{"match_all": map[string]any{}}, nil
	}
	if strings.TrimSpace(messageField) == "" {
		return nil, fmt.Errorf("message field is required")
	}
	if !fieldName(messageField) {
		return nil, fmt.Errorf("message field %q is not a dotted path", messageField)
	}
	p := &kqlParser{tokens: lexKQL(query), message: messageField}
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
			closed := false
			for j < len(s) {
				if s[j] == '\\' && j+1 < len(s) {
					b.WriteByte(s[j+1])
					j += 2
					continue
				}
				if s[j] == '"' {
					closed = true
					break
				}
				b.WriteByte(s[j])
				j++
			}
			if !closed {
				out = append(out, token{tokWord, s[i:]})
				i = len(s)
				continue
			}
			out = append(out, token{tokString, b.String()})
			i = j + 1
			continue
		}
		j := i
		for j < len(s) && !unicode.IsSpace(rune(s[j])) && !strings.ContainsRune(":()\"", rune(s[j])) {
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
	tokens  []token
	i       int
	message string
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
	parts := []any{left}
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
		if !fieldName(tok.text) {
			return nil, fmt.Errorf("KQL field %q is not a dotted path", tok.text)
		}
		p.next()
		return p.parseFieldValue(tok.text)
	}
	if tok.kind == tokString {
		return phrase(p.message, tok.text), nil
	}
	return phrase(p.message, tok.text), nil
}

func (p *kqlParser) parseFieldValue(field string) (map[string]any, error) {
	if p.peek().kind == tokLParen {
		p.next()
		var parts []any
		for {
			clause, err := p.parseOneValue(field)
			if err != nil {
				return nil, err
			}
			parts = append(parts, clause)
			if p.peek().kind == tokOr {
				p.next()
				continue
			}
			if p.peek().kind == tokRParen {
				p.next()
				break
			}
			return nil, fmt.Errorf("KQL field %s group must be values separated by or", field)
		}
		if len(parts) == 0 {
			return nil, fmt.Errorf("KQL field %s needs a value", field)
		}
		if len(parts) == 1 {
			return parts[0].(map[string]any), nil
		}
		return map[string]any{"bool": map[string]any{"should": parts, "minimum_should_match": 1}}, nil
	}
	return p.parseOneValue(field)
}

func (p *kqlParser) parseOneValue(field string) (map[string]any, error) {
	val := p.next()
	if val.kind != tokWord && val.kind != tokString {
		return nil, fmt.Errorf("KQL field %s needs a value", field)
	}
	// Quoted text is a literal even when it contains * or ?.
	if val.kind == tokString {
		return phrase(field, val.text), nil
	}
	if strings.ContainsAny(val.text, "*?") {
		if !wildcardText(val.text) {
			return nil, fmt.Errorf("KQL wildcard for %s may only contain letters, digits, and *?", field)
		}
		return map[string]any{"wildcard": map[string]any{field: map[string]any{"value": val.text}}}, nil
	}
	if strings.ContainsAny(val.text, `+-=&|><!(){}[]^"~:\/`) {
		return nil, fmt.Errorf("KQL value for %s must be quoted", field)
	}
	return phrase(field, val.text), nil
}

func phrase(field, value string) map[string]any {
	return map[string]any{"match_phrase": map[string]any{field: value}}
}

func fieldName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i, r := range s {
		switch {
		case r == '@' && i == 0:
			continue
		case r == '.' && i > 0:
			continue
		case r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			continue
		default:
			return false
		}
	}
	return true
}

func wildcardText(s string) bool {
	if s == "" || len(s) > 200 {
		return false
	}
	for _, r := range s {
		switch {
		case r == '*' || r == '?' || r == '_' || r == '-' || r == '.' || r == '@':
			continue
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			continue
		default:
			return false
		}
	}
	return true
}
