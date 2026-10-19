// Package vuln matches installed software to public vulnerability records.
package vuln

import (
	"strings"
	"unicode"
)

// token is one numeric or alphabetic piece of a version.
type token struct {
	num    bool
	digits string
	text   string
}

// Compare orders two version strings. The boolean is false when either side
// is empty or not a version, so a missing build is not treated as zero and
// therefore not treated as ancient.
//
// Numeric pieces compare as integers, so 15.10 is newer than 15.2 and a
// leading zero does not change the value. Missing trailing numeric pieces
// are zeros, so 1.0 and 1.0.0 are the same release. A letter glued to a
// number is its own piece: 9.9p1 is newer than 9.9, and 24B100 is newer than
// 24B99. A hyphen that starts a word (1.0.0-beta) is a prerelease and sorts
// before the release. A hyphen that starts a digit stays in the release, so
// 1.0-1 is newer than 1.0.
func Compare(a, b string) (int, bool) {
	ar, ap, aok := splitVersion(a)
	br, bp, bok := splitVersion(b)
	if !aok || !bok {
		return 0, false
	}
	if c := compareTokens(ar, br); c != 0 {
		return c, true
	}
	switch {
	case ap == nil && bp == nil:
		return 0, true
	case ap == nil:
		return 1, true
	case bp == nil:
		return -1, true
	default:
		return compareTokens(ap, bp), true
	}
}

func splitVersion(s string) (release, pre []token, ok bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) > 200 {
		return nil, nil, false
	}
	if len(s) > 1 && s[0] == 'v' && s[1] >= '0' && s[1] <= '9' {
		s = s[1:]
	}
	main := s
	preStr := ""
	if i := strings.IndexByte(s, '-'); i >= 0 && i+1 < len(s) && isLetter(rune(s[i+1])) {
		main = s[:i]
		preStr = s[i+1:]
	}
	release = tokenize(main)
	if len(release) == 0 {
		return nil, nil, false
	}
	if preStr != "" {
		pre = tokenize(preStr)
		if len(pre) == 0 {
			return nil, nil, false
		}
	}
	return release, pre, true
}

func tokenize(s string) []token {
	var out []token
	var buf strings.Builder
	kind := 0
	flush := func() {
		if buf.Len() == 0 {
			return
		}
		raw := buf.String()
		buf.Reset()
		if kind == 1 {
			out = append(out, token{num: true, digits: raw})
		} else if kind == 2 {
			out = append(out, token{text: raw})
		}
		kind = 0
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			if kind == 2 {
				flush()
			}
			kind = 1
			buf.WriteRune(r)
		case isLetter(r):
			if kind == 1 {
				flush()
			}
			kind = 2
			buf.WriteRune(r)
		default:
			flush()
		}
	}
	flush()
	return out
}

func isLetter(r rune) bool {
	return unicode.IsLetter(r) && r < 128
}

func compareTokens(a, b []token) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		x := pad(a, i)
		y := pad(b, i)
		if x.num && y.num {
			if c := cmpNum(x.digits, y.digits); c != 0 {
				return c
			}
			continue
		}
		if x.num != y.num {
			// A glued letter is a real suffix (9.9p1). It is newer than a
			// missing piece, and older than a positive numeric piece.
			if x.num {
				if cmpNum(x.digits, "0") == 0 {
					return -1
				}
				return 1
			}
			if cmpNum(y.digits, "0") == 0 {
				return 1
			}
			return -1
		}
		if x.text < y.text {
			return -1
		}
		if x.text > y.text {
			return 1
		}
	}
	return 0
}

func pad(toks []token, i int) token {
	if i < len(toks) {
		return toks[i]
	}
	return token{num: true, digits: "0"}
}

func cmpNum(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if a == "" {
		a = "0"
	}
	if b == "" {
		b = "0"
	}
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// SameShape reports whether an installed version can be compared with the
// bounds. A CFBundleVersion such as 6778.86 must not be placed on a Chrome
// range whose first component is 131: the widths differ and the leading
// numbers are not the same magnitude, so the result would be noise.
func SameShape(installed string, bounds ...string) bool {
	it, _, ok := splitVersion(installed)
	if !ok {
		return false
	}
	in, ifirst := numCount(it), firstNum(it)
	checked := false
	for _, b := range bounds {
		if strings.TrimSpace(b) == "" {
			continue
		}
		bt, _, bok := splitVersion(b)
		if !bok {
			return false
		}
		checked = true
		bn, bf := numCount(bt), firstNum(bt)
		if in != bn && ifirst != "" && bf != "" && (numGreater(ifirst, bf, 8) || numGreater(bf, ifirst, 8)) {
			return false
		}
	}
	return checked
}

func numCount(toks []token) int {
	n := 0
	for _, t := range toks {
		if t.num {
			n++
		}
	}
	return n
}

func firstNum(toks []token) string {
	for _, t := range toks {
		if t.num {
			d := strings.TrimLeft(t.digits, "0")
			if d == "" {
				return "0"
			}
			return d
		}
	}
	return ""
}

func numGreater(a, b string, factor int) bool {
	return cmpNum(a, mulSmall(b, factor)) > 0
}

func mulSmall(digits string, factor int) string {
	if factor <= 0 {
		return "0"
	}
	out := make([]byte, 0, len(digits)+2)
	carry := 0
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i]-'0')*factor + carry
		out = append(out, byte('0'+d%10))
		carry = d / 10
	}
	for carry > 0 {
		out = append(out, byte('0'+carry%10))
		carry /= 10
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// Major is the leading numeric component, used to keep OS and ESR trains apart.
func Major(version string) (int, bool) {
	rel, _, ok := splitVersion(version)
	if !ok {
		return 0, false
	}
	d := firstNum(rel)
	if d == "" || len(d) > 6 {
		return 0, false
	}
	n := 0
	for _, r := range d {
		n = n*10 + int(r-'0')
	}
	return n, true
}
