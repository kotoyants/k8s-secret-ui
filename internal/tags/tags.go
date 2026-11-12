// Package tags validates and normalizes tag lists used on roles and secrets.
package tags

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// MaxLen is the maximum length of a single tag (must match the DB CHECK constraint).
const MaxLen = 64

var valid = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// Normalize lowercases, trims, de-duplicates and sorts tags, and validates each one.
// Empty items are dropped. The result is never nil.
func Normalize(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if !valid.MatchString(t) {
			return nil, fmt.Errorf("invalid tag %q: use 1-%d characters a-z, 0-9, '-' or '_'", t, MaxLen)
		}
		out = append(out, t)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// Parse splits user input separated by commas and/or whitespace, then normalizes it.
func Parse(s string) ([]string, error) {
	return Normalize(strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}))
}
