package tags

import (
	"slices"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{"", []string{}, false},
		{" , ,", []string{}, false},
		{"front", []string{"front"}, false},
		{"Prod, front  front\nback_end", []string{"back_end", "front", "prod"}, false},
		{"a-b,c_d,9", []string{"9", "a-b", "c_d"}, false},
		{"bad tag!", nil, true},
		{"фронт", nil, true},
		{"a.b", nil, true},
		{strings.Repeat("a", MaxLen), []string{strings.Repeat("a", MaxLen)}, false},
		{strings.Repeat("a", MaxLen+1), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := Parse(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeNeverNil(t *testing.T) {
	got, err := Normalize(nil)
	if err != nil || got == nil {
		t.Fatalf("got %v, %v; want empty non-nil slice", got, err)
	}
}
