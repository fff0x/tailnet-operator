package routes

import "testing"

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func TestClassify(t *testing.T) {
	r := "10.0.10.20/32"
	cases := []struct {
		name                         string
		netmap, advertised, approved map[string]bool
		want                         Reason
	}{
		{
			name:       "present in netmap",
			netmap:     set(r),
			advertised: set(r),
			approved:   set(r),
			want:       Present,
		},
		{
			name:       "nobody advertises it",
			netmap:     set(),
			advertised: set("10.0.0.0/24"),
			approved:   set(),
			want:       NotAdvertised,
		},
		{
			name:       "advertised but not approved",
			netmap:     set(),
			advertised: set(r),
			approved:   set(),
			want:       NotApproved,
		},
		{
			name:       "advertised and approved but not in this node's netmap",
			netmap:     set(),
			advertised: set(r),
			approved:   set(r),
			want:       NoGrant,
		},
	}
	for _, c := range cases {
		if got := Classify(r, c.netmap, c.advertised, c.approved); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
