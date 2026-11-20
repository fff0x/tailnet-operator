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
		name, route                  string
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
			name:       "covered by an aggregate LAN route",
			netmap:     set("10.0.0.0/8"),
			advertised: set("10.0.0.0/8"),
			approved:   set("10.0.0.0/8"),
			want:       Present,
		},
		{
			name:       "aggregate advertised and approved, not in netmap",
			netmap:     set("192.168.0.0/16"),
			advertised: set("10.0.0.0/8"),
			approved:   set("10.0.0.0/8"),
			want:       NoGrant,
		},
		{
			name:       "a narrower prefix does not cover a wider one",
			route:      "10.0.10.0/24",
			netmap:     set(),
			advertised: set("10.0.10.20/32", "10.0.10.0/25"),
			approved:   set(),
			want:       NotAdvertised,
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
		{
			name:       "only a default route is advertised and approved",
			netmap:     set(),
			advertised: set("0.0.0.0/0", "::/0"),
			approved:   set("0.0.0.0/0", "::/0"),
			want:       NotAdvertised,
		},
		{
			name:       "a default route in the netmap does not make the target present",
			netmap:     set("0.0.0.0/0"),
			advertised: set("0.0.0.0/0"),
			approved:   set("0.0.0.0/0"),
			want:       NotAdvertised,
		},
		{
			name:       "an approved default route does not approve the site route",
			netmap:     set("0.0.0.0/0"),
			advertised: set("0.0.0.0/0", "10.0.0.0/8"),
			approved:   set("0.0.0.0/0"),
			want:       NotApproved,
		},
		{
			name:       "IPv6 target behind a default route only",
			route:      "2001:db8::20/128",
			netmap:     set("::/0"),
			advertised: set("::/0"),
			approved:   set("::/0"),
			want:       NotAdvertised,
		},
	}
	for _, c := range cases {
		route := c.route
		if route == "" {
			route = r
		}
		if got := Classify(route, c.netmap, c.advertised, c.approved); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
