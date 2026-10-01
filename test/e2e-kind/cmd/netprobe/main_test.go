package main

import "testing"

func TestAuthorizationWithoutCapture(t *testing.T) {
	for _, tt := range []struct {
		args []string
		uid  int
		want bool
	}{
		{nil, 65534, false}, {[]string{"--capture=node"}, 65534, false},
		{[]string{"--capture=node", "--fixture=p1.8-layered-isolation"}, 1000, false},
		{[]string{"--capture=node", "--fixture=p1.8-layered-isolation"}, 0, false},
		{[]string{"--capture=node", "--fixture=p1.8-layered-isolation"}, 65532, false},
		{[]string{"--capture=node", "--fixture=p1.8-layered-isolation"}, 65534, true},
		{[]string{"--capture=pod", "--fixture=p1.8-layered-isolation"}, 65532, true},
		{[]string{"--capture=pod", "--fixture=wrong"}, 65532, false},
		{[]string{"--capture=pod", "--fixture=p1.8-layered-isolation", "extra"}, 65532, false},
		// The removed TCP observation mode must stay rejected.
		{[]string{"--observe=pod-tcp", "--fixture=p1.8-layered-isolation"}, 65532, false},
		{[]string{"--fixture=p1.8-layered-isolation", "--capture=pod"}, 65532, false},
		{[]string{"--capture=pod ", "--fixture=p1.8-layered-isolation"}, 65532, false},
	} {
		if authorized(tt.args, tt.uid) != tt.want {
			t.Fatal("unexpected authorization")
		}
	}
}
