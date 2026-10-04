package main

import "testing"

func TestAuthorized(t *testing.T) {
	for _, tc := range []struct {
		args []string
		uid  int
		want bool
	}{
		{[]string{"--capture=node", "--fixture=p2.1-kernel-prerequisites"}, 65534, true},
		{[]string{"--capture=pod", "--fixture=p2.1-kernel-prerequisites"}, 65532, true},
		{[]string{"--capture=node", "--fixture=p2.1-kernel-prerequisites"}, 0, false},
		{[]string{"--capture=pod", "--fixture=p2.1-kernel-prerequisites"}, 65534, false},
		{[]string{"--capture=node", "--fixture=p1.8-layered-isolation"}, 65534, false},
		{[]string{"--capture=host", "--fixture=p2.1-kernel-prerequisites"}, 65534, false},
		{[]string{"--capture=node"}, 65534, false},
		{[]string{"--capture=node", "--fixture=p2.1-kernel-prerequisites", "--repair"}, 65534, false},
		{nil, 65534, false},
	} {
		if authorized(tc.args, tc.uid) != tc.want {
			t.Fatal("unexpected capture authorization")
		}
	}
}
