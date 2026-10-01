package main

import (
	"context"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	marker := []string{"--fixture=p1.8-layered-isolation"}
	if validate(marker, 65532) != nil {
		t.Fatal("valid holder rejected")
	}
	for _, tc := range []struct {
		args []string
		uid  int
	}{
		{nil, 65532}, {marker, 0}, {marker, 65534},
		{[]string{"--fixture=wrong"}, 65532}, {append(marker, "extra"), 65532},
	} {
		if validate(tc.args, tc.uid) == nil {
			t.Fatal("invalid holder accepted")
		}
	}
}

func TestBoundedWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { wait(ctx, time.Hour); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("signal not honored")
	}
	done = make(chan struct{})
	go func() { wait(context.Background(), time.Millisecond); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("deadline not honored")
	}
}
