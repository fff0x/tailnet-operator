// netprobe captures private fixture evidence, not an ownership or security proof.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"tsunaro.io/tailnet-operator/test/internal/netproof"
)

// No defaults, environment fallbacks, or command execution. This gate runs
// before reading proc files, opening netlink sockets, or checking external dials.
func authorized(args []string, uid int) bool {
	if len(args) != 2 || args[1] != "--fixture=p1.8-layered-isolation" {
		return false
	}
	return args[0] == "--capture=node" && uid == 65534 || args[0] == "--capture=pod" && uid == 65532
}
func main() {
	if !authorized(os.Args[1:], os.Getuid()) {
		fail()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	s, err := netproof.Capture(ctx)
	if err != nil {
		fail()
	}
	s.Dials = netproof.CheckExternal(ctx)
	if ctx.Err() != nil {
		fail()
	}
	b, err := json.Marshal(s)
	b = append(b, '\n')
	if err != nil || len(b) > netproof.MaxJSON {
		fail()
	}
	if n, err := os.Stdout.Write(b); err != nil || n != len(b) {
		fail()
	}
}
func fail() { fmt.Fprintln(os.Stderr, "netprobe: fixture capture rejected"); os.Exit(2) }
