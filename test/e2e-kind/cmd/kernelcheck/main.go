// kernelcheck captures bounded, read-only observations for an owned test fixture.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"tsunaro.io/tailnet-operator/test/internal/kernelcheck"
)

func authorized(args []string, uid int) bool {
	return len(args) == 2 && args[1] == "--fixture=p2.1-kernel-prerequisites" &&
		(args[0] == "--capture=node" && uid == 65534 || args[0] == "--capture=pod" && uid == 65532)
}

func main() {
	if !authorized(os.Args[1:], os.Getuid()) {
		fail()
	}
	s, err := kernelcheck.Capture(strings.TrimPrefix(os.Args[1], "--capture="))
	if err != nil {
		fail()
	}
	b, err := json.Marshal(s)
	b = append(b, '\n')
	if err != nil || len(b) > kernelcheck.MaxJSON {
		fail()
	}
	if n, err := os.Stdout.Write(b); err != nil || n != len(b) {
		fail()
	}
}

func fail() { fmt.Fprintln(os.Stderr, "kernelcheck: fixture capture rejected"); os.Exit(2) }
