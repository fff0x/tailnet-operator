//go:build e2e_kind && !linux

package e2ekind

import (
	"fmt"
	"os/exec"
)

func configureCommandLifecycle(_ *exec.Cmd) (func(), error) {
	return nil, fmt.Errorf("command lifecycle requires Linux process-group pidfds")
}
