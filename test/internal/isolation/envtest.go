// Package isolation contains safety guards shared by disposable API-server tests.
package isolation

import (
	"fmt"
	"os"
	"strings"
)

// ClearEnvtestOverrides removes inherited settings that can escape the test's explicit config.
// In particular, ETCD_CONFIG_FILE overrides even envtest's data-dir/listen CLI arguments, and
// TEST_ASSET_* takes precedence over BinaryAssetsDirectory. Call before starting any processes.
// Changes affect only this dedicated test process, not its invoking shell.
func ClearEnvtestOverrides() error {
	for _, variable := range os.Environ() {
		name, _, _ := strings.Cut(variable, "=")
		if strings.HasPrefix(name, "ETCD_") || strings.HasPrefix(name, "TEST_ASSET_") {
			if err := os.Unsetenv(name); err != nil {
				return fmt.Errorf("clear envtest override %s: %w", name, err)
			}
		}
	}
	return nil
}
