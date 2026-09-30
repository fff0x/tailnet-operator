package isolation

import (
	"os"
	"testing"
)

func TestClearEnvtestOverrides(t *testing.T) {
	removed := []string{"ETCD_CONFIG_FILE", "ETCD_DATA_DIR", "ETCD_INITIAL_CLUSTER", "ETCD_LISTEN_CLIENT_URLS", "ETCD_UNSUPPORTED_ARCH", "TEST_ASSET_ETCD", "TEST_ASSET_KUBE_APISERVER", "TEST_ASSET_KUBECTL"}
	for _, name := range removed {
		t.Setenv(name, "must-not-be-used")
	}
	kept := []string{"KUBEBUILDER_ASSETS", "HEADSCALE_VERSIONS", "E2E_HEADSCALE_DIR", "ETCDCTL_ENDPOINTS"}
	for _, name := range kept {
		t.Setenv(name, "keep-explicit-selection")
	}
	if err := ClearEnvtestOverrides(); err != nil {
		t.Fatal(err)
	}
	for _, name := range removed {
		if _, exists := os.LookupEnv(name); exists {
			t.Errorf("%s was not cleared", name)
		}
	}
	for _, name := range kept {
		if os.Getenv(name) != "keep-explicit-selection" {
			t.Errorf("%s should be preserved", name)
		}
	}
}
