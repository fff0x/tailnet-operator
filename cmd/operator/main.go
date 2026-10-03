// Command tailnet-operator is the control plane. It watches Tailnet (cluster-scoped), TailnetEgress
// (namespaced, in its own namespace) and TailnetIngress (namespaced, in any tenant namespace), mints
// and rotates Headscale keys, and writes the per-CR agent Deployment + children. It never speaks
// tailscale — the agent does.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"tsunaro.io/tailnet-operator/internal/manager"
)

func main() {
	leaderElection := leaderElectionFlag(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New())
	l := ctrl.Log.WithName("setup")
	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		l.Error(nil, "POD_NAMESPACE is required")
		os.Exit(1)
	}
	image := os.Getenv("OPERATOR_IMAGE") // agent default = operator's own image
	imagePullSecrets, err := parseAgentImagePullSecrets(os.Getenv("AGENT_IMAGE_PULL_SECRETS"))
	if err != nil {
		l.Error(err, "invalid AGENT_IMAGE_PULL_SECRETS")
		os.Exit(1)
	}
	agentResources, err := parseAgentResources(os.Getenv("AGENT_RESOURCES"))
	if err != nil {
		l.Error(err, "invalid AGENT_RESOURCES")
		os.Exit(1)
	}
	mgr, err := manager.New(ctrl.GetConfigOrDie(), manager.Options{
		Namespace: ns, Image: image, AgentImagePullSecrets: imagePullSecrets, AgentResources: agentResources,
		LeaderElection:     *leaderElection,
		MetricsBindAddress: ":8080", HealthProbeBindAddress: ":8081",
	})
	if err != nil {
		l.Error(err, "create manager")
		os.Exit(1)
	}
	l.Info("starting tailnet-operator", "namespace", ns, "leaderElection", *leaderElection)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		l.Error(err, "manager exited")
		os.Exit(1)
	}
}

func leaderElectionFlag(fs *flag.FlagSet) *bool {
	return fs.Bool("leader-elect", true, "Elect one active operator using a namespaced Lease; disable only for a single non-overlapping process")
}

// parseAgentImagePullSecrets deliberately omits input values from errors: startup logs must not
// expose arbitrary environment contents, including malformed JSON or invalid Secret names.
func parseAgentImagePullSecrets(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var names []string
	if err := json.Unmarshal([]byte(raw), &names); err != nil || names == nil {
		return nil, fmt.Errorf("must be a JSON array of Kubernetes Secret names")
	}
	for i, name := range names {
		if len(validation.IsDNS1123Subdomain(name)) > 0 {
			return nil, fmt.Errorf("item %d must be a Kubernetes Secret name (DNS1123 subdomain, 1–253 characters)", i)
		}
	}
	return names, nil
}
