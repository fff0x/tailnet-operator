//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/policy"
)

const spokeFragmentDoc = `{"tagOwners":{"tag:egress-prod-2-db":["group:ops"]},` +
	`"autoApprovers":{"routes":{"198.51.100.5/32":["tag:fabric"]}},` +
	`"grants":[{"src":["tag:egress-prod-2-db"],"dst":["198.51.100.5/32"],"ip":["tcp:5432"]}]}`

// spokeReaderKubeconfig makes the disposable API server play the spoke: a ServiceAccount whose Role
// may read exactly one ConfigMap, a short-lived token for it, and a kubeconfig the hub stores.
func spokeReaderKubeconfig(t *testing.T, ctx context.Context, prefix, configMap string) (kubeconfig string, role *rbacv1.Role) {
	t.Helper()
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: prefix + "-reader", Namespace: namespace}}
	role = &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: prefix + "-reader", Namespace: namespace},
		Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{configMap}, Verbs: []string{"get", "list", "watch"}}}}
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: prefix + "-reader", Namespace: namespace},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: sa.Name, Namespace: namespace}}}
	for _, obj := range []client.Object{sa, role, rb} {
		if err := kube.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = kube.Delete(context.Background(), obj) })
	}
	tr := &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: ptr.To[int64](3600)}}
	if err := kube.SubResource("token").Create(ctx, sa, tr); err != nil {
		t.Fatal(err)
	}
	ca := base64.StdEncoding.EncodeToString(apiCfg.CAData)
	kubeconfig = fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: spoke
  cluster:
    server: %s
    certificate-authority-data: %s
users:
- name: reader
  user:
    token: %s
contexts:
- name: spoke
  context:
    cluster: spoke
    user: reader
current-context: spoke
`, apiCfg.Host, ca, tr.Status.Token)
	return kubeconfig, role
}

func spokeStatus(tn *tnv1.Tailnet, name string) *tnv1.SpokeStatus {
	for i := range tn.Status.Spokes {
		if tn.Status.Spokes[i].Name == name {
			return &tn.Status.Spokes[i]
		}
	}
	return nil
}

// A hub pulls a spoke's fragment through a kubeconfig scoped to that one ConfigMap and gates it:
// Manual holds the first fetch as pending (nothing reaches Headscale), the approve annotation adopts
// it, the merged policy carries the spoke's grant. When the reader loses its RBAC the spoke turns
// Forbidden while the approved fragment stays live; the stored token never shows up in status.
func TestHubSpokePull(t *testing.T) {
	ctx := testContext(t)
	hs := startHeadscale(t, ctx, "v0.29.3", "database", false)
	name := createTailnet(t, ctx, hs)
	// The base owns tag:fabric (Headscale validates route approvers against tagOwners) and
	// defines group:ops, the only tag owner this hub allows (Headscale refuses autogroups there).
	enablePolicy(t, ctx, name, `{"groups":{"group:ops":["ops@"]},"tagOwners":{"tag:fabric":["group:ops"]},"acls":[{"action":"accept","src":["*"],"dst":["192.0.2.1:443"]}]}`, "Apply")
	updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) { tn.Spec.Policy.TagOwners = []string{"group:ops"} })
	waitApplied(t, ctx, name, "192.0.2.1:443", hs)

	fragment := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name + "-prod-2-fragment", Namespace: namespace},
		Data: map[string]string{"policy": spokeFragmentDoc}}
	if err := kube.Create(ctx, fragment); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = kube.Delete(context.Background(), fragment) })
	kubeconfig, role := spokeReaderKubeconfig(t, ctx, name, fragment.Name)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name + "-prod-2-kubeconfig", Namespace: namespace},
		Data: map[string][]byte{"kubeconfig": []byte(kubeconfig)}}
	if err := kube.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = kube.Delete(context.Background(), secret)
		for _, kind := range []string{"approved", "pending"} {
			_ = kube.Delete(context.Background(), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "prod-2-policy-fragment-" + kind, Namespace: namespace}})
		}
	})

	updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) {
		tn.Spec.Policy.Spokes = []tnv1.SpokeRef{{Name: "prod-2", Approval: "Manual",
			KubeconfigSecretRef: tnv1.SpokeKubeconfigRef{Name: secret.Name}, ConfigMap: fragment.Name}}
	})
	waitCondition(t, ctx, name, "SpokesReady", metav1.ConditionFalse, "ApprovalPending")
	tn := getTailnet(t, ctx, name)
	st := spokeStatus(tn, "prod-2")
	canonical, _ := policy.Normalize([]byte(spokeFragmentDoc))
	if st == nil || st.PendingHash != policy.Hash(canonical) || st.ApprovedHash != "" {
		t.Fatalf("spoke status = %+v", st)
	}
	if strings.Contains(livePolicy(t, ctx, hs), "tag:egress-prod-2-db") {
		t.Fatal("pending fragment reached Headscale")
	}
	var pending corev1.ConfigMap
	if err := kube.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "prod-2-policy-fragment-pending"}, &pending); err != nil || pending.Data["policy"] != spokeFragmentDoc {
		t.Fatalf("pending copy for review: %v %q", err, pending.Data["policy"])
	}

	updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) {
		if tn.Annotations == nil {
			tn.Annotations = map[string]string{}
		}
		tn.Annotations["tsunaro.io/approve-spoke.prod-2"] = st.PendingHash
	})
	waitCondition(t, ctx, name, "SpokesReady", metav1.ConditionTrue, "AllMerged")
	eventually(t, ctx, "spoke grant live", func() bool {
		if c := meta.FindStatusCondition(getTailnet(t, ctx, name).Status.Conditions, "PolicyApplied"); c != nil && c.Reason == "PolicyRejected" {
			t.Fatalf("merged policy rejected: %s", c.Message)
		}
		return strings.Contains(livePolicy(t, ctx, hs), "tag:egress-prod-2-db")
	})
	tn = getTailnet(t, ctx, name)
	if st = spokeStatus(tn, "prod-2"); st.ApprovedHash != policy.Hash(canonical) || st.PendingHash != "" {
		t.Fatalf("spoke status after approval = %+v", st)
	}

	// Revoke the reader's access: the fragment stays merged, the spoke reports Forbidden.
	role.Rules[0].ResourceNames = []string{"something-else"}
	if err := kube.Update(ctx, role); err != nil {
		t.Fatal(err)
	}
	// A spec change wakes the hub without waiting for the periodic requeue.
	updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) { tn.Spec.Policy.Spokes[0].TagPatterns = []string{"tag:*-prod-2-*"} })
	eventually(t, ctx, "spoke Forbidden", func() bool {
		st := spokeStatus(getTailnet(t, ctx, name), "prod-2")
		return st != nil && meta.IsStatusConditionFalse(st.Conditions, "SpokeReachable") &&
			meta.FindStatusCondition(st.Conditions, "SpokeReachable").Reason == "Forbidden"
	})
	if !strings.Contains(livePolicy(t, ctx, hs), "tag:egress-prod-2-db") {
		t.Fatal("approved fragment dropped on a fetch failure")
	}
	token := strings.TrimSpace(strings.Split(strings.Split(kubeconfig, "token: ")[1], "\n")[0])
	tn = getTailnet(t, ctx, name)
	for _, s := range tn.Status.Spokes {
		for _, c := range s.Conditions {
			if strings.Contains(c.Message, token) {
				t.Fatalf("token in status: %s", c.Message)
			}
		}
	}
}
