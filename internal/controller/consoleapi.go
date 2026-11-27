package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
	operatormetrics "tsunaro.io/tailnet-operator/internal/metrics"
)

// ConsoleAPIAudience is the audience of the projected ServiceAccount token the console presents.
// A token for this audience is useless against the Kubernetes API server.
const ConsoleAPIAudience = "tailnet-operator"

// ConsoleAPI serves the console the Headscale data it has no key for: users, tagged nodes and the
// live policy of one Tailnet. Only the ServiceAccount named by Subject may call it. Responses carry
// personal data; nothing of a request or response reaches logs, status, events or metric labels.
type ConsoleAPI struct {
	Client            client.Client
	OperatorNamespace string
	Subject           string
	Metrics           *operatormetrics.Metrics
}

// ConsoleNode is the subset of a tagged node the console map needs.
type ConsoleNode struct {
	Name     string     `json:"name"`
	Online   bool       `json:"online"`
	LastSeen *time.Time `json:"lastSeen,omitempty"`
	Tags     []string   `json:"tags"`
}

// Handler authenticates every request before routing it.
func (a *ConsoleAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tailnets/{name}/users", a.serve(func(ctx context.Context, hs *headscale.Client) (any, error) {
		users, err := hs.ListUsers(ctx)
		if users == nil {
			users = []headscale.User{}
		}
		return map[string]any{"users": users}, err
	}))
	mux.HandleFunc("GET /v1/tailnets/{name}/nodes", a.serve(func(ctx context.Context, hs *headscale.Client) (any, error) {
		nodes, err := hs.ListNodes(ctx)
		out := []ConsoleNode{}
		for _, n := range nodes {
			// Untagged nodes are personal devices; their names never leave the operator.
			if len(n.Tags) == 0 {
				continue
			}
			name := n.GivenName
			if name == "" {
				name = n.Name
			}
			out = append(out, ConsoleNode{Name: name, Online: n.Online, LastSeen: n.LastSeen, Tags: n.Tags})
		}
		return map[string]any{"nodes": out}, err
	}))
	mux.HandleFunc("GET /v1/tailnets/{name}/policy", a.serve(func(ctx context.Context, hs *headscale.Client) (any, error) {
		policy, err := hs.GetPolicy(ctx)
		return map[string]string{"policy": policy}, err
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if code := a.authenticate(r); code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *ConsoleAPI) authenticate(r *http.Request) int {
	log := logf.FromContext(r.Context()).WithName("console-api")
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		log.Info("request rejected", "reason", "no bearer token")
		return http.StatusUnauthorized
	}
	tr := &authv1.TokenReview{Spec: authv1.TokenReviewSpec{Token: token, Audiences: []string{ConsoleAPIAudience}}}
	if err := a.Client.Create(r.Context(), tr); err != nil {
		log.Error(err, "token review failed")
		return http.StatusServiceUnavailable
	}
	switch {
	case !tr.Status.Authenticated || !slices.Contains(tr.Status.Audiences, ConsoleAPIAudience):
		log.Info("request rejected", "reason", "token not valid for the console API")
		return http.StatusUnauthorized
	case tr.Status.User.Username != a.Subject:
		log.Info("request rejected", "reason", "caller is not the console")
		return http.StatusForbidden
	}
	return http.StatusOK
}

func (a *ConsoleAPI) serve(read func(context.Context, *headscale.Client) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		log := logf.FromContext(ctx).WithName("console-api")
		var tn tnv1.Tailnet
		if err := a.Client.Get(ctx, types.NamespacedName{Name: r.PathValue("name")}, &tn); err != nil {
			if apierrors.IsNotFound(err) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			log.Error(err, "read Tailnet failed")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		key, err := readWorkingKey(ctx, a.Client, a.OperatorNamespace, tn.Name)
		if err != nil {
			log.Info("working API key unavailable", "tailnet", tn.Name)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		apiURL := tn.Spec.APIURL
		if apiURL == "" {
			apiURL = tn.Spec.Server
		}
		body, err := read(ctx, headscale.New(apiURL, key, a.Metrics.Headscale(tn.Name)))
		if err != nil {
			// headscale errors are sanitized; the upstream body is never read or forwarded.
			log.Info("Headscale read failed", "tailnet", tn.Name, "error", err.Error())
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}
