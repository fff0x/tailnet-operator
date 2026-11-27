package console

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// state is one condition as the page shows it: the reason, coloured by status.
type state struct {
	Text  string
	Class string // ok, bad, unknown
}

func condState(conds []metav1.Condition, t string) state {
	c := meta.FindStatusCondition(conds, t)
	switch {
	case c == nil:
		return state{Text: "—", Class: "unknown"}
	case c.Status == metav1.ConditionTrue:
		return state{Text: c.Reason, Class: "ok"}
	case c.Status == metav1.ConditionFalse:
		return state{Text: c.Reason, Class: "bad"}
	}
	return state{Text: c.Reason, Class: "unknown"}
}

// policyState shows PolicyApplied. A False that only names the chosen mode (DryRun,
// PolicyModeFile, Export) is neutral; every other False (HubPending, NoAPIKey, errors) is a fault.
func policyState(conds []metav1.Condition) state {
	st := condState(conds, "PolicyApplied")
	if st.Class == "bad" && slices.Contains([]string{"DryRun", "PolicyModeFile", "Export"}, st.Text) {
		st.Class = "unknown"
	}
	return st
}

type tailnetRow struct {
	Name, Server, Version, Mode, Generated string
	Policy                                 state
}

type spokeRow struct {
	Tailnet, Name              string
	Reachable, Valid, Approved state
	Pending                    bool
}

type ingressRow struct {
	Namespace, Name, Tailnet, Tag string
	Hosts, Ports, AllowFrom       []string
	Ready                         state
}

type siteRow struct {
	Tailnet, Name, Owner, Description string
	Prefixes                          []string
	Ready                             state
}

type overview struct {
	Maps      []tailnetMap
	PollMS    int64 // how often the page module reloads the live part; 0 disables it
	Tailnets  []tailnetRow
	Spokes    []spokeRow
	Ingresses []ingressRow
	Sites     []siteRow
}

func policyMode(tn *tnv1.Tailnet) string {
	switch {
	case tn.Spec.Policy.Mode == "Export":
		return "Export"
	case tn.Spec.Policy.BaseConfigMap == "":
		return "off"
	case tn.Spec.Policy.Mode == "":
		return "DryRun"
	}
	return tn.Spec.Policy.Mode
}

// maskUsers keeps groups, tags and autogroups and replaces user references by their count:
// a user reference names a person, and the overview is visible to every signed-in user.
func maskUsers(sources []string) []string {
	var out []string
	users := 0
	for _, s := range sources {
		if strings.Contains(s, "@") {
			users++
			continue
		}
		out = append(out, s)
	}
	if users > 0 {
		out = append(out, fmt.Sprintf("%d user(s)", users))
	}
	return out
}

func (s *Server) loadOverview(ctx context.Context) (overview, error) {
	var tns tnv1.TailnetList
	var ins tnv1.TailnetIngressList
	var sites tnv1.TailnetSiteList
	if err := s.reader.List(ctx, &tns); err != nil {
		return overview{}, err
	}
	if err := s.reader.List(ctx, &ins); err != nil {
		return overview{}, err
	}
	if err := s.reader.List(ctx, &sites); err != nil {
		return overview{}, err
	}
	var o overview
	for i := range tns.Items {
		tn := &tns.Items[i]
		row := tailnetRow{Name: tn.Name, Server: tn.Spec.Server, Version: tn.Status.Version, Mode: policyMode(tn),
			Policy: policyState(tn.Status.Conditions)}
		if p := tn.Status.Policy; p != nil {
			row.Generated = fmt.Sprintf("%d tags, %d grants, %d routes", p.Generated.Tags, p.Generated.Grants, p.Generated.Routes)
		}
		o.Tailnets = append(o.Tailnets, row)
		for _, sp := range tn.Status.Spokes {
			o.Spokes = append(o.Spokes, spokeRow{Tailnet: tn.Name, Name: sp.Name,
				Reachable: condState(sp.Conditions, "SpokeReachable"), Valid: condState(sp.Conditions, "SpokeFragmentValid"),
				Approved: condState(sp.Conditions, "SpokeFragmentApproved"), Pending: sp.PendingHash != ""})
		}
	}
	for i := range ins.Items {
		in := &ins.Items[i]
		o.Ingresses = append(o.Ingresses, ingressRow{Namespace: in.Namespace, Name: in.Name, Tailnet: in.Spec.TailnetRef.Name,
			Tag: in.Status.Tag, Hosts: in.Status.Hosts, Ports: exposePorts(in), AllowFrom: maskUsers(in.Spec.AllowFrom),
			Ready: condState(in.Status.Conditions, "Ready")})
	}
	for i := range sites.Items {
		st := &sites.Items[i]
		row := siteRow{Tailnet: st.Spec.TailnetRef.Name, Name: st.Name, Owner: st.Spec.Owner, Description: st.Spec.Description,
			Ready: condState(st.Status.Conditions, "Ready")}
		for _, p := range st.Spec.Prefixes {
			row.Prefixes = append(row.Prefixes, string(p))
		}
		o.Sites = append(o.Sites, row)
	}
	for i := range tns.Items {
		tn := &tns.Items[i]
		var tIns []tnv1.TailnetIngress
		var tSites []tnv1.TailnetSite
		for _, in := range ins.Items {
			if in.Spec.TailnetRef.Name == tn.Name {
				tIns = append(tIns, in)
			}
		}
		for _, st := range sites.Items {
			if st.Spec.TailnetRef.Name == tn.Name {
				tSites = append(tSites, st)
			}
		}
		data, err := s.dir.get(ctx, tn.Name)
		o.Maps = append(o.Maps, buildMap(tn, tIns, tSites, data, err))
	}
	slices.SortFunc(o.Maps, func(a, b tailnetMap) int { return strings.Compare(a.Name, b.Name) })
	o.PollMS = s.poll.Milliseconds()
	slices.SortFunc(o.Tailnets, func(a, b tailnetRow) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(o.Spokes, func(a, b spokeRow) int { return strings.Compare(a.Tailnet+"/"+a.Name, b.Tailnet+"/"+b.Name) })
	slices.SortFunc(o.Ingresses, func(a, b ingressRow) int {
		return strings.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})
	slices.SortFunc(o.Sites, func(a, b siteRow) int { return strings.Compare(a.Tailnet+"/"+a.Name, b.Tailnet+"/"+b.Name) })
	return o, nil
}

func (s *Server) overviewPage(w http.ResponseWriter, r *http.Request, sess *session) {
	o, err := s.loadOverview(r.Context())
	if err != nil {
		s.log.Info("overview read failed")
		s.message(w, r, http.StatusServiceUnavailable, "Overview unavailable", "The console cannot read the cluster state right now.")
		return
	}
	s.render(w, http.StatusOK, "overview", page{Title: "Overview", Session: sess, Body: o})
}
