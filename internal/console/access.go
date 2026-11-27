package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
	"tsunaro.io/tailnet-operator/internal/policy"
)

// target is one destination as written in the rule, with the name of a known ingress or site.
// A masked target stands for a user destination and is prose, not a policy value.
type target struct {
	Value, Name string
	Masked      bool
}

type accessRow struct {
	Targets []target
	Ports   []string
	Via     []string // what in src matched: "you", a group, autogroup:member or *
	Origin  string
	Expires string
}

type accessSection struct {
	Tailnet  string
	Problem  bool // the operator could not provide users or policy
	Unknown  bool // no Headscale user has this sign-in's provider identifier
	Personal []accessRow
	Everyone []accessRow
}

type liveRule struct {
	src, dst, ports []string
	grant           bool
}

// tailnetObjects are the Kubernetes objects of one Tailnet that name targets and origins.
type tailnetObjects struct {
	ingresses []tnv1.TailnetIngress
	sites     []tnv1.TailnetSite
	grants    []tnv1.TailnetGrant
}

// userRef applies Headscale's rule: a user reference has an "@", appended when the value has none.
func userRef(v string) string {
	if v == "" || strings.Contains(v, "@") {
		return v
	}
	return v + "@"
}

// providerID builds the identifier exactly as Headscale does (hscontrol/types at v0.29.6,
// OIDCClaims.Identifier and CleanIdentifier): issuer and subject joined by one "/", empty path
// segments dropped, the scheme lowered and the URL encoded again, so "auth0|x" becomes "auth0%7Cx".
// Unlike Headscale, an empty issuer or subject gives "", which names nobody.
func providerID(issuer, subject string) string {
	if issuer == "" || subject == "" {
		return ""
	}
	segments := func(p string) string {
		parts := strings.FieldsFunc(p, func(c rune) bool { return c == '/' })
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return strings.Join(slices.DeleteFunc(parts, func(p string) bool { return p == "" }), "/")
	}
	id := strings.TrimSpace(strings.TrimSuffix(issuer, "/") + "/" + strings.TrimPrefix(subject, "/"))
	u, err := url.Parse(id)
	if err != nil || u.Scheme == "" {
		return segments(id)
	}
	if u.Path = segments(u.Path); u.Path != "" {
		u.Path = "/" + u.Path
	}
	u.Scheme = strings.ToLower(u.Scheme)
	return u.String()
}

// parseLive reads the grants and the accepting ACLs of a live policy. Grants without "ip" (app
// capabilities only) grant no network access and are skipped; "via" and SSH rules are not shown.
// An ACL gives one rule per distinct port set, with exactly the destinations that carry it.
func parseLive(doc string) (map[string][]string, []liveRule, error) {
	if strings.TrimSpace(doc) == "" {
		return nil, nil, nil
	}
	canonical, err := policy.Normalize([]byte(doc))
	if err != nil {
		return nil, nil, err
	}
	var p struct {
		Groups map[string][]string `json:"groups"`
		Grants []struct {
			Src []string `json:"src"`
			Dst []string `json:"dst"`
			IP  []string `json:"ip"`
		} `json:"grants"`
		ACLs []struct {
			Action string   `json:"action"`
			Proto  string   `json:"proto"`
			Src    []string `json:"src"`
			Dst    []string `json:"dst"`
		} `json:"acls"`
	}
	if err := json.Unmarshal([]byte(canonical), &p); err != nil {
		return nil, nil, err
	}
	var rules []liveRule
	for _, g := range p.Grants {
		if len(g.IP) > 0 {
			rules = append(rules, liveRule{src: g.Src, dst: g.Dst, ports: g.IP, grant: true})
		}
	}
	for _, a := range p.ACLs {
		if a.Action != "accept" {
			continue
		}
		var hosts []string
		ports := map[string][]string{}
		for _, d := range a.Dst {
			// An ACL destination is host:ports; the host itself may contain ":" (tag:x, IPv6).
			i := strings.LastIndex(d, ":")
			host, list := d, "*"
			if i > 0 {
				host, list = d[:i], d[i+1:]
			}
			if _, ok := ports[host]; !ok {
				hosts = append(hosts, host)
			}
			for _, p := range strings.Split(list, ",") {
				if a.Proto != "" {
					p = a.Proto + ":" + p
				}
				if !slices.Contains(ports[host], p) {
					ports[host] = append(ports[host], p)
				}
			}
		}
		first := len(rules)
		for _, h := range hosts {
			i := slices.IndexFunc(rules[first:], func(r liveRule) bool { return sameSet(r.ports, ports[h]) })
			if i < 0 {
				rules = append(rules, liveRule{src: a.Src, ports: ports[h]})
				i = len(rules) - 1 - first
			}
			rules[first+i].dst = append(rules[first+i].dst, h)
		}
	}
	return p.Groups, rules, nil
}

// evaluate sorts the live rules of one Tailnet into the two lists of "My access":
//  1. The person is the Headscale user whose providerId is the one Headscale builds from the
//     issuer and the subject (providerID). Without one, both lists stay empty.
//  2. A reference means the person when it equals the user's e-mail, name or providerId, each
//     with "@" appended when it has none. Empty fields never match.
//  3. The person's policy groups are the groups that list such a reference.
//  4. All grants and all accepting ACLs of the live policy count.
//  5. Personal: src names the person or one of their groups. For everyone: src names
//     autogroup:member or * and the rule is not personal.
//  6. Tags, hosts, addresses, autogroup:tagged and autogroup:danger-all mean devices, not people.
func evaluate(sec *accessSection, data tailnetData, issuer, subject string, objs tailnetObjects, now time.Time) error {
	groups, rules, err := parseLive(data.Policy)
	if err != nil {
		// A parser error may quote the policy, and the policy names people.
		return errors.New("live policy unreadable")
	}
	var me *headscale.User
	want := providerID(issuer, subject)
	for i := range data.Users {
		if want != "" && data.Users[i].ProviderID == want {
			me = &data.Users[i]
			break
		}
	}
	if me == nil {
		sec.Unknown = true
		return nil
	}
	refs := map[string]bool{}
	for _, v := range []string{me.Email, me.Name, me.ProviderID} {
		if v != "" {
			refs[userRef(v)] = true
		}
	}
	mine := map[string]bool{}
	for name, members := range groups {
		if slices.ContainsFunc(members, func(m string) bool { return refs[m] }) {
			mine[name] = true
		}
	}
	for _, r := range rules {
		var personal, everyone []string
		for _, s := range r.src {
			switch {
			case refs[s]:
				if !slices.Contains(personal, "you") {
					personal = append(personal, "you")
				}
			case mine[s]:
				personal = append(personal, s)
			case s == "autogroup:member" || s == "*":
				everyone = append(everyone, s)
			}
		}
		if len(personal) == 0 && len(everyone) == 0 {
			continue
		}
		row := accessRow{Ports: r.ports, Origin: "Policy"}
		for _, d := range r.dst {
			row.Targets = append(row.Targets, describe(d, refs, objs))
		}
		if r.grant {
			row.Origin, row.Expires = origin(r, objs, now)
		}
		if len(personal) > 0 {
			row.Via = personal
			sec.Personal = append(sec.Personal, row)
		} else {
			row.Via = everyone
			sec.Everyone = append(sec.Everyone, row)
		}
	}
	return nil
}

// describe never shows another person's reference: a user destination is masked.
func describe(d string, refs map[string]bool, objs tailnetObjects) target {
	switch {
	case refs[d]:
		return target{Value: "your devices", Masked: true}
	case strings.Contains(d, "@"):
		return target{Value: "a user's devices", Masked: true}
	}
	t := target{Value: d}
	for _, in := range objs.ingresses {
		if in.Status.Tag == d {
			t.Name = "ingress " + in.Namespace + "/" + in.Name
			if len(in.Status.Hosts) > 0 {
				t.Name += " (" + strings.Join(in.Status.Hosts, ", ") + ")"
			}
			return t
		}
	}
	for _, s := range objs.sites {
		for _, p := range s.Spec.Prefixes {
			if string(p) == d {
				t.Name = "site " + s.Name
				return t
			}
		}
	}
	return t
}

// origin matches a live grant against the CRs that render grants. ponytail: a comparison, not
// provenance; a base-policy rule identical to a CR's is attributed to the CR. Exact origins need the
// renderer to record them. Equal sources are tried before a shortened source list, so of two CRs
// with the same target and ports the one that wrote the rule is named.
func origin(r liveRule, objs tailnetObjects, now time.Time) (string, string) {
	for _, sources := range []func(live, spec []string) bool{sameSet, subset} {
		for _, g := range objs.grants {
			if !meta.IsStatusConditionTrue(g.Status.Conditions, "Ready") {
				continue
			}
			dst := []string{g.Spec.Target.Tag}
			if g.Spec.Target.Tag == "" {
				dst = dst[:0]
				for _, p := range g.Spec.Target.Prefixes {
					dst = append(dst, string(p))
				}
			}
			if sameSet(r.dst, dst) && sameSet(r.ports, tcpPorts(g.Spec.Ports)) && sources(r.src, g.Spec.Sources) {
				expires := ""
				if g.Spec.ExpiresAt != nil {
					expires = remaining(g.Spec.ExpiresAt.Sub(now)) + " (" + g.Spec.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC") + ")"
				}
				return "TailnetGrant " + g.Name, expires
			}
		}
		for _, in := range objs.ingresses {
			var ports []int32
			for _, e := range in.Spec.Exposes {
				ports = append(ports, e.Port)
			}
			if in.Status.Tag != "" && sameSet(r.dst, []string{in.Status.Tag}) && sameSet(r.ports, tcpPorts(ports)) && sources(r.src, in.Spec.AllowFrom) {
				return "TailnetIngress " + in.Namespace + "/" + in.Name, ""
			}
		}
	}
	return "Policy", ""
}

func tcpPorts(ports []int32) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, fmt.Sprintf("tcp:%d", p))
	}
	return out
}

func sameSet(a, b []string) bool { return subset(a, b) && subset(b, a) }

func subset(a, b []string) bool {
	for _, v := range a {
		if !slices.Contains(b, v) {
			return false
		}
	}
	return true
}

func remaining(d time.Duration) string {
	switch {
	case d <= 0:
		return "expired"
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d/(24*time.Hour)))
	case d >= time.Hour:
		return fmt.Sprintf("%dh %02dm", int(d/time.Hour), int(d%time.Hour/time.Minute))
	}
	return fmt.Sprintf("%dm", int((d+time.Minute-1)/time.Minute))
}

func (s *Server) loadAccess(ctx context.Context, sess *session) ([]accessSection, error) {
	var tns tnv1.TailnetList
	var ins tnv1.TailnetIngressList
	var sites tnv1.TailnetSiteList
	var grants tnv1.TailnetGrantList
	if err := s.reader.List(ctx, &tns); err != nil {
		return nil, err
	}
	if err := s.reader.List(ctx, &ins); err != nil {
		return nil, err
	}
	if err := s.reader.List(ctx, &sites); err != nil {
		return nil, err
	}
	if err := s.reader.List(ctx, &grants); err != nil {
		return nil, err
	}
	// The cache lists in no fixed order; a tie between two CRs must not change between requests.
	slices.SortFunc(grants.Items, func(a, b tnv1.TailnetGrant) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(ins.Items, func(a, b tnv1.TailnetIngress) int {
		return strings.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})
	var out []accessSection
	for _, tn := range tns.Items {
		var objs tailnetObjects
		for _, in := range ins.Items {
			if in.Spec.TailnetRef.Name == tn.Name {
				objs.ingresses = append(objs.ingresses, in)
			}
		}
		for _, st := range sites.Items {
			if st.Spec.TailnetRef.Name == tn.Name {
				objs.sites = append(objs.sites, st)
			}
		}
		for _, g := range grants.Items {
			if g.Spec.TailnetRef.Name == tn.Name {
				objs.grants = append(objs.grants, g)
			}
		}
		sec := accessSection{Tailnet: tn.Name}
		data, err := s.dir.get(ctx, tn.Name)
		if err == nil {
			err = evaluate(&sec, data, sess.Issuer, sess.Subject, objs, time.Now())
		}
		if err != nil {
			s.log.Info("access read failed", "tailnet", tn.Name, "error", err.Error())
			sec = accessSection{Tailnet: tn.Name, Problem: true}
		}
		out = append(out, sec)
	}
	slices.SortFunc(out, func(a, b accessSection) int { return strings.Compare(a.Tailnet, b.Tailnet) })
	return out, nil
}

func (s *Server) accessPage(w http.ResponseWriter, r *http.Request, sess *session) {
	secs, err := s.loadAccess(r.Context(), sess)
	if err != nil {
		s.log.Info("access read failed")
		s.message(w, r, http.StatusServiceUnavailable, "Access unavailable", "The console cannot read the cluster state right now.")
		return
	}
	s.render(w, http.StatusOK, "access", page{Title: "My access", Session: sess, Body: secs})
}
