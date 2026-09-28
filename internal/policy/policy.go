// Package policy renders the control-server policy the operator owns: a human-written HuJSON base
// plus what the CRs imply. Everything generated is additive — base entries are never changed or
// removed, a base tagOwners key always wins — so a bug here can at worst over-grant, never lock the
// humans out. The base is parsed generically (map[string]any); blocks the operator does not know
// (ssh, tests, nodeAttrs, randomizeClientPort, …) pass through untouched.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"

	"github.com/tailscale/hujson"
)

var (
	// ErrBaseInvalid: the base document is not HuJSON or not an object.
	ErrBaseInvalid = errors.New("base policy invalid")
	// ErrEmpty: the base has no tagOwners or neither acls nor grants — applying it would lock
	// everyone out, so the operator refuses to render.
	ErrEmpty = errors.New("base policy empty: needs tagOwners and at least one acl or grant")
)

// Target is one egress destination the tag may reach.
type Target struct {
	CIDR string // host route, e.g. 10.0.10.20/32
	Port int32
}

// Egress is one TailnetEgress as seen by the policy: its tag and TCP targets.
type Egress struct {
	Tag     string
	Targets []Target
}

// Ingress is one TailnetIngress: its tag, who may reach it and the ports it listens on.
type Ingress struct {
	Tag       string
	AllowFrom []string
	Ports     []int32
}

// Inputs is everything Render needs besides the base document.
type Inputs struct {
	TagOwners              []string
	RouteApprovers         []string
	IngressSourceAllowlist []string
	Egresses               []Egress
	Ingresses              []Ingress
}

// Summary counts what was added and which ingress tags were denied a grant.
type Summary struct {
	Tags, Grants, Routes int
	Denied               []string
}

// Allowed reports whether src matches one of the glob patterns (path.Match syntax, e.g. "group:*").
// An empty allowlist allows nothing.
func Allowed(src string, allowlist []string) bool {
	for _, p := range allowlist {
		if ok, _ := path.Match(p, src); ok {
			return true
		}
	}
	return false
}

// Render returns the base with the generated tagOwners, autoApprovers.routes and grants appended,
// as indented JSON (comments of the base are not carried over; they live in Git).
func Render(base []byte, in Inputs) ([]byte, Summary, error) {
	var sum Summary
	doc, err := parse(base)
	if err != nil {
		return nil, sum, err
	}
	owners, ok := doc["tagOwners"].(map[string]any)
	if !ok || (len(arr(doc["acls"])) == 0 && len(arr(doc["grants"])) == 0) {
		return nil, sum, ErrEmpty
	}

	// tagOwners: declare every CR tag the base does not already own.
	tags := make([]string, 0, len(in.Egresses)+len(in.Ingresses))
	for _, e := range in.Egresses {
		tags = append(tags, e.Tag)
	}
	for _, i := range in.Ingresses {
		tags = append(tags, i.Tag)
	}
	sort.Strings(tags)
	for _, t := range tags {
		if _, exists := owners[t]; !exists {
			owners[t] = toAny(in.TagOwners)
			sum.Tags++
		}
	}

	// autoApprovers.routes: every egress target /32 may be auto-approved on the routers.
	aa, _ := doc["autoApprovers"].(map[string]any)
	if aa == nil {
		aa = map[string]any{}
		doc["autoApprovers"] = aa
	}
	routes, _ := aa["routes"].(map[string]any)
	if routes == nil {
		routes = map[string]any{}
		aa["routes"] = routes
	}
	for _, e := range in.Egresses {
		for _, t := range e.Targets {
			cur := strs(routes[t.CIDR])
			merged, added := union(cur, in.RouteApprovers)
			if added {
				routes[t.CIDR] = toAny(merged)
				sum.Routes++
			}
		}
	}

	// grants: one per (egress, port) and one per ingress; identical rules are not duplicated.
	grants := arr(doc["grants"])
	seen := map[string]bool{}
	for _, g := range grants {
		seen[canon(g)] = true
	}
	add := func(g map[string]any) {
		if k := canon(g); !seen[k] {
			seen[k] = true
			grants = append(grants, g)
			sum.Grants++
		}
	}
	for _, e := range in.Egresses {
		byPort := map[int32][]string{}
		for _, t := range e.Targets {
			byPort[t.Port] = append(byPort[t.Port], t.CIDR)
		}
		ports := make([]int, 0, len(byPort))
		for p := range byPort {
			ports = append(ports, int(p))
		}
		sort.Ints(ports)
		for _, p := range ports {
			dst := dedupe(byPort[int32(p)])
			add(map[string]any{"src": []any{e.Tag}, "dst": toAny(dst), "ip": []any{fmt.Sprintf("tcp:%d", p)}})
		}
	}
	for _, i := range in.Ingresses {
		if len(i.AllowFrom) == 0 || len(i.Ports) == 0 {
			continue
		}
		denied := false
		for _, s := range i.AllowFrom {
			if !Allowed(s, in.IngressSourceAllowlist) {
				denied = true
				break
			}
		}
		if denied {
			sum.Denied = append(sum.Denied, i.Tag)
			continue
		}
		ports := make([]int, 0, len(i.Ports))
		for _, p := range i.Ports {
			ports = append(ports, int(p))
		}
		sort.Ints(ports)
		ip := make([]any, 0, len(ports))
		for _, p := range dedupeInts(ports) {
			ip = append(ip, fmt.Sprintf("tcp:%d", p))
		}
		add(map[string]any{"src": toAny(dedupe(i.AllowFrom)), "dst": []any{i.Tag}, "ip": ip})
	}
	doc["grants"] = grants

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, sum, err
	}
	return append(out, '\n'), sum, nil
}

// Normalize returns the canonical compact JSON of a HuJSON document, so a policy read back from the
// server compares equal to the one rendered regardless of whitespace, comments or key order.
func Normalize(doc []byte) (string, error) {
	m, err := parse(doc)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Hash is the sha256 hex of a canonical document.
func Hash(canonical string) string {
	h := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(h[:])
}

// Approvers returns autoApprovers.routes of a policy document: prefix → aliases allowed to
// advertise it. Missing block → empty map.
func Approvers(doc []byte) (map[string][]string, error) {
	m, err := parse(doc)
	if err != nil {
		return nil, err
	}
	aa, _ := m["autoApprovers"].(map[string]any)
	routes, _ := aa["routes"].(map[string]any)
	out := make(map[string][]string, len(routes))
	for cidr, v := range routes {
		out[cidr] = strs(v)
	}
	return out, nil
}

func parse(doc []byte) (map[string]any, error) {
	std, err := hujson.Standardize(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBaseInvalid, err)
	}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, fmt.Errorf("%w: not a JSON object", ErrBaseInvalid)
	}
	return m, nil
}

func arr(v any) []any { a, _ := v.([]any); return a }

func strs(v any) []string {
	var out []string
	for _, x := range arr(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func union(cur, add []string) ([]string, bool) {
	have := map[string]bool{}
	for _, s := range cur {
		have[s] = true
	}
	added := false
	for _, s := range add {
		if !have[s] {
			cur = append(cur, s)
			have[s] = true
			added = true
		}
	}
	return cur, added
}

func dedupe(ss []string) []string {
	out, _ := union(nil, ss)
	sort.Strings(out)
	return out
}

func dedupeInts(is []int) []int {
	var out []int
	for i, v := range is {
		if i == 0 || v != is[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// canon is the compact JSON of a grant, the identity used for de-duplication.
func canon(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
