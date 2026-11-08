package policy

import (
	"reflect"
	"testing"
)

func TestMissingFromLive(t *testing.T) {
	fragment := []byte(`{
		"tagOwners": {"tag:ingress-web": ["tag:operator"], "tag:egress-db": ["tag:operator"]},
		"autoApprovers": {"routes": {"10.0.0.0/8": ["tag:gateway", "tag:edge"]}},
		"grants": [
			{"src": ["group:dev"], "dst": ["tag:ingress-web"], "ip": ["tcp:443"]},
			{"src": ["tag:egress-db"], "dst": ["10.0.0.5/32"], "ip": ["tcp:5432"]}
		]
	}`)
	for name, tc := range map[string]struct {
		live []byte
		want []string
	}{
		"all merged": {
			live: []byte(`{
				"tagOwners": {"tag:operator": ["group:ops"], "tag:ingress-web": ["tag:operator"], "tag:egress-db": ["tag:operator"]},
				"autoApprovers": {"routes": {"10.0.0.0/8": ["tag:edge", "tag:gateway", "tag:other"]}},
				"grants": [
					{"src": ["*"], "dst": ["*"], "ip": ["*"]},
					{"src": ["tag:egress-db"], "dst": ["10.0.0.5/32"], "ip": ["tcp:5432"]},
					{"src": ["group:dev"], "dst": ["tag:ingress-web"], "ip": ["tcp:443"]}
				]
			}`),
		},
		"nothing merged": {
			live: []byte(`{"tagOwners": {"tag:operator": ["group:ops"]}, "grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`),
			want: []string{"tag:egress-db", "tag:ingress-web", "route 10.0.0.0/8 → tag:gateway", "route 10.0.0.0/8 → tag:edge",
				"grant group:dev → tag:ingress-web", "grant tag:egress-db → 10.0.0.5/32"},
		},
		"one approver and one grant missing": {
			live: []byte(`{
				"tagOwners": {"tag:ingress-web": ["tag:operator"], "tag:egress-db": ["tag:operator"]},
				"autoApprovers": {"routes": {"10.0.0.0/8": ["tag:gateway"]}},
				"grants": [{"src": ["group:dev"], "dst": ["tag:ingress-web"], "ip": ["tcp:443"]}]
			}`),
			want: []string{"route 10.0.0.0/8 → tag:edge", "grant tag:egress-db → 10.0.0.5/32"},
		},
		"grant differs only in ports": {
			live: []byte(`{
				"tagOwners": {"tag:ingress-web": ["tag:operator"], "tag:egress-db": ["tag:operator"]},
				"autoApprovers": {"routes": {"10.0.0.0/8": ["tag:gateway", "tag:edge"]}},
				"grants": [
					{"src": ["group:dev"], "dst": ["tag:ingress-web"], "ip": ["tcp:8443"]},
					{"src": ["tag:egress-db"], "dst": ["10.0.0.5/32"], "ip": ["tcp:5432"]}
				]
			}`),
			want: []string{"grant group:dev → tag:ingress-web"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := MissingFromLive(tc.live, fragment)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("missing = %q, want %q", got, tc.want)
			}
		})
	}
	if got, err := MissingFromLive([]byte(`{"tagOwners": {}}`), []byte(`{}`)); err != nil || len(got) != 0 {
		t.Fatalf("empty fragment: %q %v", got, err)
	}
	if _, err := MissingFromLive([]byte(`{`), fragment); err == nil {
		t.Fatal("unparsable live policy must error, not report everything merged")
	}
}
