package v1alpha1

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestImagePullSecretsRoundTripAndDeepCopy(t *testing.T) {
	for _, tt := range []struct {
		name string
		raw  string
		want *[]string
	}{
		{name: "omitted", raw: `{}`},
		{name: "empty", raw: `{"imagePullSecrets":[]}`, want: slicePointer([]string{})},
		{name: "override", raw: `{"imagePullSecrets":["registry","second"]}`, want: slicePointer([]string{"registry", "second"})},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tn := &Tailnet{}
			if err := json.Unmarshal([]byte(tt.raw), &tn.Spec.Proxy); err != nil {
				t.Fatal(err)
			}
			copy := tn.DeepCopy()
			listCopy := (&TailnetList{Items: []Tailnet{*tn}}).DeepCopy()
			data, err := json.Marshal(tn)
			if err != nil {
				t.Fatal(err)
			}
			var roundTrip Tailnet
			if err := json.Unmarshal(data, &roundTrip); err != nil {
				t.Fatal(err)
			}
			for name, got := range map[string]*Tailnet{"deepcopy": copy, "list-deepcopy": &listCopy.Items[0], "json": &roundTrip} {
				if !reflect.DeepEqual(got.Spec.Proxy.ImagePullSecrets, tt.want) {
					t.Fatalf("%s lost omitted/empty/override state: got %v, want %v", name, got.Spec.Proxy.ImagePullSecrets, tt.want)
				}
				if tt.want != nil {
					if got.Spec.Proxy.ImagePullSecrets == tn.Spec.Proxy.ImagePullSecrets {
						t.Fatalf("%s shares slice pointer", name)
					}
					if len(*got.Spec.Proxy.ImagePullSecrets) > 0 {
						(*got.Spec.Proxy.ImagePullSecrets)[0] = "changed"
					}
					*got.Spec.Proxy.ImagePullSecrets = append(*got.Spec.Proxy.ImagePullSecrets, "appended")
					if !reflect.DeepEqual(tn.Spec.Proxy.ImagePullSecrets, tt.want) {
						t.Fatalf("%s mutation changed source", name)
					}
				}
			}
			var fields map[string]json.RawMessage
			proxyJSON, err := json.Marshal(tn.Spec.Proxy)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(proxyJSON, &fields); err != nil {
				t.Fatal(err)
			}
			value, exists := fields["imagePullSecrets"]
			if exists != (tt.want != nil) || (tt.name == "empty" && string(value) != "[]") {
				t.Fatalf("JSON did not preserve presence: %s", proxyJSON)
			}
		})
	}
}

func slicePointer(names []string) *[]string { return &names }
