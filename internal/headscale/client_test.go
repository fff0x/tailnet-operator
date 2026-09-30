package headscale

import "testing"

func TestPrefixOf(t *testing.T) {
	for _, tt := range []struct{ name, input, want string }{
		{"legacy-key", "abcdefg.secret", "abcdefg"},
		{"legacy-display", "abcdefg***", "abcdefg"},
		{"bare", "abcdefg", "abcdefg"},
		{"modern-key", "hskey-api-ab-cd_12EFgh-private-value", "ab-cd_12EFgh"},
		{"modern-display", "hskey-api-ab-cd_12EFgh-***", "ab-cd_12EFgh"},
		{"modern-prefix", "hskey-api-ab-cd_12EFgh", "ab-cd_12EFgh"},
		{"short-modern", "hskey-api-secret", ""},
		{"invalid-separator", "hskey-api-ab-cd_12EFgh.secret", ""},
		{"invalid-prefix", "hskey-api-!b-cd_12EFgh-secret", ""},
		{"unknown-format", "future-format-private-token-value", ""},
		{"unknown-dotted", "future-private-token.secret-part", ""},
		{"invalid-legacy", "abc!efg.secret", ""},
		{"empty-legacy", ".secret", ""},
		{"invalid-bare", "invalid!char", ""},
		{"empty", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := PrefixOf(tt.input); got != tt.want {
				t.Fatal("unexpected API-key prefix")
			}
		})
	}
}
