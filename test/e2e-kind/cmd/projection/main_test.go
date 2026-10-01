package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

func TestProjectionObservation(t *testing.T) {
	now := time.Now()
	ca, err := kindfixture.NewAuthority(now)
	if err != nil {
		t.Fatal("fixture PKI failed")
	}
	cert, key, hash, err := ca.Issue("rotation.fixture.invalid", now, now.Add(time.Minute))
	if err != nil {
		t.Fatal("leaf creation failed")
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "..version-one")
	if os.Mkdir(data, 0700) != nil {
		t.Fatal("fixture directory failed")
	}
	for name, b := range map[string][]byte{"tls.crt": cert, "tls.key": key} {
		// Kubelet sets the final mode explicitly; do not depend on the test
		// runner's umask (private evidence runners commonly use 0077).
		if os.WriteFile(filepath.Join(data, name), b, 0600) != nil || os.Chmod(filepath.Join(data, name), 0440) != nil || os.Symlink("..data/"+name, filepath.Join(dir, name)) != nil {
			t.Fatal("fixture projection failed")
		}
	}
	if os.Symlink("..version-one", filepath.Join(dir, "..data")) != nil || os.WriteFile(filepath.Join(dir, "ca.pem"), ca.PublicPEM(), 0600) != nil {
		t.Fatal("fixture paths failed")
	}
	o := observe(dir, filepath.Join(dir, "ca.pem"), "rotation.fixture.invalid", now)
	sum := sha256.Sum256(ca.PublicPEM())
	if !o.CertificateReadable || !o.KeyReadable || !o.ProjectedSymlinks || !o.PairValid || o.LeafSHA256 != hash || o.PublicCASHA256 != hex.EncodeToString(sum[:]) || o.CertificateMode != 0440 || o.KeyMode != 0440 {
		t.Fatal("valid projected material not observed")
	}
	if observe(dir, filepath.Join(dir, "ca.pem"), "rotation.fixture.invalid", now.Add(2*time.Minute)).PairValid {
		t.Fatal("expiry ignored")
	}
	if os.Remove(filepath.Join(data, "tls.key")) != nil {
		t.Fatal("fixture removal failed")
	}
	o = observe(dir, filepath.Join(dir, "ca.pem"), "rotation.fixture.invalid", now)
	if o.KeyReadable || o.PairValid {
		t.Fatal("missing key accepted")
	}
}

func TestProjectionHostGuard(t *testing.T) {
	if run(nil) == nil || run([]string{"--fixture=wrong", "--dns=rotation.fixture.invalid"}) == nil {
		t.Fatal("unguarded probe accepted")
	}
}
