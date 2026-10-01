// projection observes a real kubelet volume as a non-root fixture process. It
// never starts tsnet, substitutes an agent, or treats file access as serving proof.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"tsunaro.io/tailnet-operator/internal/certificates"
)

type observation struct {
	UID                 int    `json:"uid"`
	CertificateReadable bool   `json:"certificateReadable"`
	KeyReadable         bool   `json:"keyReadable"`
	CertificateMode     uint32 `json:"certificateMode"`
	KeyMode             uint32 `json:"keyMode"`
	CertificateGroup    uint32 `json:"certificateGroup"`
	KeyGroup            uint32 `json:"keyGroup"`
	ProjectedSymlinks   bool   `json:"projectedSymlinks"`
	PublicCASHA256      string `json:"publicCASHA256"`
	LeafSHA256          string `json:"leafSHA256,omitempty"`
	PairValid           bool   `json:"pairValid"`
}

func main() {
	if run(os.Args[1:]) != nil {
		fmt.Fprintln(os.Stderr, "kind fixture: projection probe rejected")
		os.Exit(1)
	}
}
func run(args []string) error {
	f := flag.NewFlagSet("projection", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	marker := f.String("fixture", "", "")
	hold := f.Bool("hold", false, "")
	dns := f.String("dns", "", "")
	if f.Parse(args) != nil || f.NArg() != 0 || *marker != "p1.8-projection" || runtime.GOOS != "linux" || os.Geteuid() != 65532 {
		return os.ErrPermission
	}
	if *hold {
		if *dns != "" {
			return os.ErrInvalid
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		timer := time.NewTimer(10 * time.Minute)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			return nil
		}
	}
	if *dns != "rotation.fixture.invalid" {
		return os.ErrInvalid
	}
	o := observe("/tls", "/ca-certificates.crt", *dns, time.Now())
	return json.NewEncoder(os.Stdout).Encode(o)
}

func boundedRead(path string) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	return b, err == nil && len(b) <= 64<<10
}
func observe(dir, caPath, dns string, now time.Time) observation {
	o := observation{UID: os.Geteuid()}
	cert, certOK := boundedRead(dir + "/tls.crt")
	key, keyOK := boundedRead(dir + "/tls.key")
	o.CertificateReadable, o.KeyReadable = certOK, keyOK
	stat := func(p string) (uint32, uint32, bool) {
		i, err := os.Stat(p)
		if err != nil {
			return 0, 0, false
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, 0, false
		}
		l, err := os.Readlink(p)
		return uint32(i.Mode().Perm()), s.Gid, err == nil && strings.HasPrefix(l, "..data/")
	}
	var certLink, keyLink bool
	o.CertificateMode, o.CertificateGroup, certLink = stat(dir + "/tls.crt")
	o.KeyMode, o.KeyGroup, keyLink = stat(dir + "/tls.key")
	o.ProjectedSymlinks = certLink && keyLink
	if ca, ok := boundedRead(caPath); ok {
		sum := sha256.Sum256(ca)
		o.PublicCASHA256 = hex.EncodeToString(sum[:])
	}
	if certOK && keyOK {
		pair, err := certificates.ParseServingPair(cert, key, dns)
		if err == nil {
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err == nil {
				sum := sha256.Sum256(leaf.Raw)
				o.LeafSHA256 = hex.EncodeToString(sum[:])
				o.PairValid = !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
			}
		}
	}
	return o
}
