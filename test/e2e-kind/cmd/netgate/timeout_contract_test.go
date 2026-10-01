//go:build linux

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"tsunaro.io/tailnet-operator/test/internal/netproof"
)

func TestTimeoutSnapshotRetainsApprovalContract(t *testing.T) {
	for _, mode := range []string{"valid", "epoch", "hash", "host-expired", "snapshot-expired", "await-expired", "await-epoch"} {
		t.Run(mode, func(t *testing.T) {
			s, v, _ := newStore(t)
			var raw bytes.Buffer
			capture := func(ctx context.Context) (netproof.Snapshot, error) {
				p, err := fakeCapture(ctx)
				p.Dials.IPv4 = netproof.TimedOut
				return p, err
			}
			if s.snapshot(context.Background(), testUID, clock, capture, &raw) != nil {
				t.Fatal("timeout snapshot rejected")
			}
			a := approved(v, raw.Bytes())
			a.HostProofExpiresAtMillis = testTime.Add(25 * time.Second).UnixMilli()
			now := clock
			switch mode {
			case "epoch":
				a.Epoch = strings.Repeat("b", 64)
			case "hash":
				a.SnapshotSHA256 = strings.Repeat("0", 64)
			case "host-expired":
				now = func() time.Time { return testTime.Add(25*time.Second + time.Millisecond) }
			case "snapshot-expired":
				now = func() time.Time { return testTime.Add(31 * time.Second) }
			}
			err := s.release(context.Background(), testUID, bytes.NewReader(encode(t, a)), now)
			if mode == "epoch" || mode == "hash" || mode == "host-expired" || mode == "snapshot-expired" {
				assertRejected(t, err)
				return
			}
			if err != nil {
				t.Fatal("fresh bound timeout approval rejected")
			}
			if mode == "await-expired" {
				now = func() time.Time { return testTime.Add(26 * time.Second) }
			}
			if mode == "await-epoch" {
				if _, err := s.initialize(context.Background(), testUID); err != nil {
					t.Fatal("replacement epoch unavailable")
				}
			}
			err = s.await(context.Background(), v, now)
			if mode != "valid" {
				assertRejected(t, err)
			} else if err != nil {
				t.Fatal("fresh timeout approval not consumed")
			}
		})
	}
}
