package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	proof "tsunaro.io/tailnet-operator/test/internal/gatewayprobe"
)

func dnsResponse(id uint16) dnsmessage.Message {
	name := dnsmessage.MustNewName(proof.DNSName)
	return dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true, Authoritative: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers:   []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{198, 51, 100, 8}}}},
		// CoreDNS 1.14.6 file.Lookup includes the rendered apex NS even on A success.
		Authorities: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("tail.example."), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.NSResource{NS: dnsmessage.MustNewName("tail.example.")}}},
	}
}

func TestDNSParser(t *testing.T) {
	m := dnsResponse(123)
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if parseDNS(b, 123) != nil {
		t.Fatal("valid DNS response")
	}
	compressed := dnsmessage.NewBuilder(nil, m.Header)
	compressed.EnableCompression()
	if compressed.StartQuestions() != nil || compressed.Question(m.Questions[0]) != nil || compressed.StartAnswers() != nil ||
		compressed.AResource(m.Answers[0].Header, *m.Answers[0].Body.(*dnsmessage.AResource)) != nil || compressed.StartAuthorities() != nil ||
		compressed.NSResource(m.Authorities[0].Header, *m.Authorities[0].Body.(*dnsmessage.NSResource)) != nil {
		t.Fatal("build compressed DNS fixture")
	}
	wire, err := compressed.Finish()
	if err != nil || parseDNS(wire, 123) != nil {
		t.Fatal("compressed A/NS response rejected")
	}
	if parseDNS(b, 124) == nil {
		t.Fatal("wrong transaction ID")
	}
	if parseDNS(append(b, 0), 123) == nil {
		t.Fatal("trailing bytes")
	}
	reserved := append([]byte{}, b...)
	reserved[3] |= 0x40
	if parseDNS(reserved, 123) == nil {
		t.Fatal("reserved header bit")
	}
	padded := append(append([]byte{}, b...), 0)
	answerOffset := skipWireName(padded, skipWireName(padded, 12)+4)
	binary.BigEndian.PutUint16(padded[answerOffset+8:answerOffset+10], 5)
	if parseDNS(padded, 123) == nil {
		t.Fatal("padded A resource")
	}
	for n := 0; n < len(b); n++ {
		if parseDNS(b[:n], 123) == nil {
			t.Fatal("truncation", n)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*dnsmessage.Message)
	}{
		{"request", func(m *dnsmessage.Message) { m.Response = false }},
		{"not authoritative", func(m *dnsmessage.Message) { m.Authoritative = false }},
		{"truncated", func(m *dnsmessage.Message) { m.Truncated = true }},
		{"rcode", func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeNameError }},
		{"opcode", func(m *dnsmessage.Message) { m.OpCode = 1 }},
		{"recursive", func(m *dnsmessage.Message) { m.RecursionDesired = true }},
		{"question name", func(m *dnsmessage.Message) { m.Questions[0].Name = dnsmessage.MustNewName("other.example.") }},
		{"question type", func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeAAAA }},
		{"question class", func(m *dnsmessage.Message) { m.Questions[0].Class = dnsmessage.ClassCHAOS }},
		{"answer name", func(m *dnsmessage.Message) { m.Answers[0].Header.Name = dnsmessage.MustNewName("other.example.") }},
		{"answer class", func(m *dnsmessage.Message) { m.Answers[0].Header.Class = dnsmessage.ClassCHAOS }},
		{"answer address", func(m *dnsmessage.Message) { m.Answers[0].Body = &dnsmessage.AResource{A: [4]byte{198, 51, 100, 9}} }},
		{"cname", func(m *dnsmessage.Message) {
			m.Answers[0].Header.Type = dnsmessage.TypeCNAME
			m.Answers[0].Body = &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("other.example.")}
		}},
		{"referral", func(m *dnsmessage.Message) { m.Authorities = m.Answers }},
		{"missing NS", func(m *dnsmessage.Message) { m.Authorities = nil }},
		{"foreign NS owner", func(m *dnsmessage.Message) { m.Authorities[0].Header.Name = dnsmessage.MustNewName("foreign.example.") }},
		{"foreign NS target", func(m *dnsmessage.Message) {
			m.Authorities[0].Body = &dnsmessage.NSResource{NS: dnsmessage.MustNewName("foreign.example.")}
		}},
		{"NS class", func(m *dnsmessage.Message) { m.Authorities[0].Header.Class = dnsmessage.ClassCHAOS }},
		{"additional", func(m *dnsmessage.Message) { m.Additionals = m.Answers }},
		{"multiple answers", func(m *dnsmessage.Message) { m.Answers = append(m.Answers, m.Answers[0]) }},
		{"multiple questions", func(m *dnsmessage.Message) { m.Questions = append(m.Questions, m.Questions[0]) }},
		{"no answer", func(m *dnsmessage.Message) { m.Answers = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := dnsResponse(123)
			tc.mutate(&m)
			b, err := m.Pack()
			if err != nil {
				t.Fatal(err)
			}
			if parseDNS(b, 123) == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestDNSQueryAndFreshOverlayDial(t *testing.T) {
	for _, mode := range []string{"dns-udp", "dns-tcp"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			done := make(chan struct{}, 2)
			d := probeDeps{
				native: func(context.Context, string, string) (net.Conn, error) {
					t.Error("native fallback")
					return nil, errRejected
				},
				prefs:  func(context.Context) (*ipn.Prefs, error) { return &ipn.Prefs{RouteAll: true}, nil },
				status: func(context.Context) (*ipnstate.Status, error) { return selectedStatus("100.64.0.2/32"), nil },
				overlay: func(ctx context.Context, network, address string) (net.Conn, error) {
					calls++
					if address != "100.64.0.2:53" || (mode == "dns-udp" && network != "udp") || (mode == "dns-tcp" && network != "tcp") {
						t.Fatal(network, address)
					}
					client, server := net.Pipe()
					go func() {
						defer func() { _ = server.Close(); done <- struct{}{} }()
						_ = server.SetDeadline(time.Now().Add(time.Second))
						var query []byte
						if network == "tcp" {
							var prefix [2]byte
							if _, err := io.ReadFull(server, prefix[:]); err != nil {
								t.Error(err)
								return
							}
							query = make([]byte, int(binary.BigEndian.Uint16(prefix[:])))
							if _, err := io.ReadFull(server, query); err != nil {
								t.Error(err)
								return
							}
						} else {
							query = make([]byte, 512)
							n, err := server.Read(query)
							if err != nil {
								t.Error(err)
								return
							}
							query = query[:n]
						}
						var q dnsmessage.Message
						if q.Unpack(query) != nil || q.RecursionDesired || q.Response || len(q.Questions) != 1 || q.Questions[0].Name.String() != proof.DNSName || q.Questions[0].Type != dnsmessage.TypeA || q.Questions[0].Class != dnsmessage.ClassINET {
							t.Error("unexpected query")
							return
						}
						response := dnsResponse(q.ID)
						data, err := response.Pack()
						if err != nil {
							t.Error(err)
							return
						}
						if network == "tcp" {
							frame := make([]byte, 2)
							binary.BigEndian.PutUint16(frame, uint16(len(data)))
							data = append(frame, data...)
						}
						if writeFull(server, data) != nil {
							t.Error("write response")
						}
					}()
					return client, nil
				},
			}
			for range 2 {
				r := probe(context.Background(), testConfig, mode, d)
				requireValidResult(t, r)
				if !r.Connected || !r.DNSVerified || r.AnswerIPv4 != proof.DNSAnswer || r.RouteSelected || r.TargetVerified || r.Error != "" {
					t.Fatal(r)
				}
				<-done
			}
			if calls != 2 {
				t.Fatal("cached DNS")
			}
			d.status = func(context.Context) (*ipnstate.Status, error) { return selectedStatus(), nil }
			r := probe(context.Background(), testConfig, mode, d)
			if r.Error != proof.ErrorNoRoute || calls != 2 {
				t.Fatal("missing peer dialed", r)
			}
		})
	}
}

func TestDNSBadTCPFraming(t *testing.T) {
	for _, frame := range [][]byte{{0, 0}, {0, 11}, {2, 1}, {0}, {0, 12, 0}} {
		client, server := net.Pipe()
		_ = client.SetDeadline(time.Now().Add(time.Second))
		query, id, err := dnsQuery()
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(time.Second))
			request := make([]byte, len(query)+2)
			_, _ = io.ReadFull(server, request)
			_ = writeFull(server, frame)
		}()
		if exchangeDNS(client, "tcp", query, id) == "" {
			t.Fatal("bad frame accepted")
		}
		_ = client.Close()
		<-done
	}
}
