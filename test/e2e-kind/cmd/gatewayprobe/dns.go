package main

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"

	"golang.org/x/net/dns/dnsmessage"
	proof "tsunaro.io/tailnet-operator/test/internal/gatewayprobe"
)

const maxDNSBytes = 512

func dnsQuery() ([]byte, uint16, error) {
	var nonce [2]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, 0, errRejected
	}
	id := binary.BigEndian.Uint16(nonce[:])
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id}, // No recursive resolver or host lookup.
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(proof.DNSName), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	b, err := m.Pack()
	if err != nil {
		return nil, 0, errRejected
	}
	return b, id, nil
}

// skipWireName measures encoded size only; dnsmessage validates pointer targets,
// label contents, cycles and expanded names before this function is used.
func skipWireName(b []byte, offset int) int {
	for offset < len(b) {
		n := int(b[offset])
		offset++
		if n == 0 {
			return offset
		}
		if n&0xc0 == 0xc0 {
			if offset < len(b) {
				return offset + 1
			}
			return -1
		}
		if n > 63 || offset+n > len(b) {
			return -1
		}
		offset += n
	}
	return -1
}

func parseDNS(b []byte, id uint16) error {
	if len(b) < 12 || len(b) > maxDNSBytes || b[3]&0x40 != 0 {
		return errRejected
	}
	var m dnsmessage.Message
	if m.Unpack(b) != nil || m.ID != id || !m.Response || !m.Authoritative || m.Truncated || m.RecursionDesired || m.OpCode != 0 || m.RCode != dnsmessage.RCodeSuccess ||
		len(m.Questions) != 1 || len(m.Answers) != 1 || len(m.Authorities) != 1 || len(m.Additionals) != 0 {
		return errRejected
	}
	q := m.Questions[0]
	a := m.Answers[0]
	body, ok := a.Body.(*dnsmessage.AResource)
	if q.Name.String() != proof.DNSName || q.Type != dnsmessage.TypeA || q.Class != dnsmessage.ClassINET ||
		a.Header.Name.String() != proof.DNSName || a.Header.Type != dnsmessage.TypeA || a.Header.Class != dnsmessage.ClassINET || a.Header.Length != 4 || !ok || body.A != [4]byte{198, 51, 100, 8} {
		return errRejected
	}
	// The pinned file plugin includes the rendered apex NS on positive A
	// responses. This exact local authority is not a referral or a resolver.
	ns := m.Authorities[0]
	nsBody, ok := ns.Body.(*dnsmessage.NSResource)
	if !ok || ns.Header.Name.String() != "tail.example." || ns.Header.Type != dnsmessage.TypeNS ||
		ns.Header.Class != dnsmessage.ClassINET || nsBody.NS.String() != "tail.example." {
		return errRejected
	}
	// Unpack permits trailing bytes; require exactly the advertised wire records.
	offset := skipWireName(b, 12)
	if offset < 0 || offset+4 > len(b) {
		return errRejected
	}
	offset = skipWireName(b, offset+4)
	if offset < 0 || offset+14 > len(b) {
		return errRejected
	}
	offset = skipWireName(b, offset+14) // A header (10) + address (4), then NS owner.
	if offset < 0 || offset+10 > len(b) || offset+10+int(binary.BigEndian.Uint16(b[offset+8:offset+10])) != len(b) ||
		skipWireName(b, offset+10) != len(b) {
		return errRejected
	}
	return nil
}

func exchangeDNS(c net.Conn, network string, query []byte, id uint16) string {
	var reply []byte
	if network == "tcp" {
		frame := make([]byte, 2, len(query)+2)
		binary.BigEndian.PutUint16(frame, uint16(len(query)))
		if writeFull(c, append(frame, query...)) != nil {
			return proof.ErrorExchange
		}
		var prefix [2]byte
		if _, err := io.ReadFull(c, prefix[:]); err != nil {
			return proof.ErrorExchange
		}
		size := int(binary.BigEndian.Uint16(prefix[:]))
		if size < 12 || size > maxDNSBytes {
			return proof.ErrorReply
		}
		reply = make([]byte, size)
		if _, err := io.ReadFull(c, reply); err != nil {
			return proof.ErrorExchange
		}
	} else {
		// UDP must be one datagram, not a stream assembled by writeFull/ReadFull.
		if n, err := c.Write(query); err != nil || n != len(query) {
			return proof.ErrorExchange
		}
		reply = make([]byte, maxDNSBytes+1)
		n, err := c.Read(reply)
		if err != nil {
			return proof.ErrorExchange
		}
		reply = reply[:n]
	}
	if parseDNS(reply, id) != nil {
		return proof.ErrorReply
	}
	return ""
}
