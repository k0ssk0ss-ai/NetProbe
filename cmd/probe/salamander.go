package main

// EN: Hysteria2 "salamander" obfuscation, so the QUIC probe can talk to a server that
// EN: drops plain QUIC. Wire format: 8-byte random salt, then the payload XORed with
// EN: BLAKE2b-256(password || salt) repeated. The obfs password is shared by every
// EN: client of the server (it is in each subscription link), not a user credential.
// RU: Обфускация Salamander из Hysteria2 — без неё сервер молча выбрасывает QUIC.

import (
	"crypto/rand"
	"net"

	"golang.org/x/crypto/blake2b"
)

var hy2Obfs = "" // salamander password, set via -ldflags; empty = plain QUIC

const saltLen = 8

type salamanderConn struct {
	net.PacketConn
	key []byte
}

func newSalamander(conn net.PacketConn, password string) *salamanderConn {
	return &salamanderConn{PacketConn: conn, key: []byte(password)}
}

func (c *salamanderConn) mask(salt []byte) [blake2b.Size256]byte {
	return blake2b.Sum256(append(append([]byte{}, c.key...), salt...))
}

func (c *salamanderConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, len(p)+saltLen)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n <= saltLen {
			continue // not ours
		}
		m := c.mask(buf[:saltLen])
		out := buf[saltLen:n]
		for i := range out {
			p[i] = out[i] ^ m[i%len(m)]
		}
		return n - saltLen, addr, nil
	}
}

func (c *salamanderConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	pkt := make([]byte, saltLen+len(p))
	if _, err := rand.Read(pkt[:saltLen]); err != nil {
		return 0, err
	}
	m := c.mask(pkt[:saltLen])
	for i, b := range p {
		pkt[saltLen+i] = b ^ m[i%len(m)]
	}
	if _, err := c.PacketConn.WriteTo(pkt, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}
