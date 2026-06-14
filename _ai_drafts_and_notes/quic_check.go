package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	conn, err := net.DialTimeout("udp", "1.1.1.1:443", 2*time.Second)
	if err != nil {
		fmt.Println("Dial error:", err)
		return
	}
	defer conn.Close()

	// Send a dummy QUIC packet (Long header, version 0x0a0a0a0a to force version negotiation)
	// Byte 0: 0xc0 (Long header, initial)
	// Bytes 1-4: 0x0a 0x0a 0x0a 0x0a (Version)
	// Byte 5: 0x00 (Dest Connection ID length)
	// Byte 6: 0x00 (Src Connection ID length)
	// Padding up to 1200 bytes is required by QUIC spec for Initial packets!
	payload := make([]byte, 1200)
	payload[0] = 0xc0
	payload[1] = 0x0a
	payload[2] = 0x0a
	payload[3] = 0x0a
	payload[4] = 0x0a
	payload[5] = 0x00
	payload[6] = 0x00

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write(payload)
	if err != nil {
		fmt.Println("Write error:", err)
		return
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Read error (QUIC Blocked?):", err)
	} else {
		fmt.Printf("Received %d bytes (QUIC is OPEN!)\n", n)
	}
}
