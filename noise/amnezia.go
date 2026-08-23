/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package noise

import (
	"fmt"
)

// AmneziaOptions carries the shaping parameters of an AmneziaWG .conf verbatim:
// the field names are the ones a user sees in the file (Jc, Jmin, Jmax, S1, S2,
// H1..H4, I1..I5), so an imported profile maps one to one and nothing has to be
// guessed back and forth between two naming schemes.
//
// It is deliberately separate from FakePacket: that one is our own WARP noise
// with a different packet shape, and mixing the two on one device would send
// both bursts before the same handshake.
type AmneziaOptions struct {
	// Jc / Jmin / Jmax: a burst of Jc packets of Jmin..Jmax fully random bytes,
	// sent right before the handshake initiation.
	JunkPacketCount   int `json:"jc,omitempty"`
	JunkPacketMinSize int `json:"jmin,omitempty"`
	JunkPacketMaxSize int `json:"jmax,omitempty"`

	// S1 / S2: random bytes prepended to the handshake initiation and response
	// messages themselves, so their length stops being a signature.
	InitPacketJunkSize     int `json:"s1,omitempty"`
	ResponsePacketJunkSize int `json:"s2,omitempty"`

	// H1..H4: replacements for the four WireGuard message type constants
	// (1 initiation, 2 response, 3 cookie reply, 4 transport).
	InitPacketMagicHeader     uint32 `json:"h1,omitempty"`
	ResponsePacketMagicHeader uint32 `json:"h2,omitempty"`
	CookieReplyMagicHeader    uint32 `json:"h3,omitempty"`
	TransportMagicHeader      uint32 `json:"h4,omitempty"`

	// I1..I5: fully specified packets sent before the junk burst. The syntax is
	// AmneziaWG's own: a string of <tag value> chunks, see ParseSpecialPacket.
	SpecialPacket1 string `json:"i1,omitempty"`
	SpecialPacket2 string `json:"i2,omitempty"`
	SpecialPacket3 string `json:"i3,omitempty"`
	SpecialPacket4 string `json:"i4,omitempty"`
	SpecialPacket5 string `json:"i5,omitempty"`
}

// Message sizes repeated here so the package does not have to import device
// (device imports noise, not the other way round). Guarded by a test in device.
const (
	messageInitiationSize  = 148
	messageResponseSize    = 92
	messageCookieReplySize = 64
	messageTransportSize   = 32
)

// Upper bounds are Amnezia's own: a junk packet larger than this stops being
// junk and starts being fragmented traffic.
const (
	maxJunkPacketCount = 128
	maxJunkPacketSize  = 1280
	maxHandshakeJunk   = 1280
	maxSpecialPacket   = 4096
)

func (o AmneziaOptions) specs() [5]string {
	return [5]string{o.SpecialPacket1, o.SpecialPacket2, o.SpecialPacket3, o.SpecialPacket4, o.SpecialPacket5}
}

// Enabled reports whether anything in the block asks for a protocol change.
// Magic headers left at zero mean "the WireGuard defaults", not "disabled".
func (o AmneziaOptions) Enabled() bool {
	if o.JunkPacketCount > 0 || o.InitPacketJunkSize > 0 || o.ResponsePacketJunkSize > 0 {
		return true
	}
	if o.MagicHeadersSet() {
		return true
	}
	for _, spec := range o.specs() {
		if spec != "" {
			return true
		}
	}
	return false
}

// MagicHeadersSet reports whether H1..H4 carry custom values.
func (o AmneziaOptions) MagicHeadersSet() bool {
	return o.InitPacketMagicHeader != 0 ||
		o.ResponsePacketMagicHeader != 0 ||
		o.CookieReplyMagicHeader != 0 ||
		o.TransportMagicHeader != 0
}

// Headers returns the four message type values to put on the wire, filling in
// the WireGuard defaults when H1..H4 are absent.
func (o AmneziaOptions) Headers() (initiation, response, cookieReply, transport uint32) {
	if !o.MagicHeadersSet() {
		return 1, 2, 3, 4
	}
	return o.InitPacketMagicHeader, o.ResponsePacketMagicHeader, o.CookieReplyMagicHeader, o.TransportMagicHeader
}

// Validate rejects a configuration the protocol cannot carry. Everything here
// would otherwise fail as a silently dead tunnel: the handshake goes out shaped
// one way and the peer answers shaped another, with nothing in the log.
func (o AmneziaOptions) Validate() error {
	if !o.Enabled() {
		return nil
	}
	if o.JunkPacketCount < 0 || o.JunkPacketCount > maxJunkPacketCount {
		return fmt.Errorf("amnezia: jc %d out of range 0..%d", o.JunkPacketCount, maxJunkPacketCount)
	}
	if o.JunkPacketCount > 0 {
		if o.JunkPacketMinSize < 0 || o.JunkPacketMaxSize > maxJunkPacketSize {
			return fmt.Errorf("amnezia: jmin/jmax %d-%d out of range 0..%d", o.JunkPacketMinSize, o.JunkPacketMaxSize, maxJunkPacketSize)
		}
		if o.JunkPacketMinSize > o.JunkPacketMaxSize {
			return fmt.Errorf("amnezia: jmin %d is greater than jmax %d", o.JunkPacketMinSize, o.JunkPacketMaxSize)
		}
		if o.JunkPacketMaxSize == 0 {
			return fmt.Errorf("amnezia: jc %d with jmax 0 sends nothing", o.JunkPacketCount)
		}
	}
	if o.InitPacketJunkSize < 0 || o.InitPacketJunkSize > maxHandshakeJunk {
		return fmt.Errorf("amnezia: s1 %d out of range 0..%d", o.InitPacketJunkSize, maxHandshakeJunk)
	}
	if o.ResponsePacketJunkSize < 0 || o.ResponsePacketJunkSize > maxHandshakeJunk {
		return fmt.Errorf("amnezia: s2 %d out of range 0..%d", o.ResponsePacketJunkSize, maxHandshakeJunk)
	}
	// A padded initiation and a padded response must not end up the same length:
	// the receiver tells the two apart by size before it looks at anything else.
	if o.InitPacketJunkSize+messageInitiationSize == o.ResponsePacketJunkSize+messageResponseSize {
		return fmt.Errorf("amnezia: s1 %d and s2 %d make initiation and response the same size", o.InitPacketJunkSize, o.ResponsePacketJunkSize)
	}
	if o.MagicHeadersSet() {
		headers := [4]uint32{o.InitPacketMagicHeader, o.ResponsePacketMagicHeader, o.CookieReplyMagicHeader, o.TransportMagicHeader}
		names := [4]string{"h1", "h2", "h3", "h4"}
		for i, value := range headers {
			if value == 0 {
				return fmt.Errorf("amnezia: %s is not set while the other magic headers are", names[i])
			}
			for j := i + 1; j < len(headers); j++ {
				if value == headers[j] {
					return fmt.Errorf("amnezia: %s and %s are both %d", names[i], names[j], value)
				}
			}
		}
	}
	for i, spec := range o.specs() {
		if spec == "" {
			continue
		}
		packet, err := ParseSpecialPacket(spec)
		if err != nil {
			return fmt.Errorf("amnezia: i%d: %w", i+1, err)
		}
		if packet.Len() > maxSpecialPacket {
			return fmt.Errorf("amnezia: i%d is %d bytes, over the %d limit", i+1, packet.Len(), maxSpecialPacket)
		}
	}
	return nil
}

// SpecialPackets compiles I1..I5, skipping the empty slots. Validate has
// already reported any syntax error, so a broken spec is dropped here rather
// than failing the device.
func (o AmneziaOptions) SpecialPackets() []*SpecialPacket {
	var packets []*SpecialPacket
	for _, spec := range o.specs() {
		if spec == "" {
			continue
		}
		packet, err := ParseSpecialPacket(spec)
		if err != nil {
			continue
		}
		packets = append(packets, packet)
	}
	return packets
}

// MessageSizes exposes the handshake message sizes this package validates
// against, so the device package can assert they still match the protocol
// constants it owns.
func MessageSizes() (initiation, response, cookieReply, transport int) {
	return messageInitiationSize, messageResponseSize, messageCookieReplySize, messageTransportSize
}
