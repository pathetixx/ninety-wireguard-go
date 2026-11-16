/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package noise

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
)

// AmneziaOptions carries the shaping parameters of an AmneziaWG .conf verbatim:
// the field names are the ones a user sees in the file (Jc, Jmin, Jmax,
// S1..S4, H1..H4, I1..I5), so an imported profile maps one to one and nothing
// has to be guessed back and forth between two naming schemes.
//
// AmneziaWG 2.0 is covered by the same block: S3/S4 pad the cookie reply and
// every transport packet, and H1..H4 may be ranges ("100-200") from which each
// packet draws its own type value.
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

	// S3 / S4 (AmneziaWG 2.0): the same for the cookie reply and for every
	// transport packet.
	CookieReplyJunkSize int `json:"s3,omitempty"`
	TransportJunkSize   int `json:"s4,omitempty"`

	// H1..H4: replacements for the four WireGuard message type constants
	// (1 initiation, 2 response, 3 cookie reply, 4 transport). A single value
	// is AmneziaWG 1.x; a range is 2.0 and every packet picks a value in it.
	InitPacketMagicHeader     HeaderRange `json:"h1,omitzero"`
	ResponsePacketMagicHeader HeaderRange `json:"h2,omitzero"`
	CookieReplyMagicHeader    HeaderRange `json:"h3,omitzero"`
	TransportMagicHeader      HeaderRange `json:"h4,omitzero"`

	// I1..I5: fully specified packets sent before the junk burst. The syntax is
	// AmneziaWG's own: a string of <tag value> chunks, see ParseSpecialPacket.
	SpecialPacket1 string `json:"i1,omitempty"`
	SpecialPacket2 string `json:"i2,omitempty"`
	SpecialPacket3 string `json:"i3,omitempty"`
	SpecialPacket4 string `json:"i4,omitempty"`
	SpecialPacket5 string `json:"i5,omitempty"`
}

// HeaderRange is a magic header value or an inclusive range of them. It reads
// a bare number, "123", or "100-200", and writes a single value back as a
// number, so a 1.x config round-trips unchanged.
type HeaderRange struct {
	From uint32
	To   uint32
}

// Single builds the 1.x form: one fixed value.
func Single(value uint32) HeaderRange {
	return HeaderRange{From: value, To: value}
}

// IsZero reports an unset header (omitempty relies on it).
func (r HeaderRange) IsZero() bool {
	return r.From == 0 && r.To == 0
}

// Contains reports whether a value read off the wire belongs to this header.
func (r HeaderRange) Contains(value uint32) bool {
	return r.From <= value && value <= r.To
}

// Pick draws the value for one packet. It is not crypto/rand: it runs for
// every transport packet, and the value only has to vary, not stay secret.
func (r HeaderRange) Pick() uint32 {
	if r.From >= r.To {
		return r.From
	}
	return r.From + uint32(rand.Uint64N(uint64(r.To-r.From)+1))
}

func (r HeaderRange) overlaps(other HeaderRange) bool {
	return r.From <= other.To && other.From <= r.To
}

func (r HeaderRange) String() string {
	if r.From == r.To {
		return strconv.FormatUint(uint64(r.From), 10)
	}
	return fmt.Sprintf("%d-%d", r.From, r.To)
}

func (r HeaderRange) MarshalJSON() ([]byte, error) {
	if r.From == r.To {
		return json.Marshal(r.From)
	}
	return json.Marshal(r.String())
}

func (r *HeaderRange) UnmarshalJSON(content []byte) error {
	var number uint32
	if err := json.Unmarshal(content, &number); err == nil {
		*r = Single(number)
		return nil
	}
	var text string
	if err := json.Unmarshal(content, &text); err != nil {
		return fmt.Errorf("magic header: expected a number or \"from-to\", got %s", content)
	}
	parsed, err := ParseHeaderRange(text)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// ParseHeaderRange reads the .conf spelling: "123" or "100-200".
func ParseHeaderRange(text string) (HeaderRange, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return HeaderRange{}, nil
	}
	fromText, toText, isRange := strings.Cut(text, "-")
	from, err := strconv.ParseUint(strings.TrimSpace(fromText), 10, 32)
	if err != nil {
		return HeaderRange{}, fmt.Errorf("magic header %q: %w", text, err)
	}
	to := from
	if isRange {
		to, err = strconv.ParseUint(strings.TrimSpace(toText), 10, 32)
		if err != nil {
			return HeaderRange{}, fmt.Errorf("magic header %q: %w", text, err)
		}
	}
	if to < from {
		return HeaderRange{}, fmt.Errorf("magic header %q: range ends before it starts", text)
	}
	return HeaderRange{From: uint32(from), To: uint32(to)}, nil
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
	// S4 is paid on every transport packet, on top of the MTU; past this it
	// only fragments traffic. AmneziaWG's own generator stays far below.
	maxTransportJunk = 256
)

func (o AmneziaOptions) specs() [5]string {
	return [5]string{o.SpecialPacket1, o.SpecialPacket2, o.SpecialPacket3, o.SpecialPacket4, o.SpecialPacket5}
}

// Enabled reports whether anything in the block asks for a protocol change.
// Magic headers left at zero mean "the WireGuard defaults", not "disabled".
func (o AmneziaOptions) Enabled() bool {
	if o.JunkPacketCount > 0 || o.InitPacketJunkSize > 0 || o.ResponsePacketJunkSize > 0 ||
		o.CookieReplyJunkSize > 0 || o.TransportJunkSize > 0 {
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
	return !o.InitPacketMagicHeader.IsZero() ||
		!o.ResponsePacketMagicHeader.IsZero() ||
		!o.CookieReplyMagicHeader.IsZero() ||
		!o.TransportMagicHeader.IsZero()
}

// Headers returns the four message type ranges to put on the wire, filling in
// the WireGuard defaults when H1..H4 are absent.
func (o AmneziaOptions) Headers() (initiation, response, cookieReply, transport HeaderRange) {
	if !o.MagicHeadersSet() {
		return Single(1), Single(2), Single(3), Single(4)
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
	if o.CookieReplyJunkSize < 0 || o.CookieReplyJunkSize > maxHandshakeJunk {
		return fmt.Errorf("amnezia: s3 %d out of range 0..%d", o.CookieReplyJunkSize, maxHandshakeJunk)
	}
	if o.TransportJunkSize < 0 || o.TransportJunkSize > maxTransportJunk {
		return fmt.Errorf("amnezia: s4 %d out of range 0..%d", o.TransportJunkSize, maxTransportJunk)
	}
	// A padded initiation and a padded response must not end up the same length:
	// the receiver tells the two apart by size before it looks at anything else.
	if o.InitPacketJunkSize+messageInitiationSize == o.ResponsePacketJunkSize+messageResponseSize {
		return fmt.Errorf("amnezia: s1 %d and s2 %d make initiation and response the same size", o.InitPacketJunkSize, o.ResponsePacketJunkSize)
	}
	if o.MagicHeadersSet() {
		headers := [4]HeaderRange{o.InitPacketMagicHeader, o.ResponsePacketMagicHeader, o.CookieReplyMagicHeader, o.TransportMagicHeader}
		names := [4]string{"h1", "h2", "h3", "h4"}
		for i, value := range headers {
			if value.IsZero() {
				return fmt.Errorf("amnezia: %s is not set while the other magic headers are", names[i])
			}
			if value.From > value.To {
				return fmt.Errorf("amnezia: %s range %d-%d ends before it starts", names[i], value.From, value.To)
			}
			// The receiver tells the four messages apart by which range the type
			// word falls in, so the ranges must not share a single value.
			for j := i + 1; j < len(headers); j++ {
				if value.overlaps(headers[j]) {
					return fmt.Errorf("amnezia: %s (%s) and %s (%s) overlap", names[i], value, names[j], headers[j])
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
