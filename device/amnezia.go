/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	mrand "math/rand/v2"
	"sync/atomic"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/noise"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// AmneziaWG shaping, as configured by an imported .conf. Everything below
// changes the wire, and has to be applied on send and undone on receive or the
// tunnel dies silently:
//
//   - Jc/Jmin/Jmax: junk packets before the handshake initiation.
//   - S1/S2: random bytes in front of the initiation and response messages.
//   - S3/S4 (2.0): the same in front of the cookie reply and every transport
//     packet.
//   - H1..H4: the four message type constants; in 2.0 each one is a range and
//     every packet draws its own value from it.
//   - I1..I5: fully specified packets sent ahead of everything else.
//   - Header protection (3): every message header is XORed with a ChaCha20
//     keystream; the key is configured, the nonce is the first 12 bytes of the
//     padding in front of the message. A handshake message is encrypted whole,
//     a transport message only in its 16-byte header.
//   - Random trailers (3): random bytes after a handshake message, which the
//     receiver accepts as long as the message itself fits.
//   - Content padding (3): transport plaintext padded by a random amount
//     instead of to a multiple of 16; the receiver drops it by the IP length,
//     as plain WireGuard does with its own padding.
type amneziaState struct {
	// headers is indexed by the canonical message type (1..4); slot 0 is unused.
	headers [5]noise.HeaderRange
	// padding is indexed the same way: bytes prepended to a message of that type.
	padding [5]int

	junkCount int
	junkMin   int
	junkMax   int

	special []*noise.SpecialPacket

	headerKey      [noise.HeaderKeySize]byte
	headerProtect  bool
	contentPadding noise.HeaderRange
	randomTrailers bool
	// udpWindow is the largest datagram seen on this device either way, the
	// ceiling for trailers and content padding: they must not make a packet
	// longer than ones the path already carries. AmneziaWG keeps it per peer;
	// a Ninety endpoint has one peer, so per device is the same thing.
	udpWindow atomic.Uint32
}

// defaultUDPWindow is AmneziaWG's starting ceiling before any packet is seen.
const defaultUDPWindow = 500

// SetNoise installs the noise/AmneziaWG configuration. It is the only supported
// way in: assigning Device.Noise directly still works for plain WARP noise, but
// leaves the AmneziaWG side off, and an invalid configuration has to fail here
// rather than as a tunnel that never completes a handshake.
func (device *Device) SetNoise(options noise.Options) error {
	if err := options.Amnezia.Validate(); err != nil {
		return err
	}
	if options.FakePacket.Enabled && options.Amnezia.Enabled() {
		return errors.New("noise: fake_packet and amnezia both send a junk burst before the handshake; pick one")
	}
	device.Noise = options
	if !options.Amnezia.Enabled() {
		device.amnezia = nil
		return nil
	}
	state := &amneziaState{
		junkCount: options.Amnezia.JunkPacketCount,
		junkMin:   options.Amnezia.JunkPacketMinSize,
		junkMax:   options.Amnezia.JunkPacketMaxSize,
		special:   options.Amnezia.SpecialPackets(),
	}
	initiation, response, cookieReply, transport := options.Amnezia.Headers()
	state.headers[MessageInitiationType] = initiation
	state.headers[MessageResponseType] = response
	state.headers[MessageCookieReplyType] = cookieReply
	state.headers[MessageTransportType] = transport
	state.padding[MessageInitiationType] = options.Amnezia.InitPacketJunkSize
	state.padding[MessageResponseType] = options.Amnezia.ResponsePacketJunkSize
	state.padding[MessageCookieReplyType] = options.Amnezia.CookieReplyJunkSize
	state.padding[MessageTransportType] = options.Amnezia.TransportJunkSize
	if options.Amnezia.HeaderProtectionKey != "" {
		key, err := options.Amnezia.HeaderKey()
		if err != nil {
			return err
		}
		state.headerKey = key
		state.headerProtect = true
	}
	state.contentPadding = options.Amnezia.ContentPaddingAddition
	state.randomTrailers = options.Amnezia.RandomTrailers
	state.udpWindow.Store(defaultUDPWindow)
	device.amnezia = state
	return nil
}

func (device *Device) amneziaEnabled() bool {
	return device.amnezia != nil
}

// messageType maps a canonical WireGuard message type to the value that goes on
// the wire. With a 2.0 range every call draws a fresh value.
func (device *Device) messageType(canonical uint32) uint32 {
	if device.amnezia == nil {
		return canonical
	}
	return device.amnezia.headers[canonical].Pick()
}

// isMessageType reports whether a type word read off the wire stands for the
// canonical message type: equal to it without shaping, inside H1..H4 with it.
func (device *Device) isMessageType(canonical, value uint32) bool {
	if device.amnezia == nil {
		return value == canonical
	}
	return device.amnezia.headers[canonical].Contains(value)
}

// messagePadding is the number of random bytes prepended to a message of this
// type: S1..S4 for initiation, response, cookie reply and transport.
func (device *Device) messagePadding(canonical uint32) int {
	if device.amnezia == nil {
		return 0
	}
	return device.amnezia.padding[canonical]
}

// classifyPacket recognises an incoming packet under the configured shaping and
// returns the canonical message type together with the packet without its
// padding (and, for a handshake message, without its trailer). A zero type
// means "not ours"; the caller drops the packet.
//
// The handshake messages have fixed lengths, so they are tried first and by
// length before their type word is even read; only then transport. The other
// order would let the random padding of a handshake message pass for a
// transport header whenever its bytes happen to land in a wide H4 range. This
// is the order AmneziaWG itself uses.
//
// With header protection the type word is compared after removing the first
// four keystream bytes, and the recognised header is decrypted in place:
// a handshake message whole, a transport message in its 16-byte header.
//
// A transport packet loses its S4 padding in place: it is moved to the front of
// the buffer, because the receive path addresses the decrypted content from the
// buffer start.
func (device *Device) classifyPacket(packet []byte) (uint32, []byte) {
	state := device.amnezia
	if state == nil {
		if len(packet) < 4 {
			return 0, packet
		}
		return binary.LittleEndian.Uint32(packet[:4]), packet
	}
	state.observeDatagram(len(packet))
	var typeMask [4]byte
	if state.headerProtect {
		if len(packet) < noise.HeaderNonceSize {
			return 0, packet
		}
		state.keystream(packet[:noise.HeaderNonceSize], typeMask[:])
	}
	typeWord := func(at int) uint32 {
		return binary.LittleEndian.Uint32(packet[at:at+4]) ^ binary.LittleEndian.Uint32(typeMask[:])
	}
	for _, candidate := range [3]struct {
		messageType uint32
		size        int
	}{
		{MessageResponseType, MessageResponseSize},
		{MessageInitiationType, MessageInitiationSize},
		{MessageCookieReplyType, MessageCookieReplySize},
	} {
		padding := state.padding[candidate.messageType]
		expected := padding + candidate.size
		if len(packet) != expected && !(state.randomTrailers && len(packet) > expected) {
			continue
		}
		if !state.headers[candidate.messageType].Contains(typeWord(padding)) {
			continue
		}
		message := packet[padding:expected]
		if state.headerProtect {
			state.xorHeader(packet[:noise.HeaderNonceSize], message)
		}
		return candidate.messageType, message
	}
	padding := state.padding[MessageTransportType]
	if len(packet) >= padding+MessageTransportSize && state.headers[MessageTransportType].Contains(typeWord(padding)) {
		if state.headerProtect {
			state.xorHeader(packet[:noise.HeaderNonceSize], packet[padding:padding+MessageTransportHeaderSize])
		}
		if padding > 0 {
			copy(packet, packet[padding:])
			packet = packet[:len(packet)-padding]
		}
		return MessageTransportType, packet
	}
	return 0, packet
}

// keystream writes the first len(dst) header-protection keystream bytes for
// this nonce into dst, which must be zeroed.
func (state *amneziaState) keystream(nonce, dst []byte) {
	cipher, err := chacha20.NewUnauthenticatedCipher(state.headerKey[:], nonce)
	if err != nil {
		// Key and nonce sizes are fixed constants; this cannot fail.
		return
	}
	cipher.XORKeyStream(dst, dst)
}

// xorHeader applies the header-protection keystream for this nonce to data,
// starting at keystream position 0. Encryption and decryption are the same.
func (state *amneziaState) xorHeader(nonce, data []byte) {
	cipher, err := chacha20.NewUnauthenticatedCipher(state.headerKey[:], nonce)
	if err != nil {
		return
	}
	cipher.XORKeyStream(data, data)
}

func (state *amneziaState) observeDatagram(size int) {
	for {
		current := state.udpWindow.Load()
		if uint32(size) <= current || state.udpWindow.CompareAndSwap(current, uint32(size)) {
			return
		}
	}
}

// spare is how many bytes a packet of this size may still grow by.
func (state *amneziaState) spare(size int) int {
	window := int(state.udpWindow.Load())
	if window <= size {
		return 0
	}
	return window - size
}

// handshakeTrailer is the random trailer length for a handshake datagram of
// this size, or 0 when trailers are off.
func (device *Device) handshakeTrailer(size int) int {
	state := device.amnezia
	if state == nil || !state.randomTrailers {
		return 0
	}
	spare := state.spare(size)
	if spare == 0 {
		return 0
	}
	return int(mrand.Uint32N(uint32(spare)))
}

// contentPadding is the plaintext padding for a transport packet carrying
// plainLen bytes, under ContentPaddingAddition or RandomTrailers. -1 means
// neither is set and the WireGuard multiple-of-16 rule applies.
func (device *Device) contentPadding(plainLen int) int {
	state := device.amnezia
	if state == nil {
		return -1
	}
	wire := state.padding[MessageTransportType] + MessageTransportSize + plainLen
	switch {
	case !state.contentPadding.IsZero():
		return min(int(state.contentPadding.Pick()), state.spare(wire))
	case state.randomTrailers:
		spare := state.spare(wire)
		if spare == 0 {
			return 0
		}
		return int(mrand.Uint32N(uint32(spare)))
	default:
		return -1
	}
}

// padTransport puts S4 random bytes in front of each framed transport packet.
// A framed packet keeps MessageEncapsulatingTransportSize free bytes at its
// start for the bind, so the padding goes right after them. The padded copies
// come from the outbound pool; the caller returns them with releasePadded once
// the batch is sent. Without S4 the batch is returned as is and nothing is
// allocated.
func (device *Device) padTransport(packets [][]byte) (padded [][]byte, allocated bool) {
	padding := device.messagePadding(MessageTransportType)
	state := device.amnezia
	if padding <= 0 {
		if state != nil {
			for _, packet := range packets {
				state.observeDatagram(len(packet) - MessageEncapsulatingTransportSize)
			}
		}
		return packets, false
	}
	padded = make([][]byte, len(packets))
	for i, packet := range packets {
		out := device.GetOutboundBuffer(len(packet) + padding)[:len(packet)+padding]
		_, _ = rand.Read(out[MessageEncapsulatingTransportSize : MessageEncapsulatingTransportSize+padding])
		message := out[MessageEncapsulatingTransportSize+padding:]
		copy(message, packet[MessageEncapsulatingTransportSize:])
		if state.headerProtect {
			// Validation guarantees S4 >= 12, so the nonce is all padding.
			nonce := out[MessageEncapsulatingTransportSize : MessageEncapsulatingTransportSize+noise.HeaderNonceSize]
			state.xorHeader(nonce, message[:MessageTransportHeaderSize])
		}
		state.observeDatagram(len(out) - MessageEncapsulatingTransportSize)
		padded[i] = out
	}
	return padded, true
}

// reserveOutbound makes sure elem.buffer can hold its plaintext plus extra
// bytes of content padding and the AEAD tag, moving the plaintext to a larger
// pooled buffer when it cannot. Most buffers are allocated to the exact packet
// size, with room only for WireGuard's own 16-byte padding.
func (device *Device) reserveOutbound(elem *QueueOutboundElement, extra int) {
	const offset = MessageEncapsulatingTransportSize + MessageTransportHeaderSize
	need := offset + len(elem.packet) + extra + chacha20poly1305.Overhead
	if len(elem.buffer) >= need {
		return
	}
	buffer := device.GetOutboundBuffer(need)[:need]
	n := copy(buffer[offset:], elem.packet)
	device.PutOutboundBuffer(elem.buffer)
	elem.buffer = buffer
	elem.packet = buffer[offset : offset+n]
}

func (device *Device) releasePadded(packets [][]byte) {
	for _, packet := range packets {
		device.PutOutboundBuffer(packet)
	}
}

// padCookieReply wraps a cookie reply in its S3 padding, the way padHandshake
// does for the handshake messages.
func (device *Device) padCookieReply() (buffer, message []byte) {
	return device.padHandshake(MessageCookieReplyType, MessageCookieReplySize)
}

// sendPackets sends already framed packets, keeping the reserved-byte rewrite
// out of the way when shaping is on: those three bytes land inside a magic
// header or inside handshake padding, and rewriting them would corrupt both.
// Configurations that need reserved bytes (WARP) are rejected upstream.
func (peer *Peer) sendPackets(buffers [][]byte) error {
	if peer.device.amneziaEnabled() {
		return peer.SendBuffersWithoutModify(buffers)
	}
	return peer.SendBuffers(buffers)
}

// sendHandshakeFlow sends what belongs on the flows of a handshake initiation:
// the initiation itself and the junk and I-packets in front of it. A peer with
// an endpoint resolver races the initiation over every resolved candidate and
// has no current endpoint before the first response, so the prologue takes the
// same fan-out - otherwise it fails outright, or reaches one flow and leaves
// the rest opening with a bare handshake.
func (peer *Peer) sendHandshakeFlow(buffers [][]byte, candidates []conn.Endpoint, noModify bool) error {
	if len(candidates) > 0 {
		return peer.sendHandshakeBuffers(buffers, candidates, noModify)
	}
	if noModify {
		return peer.SendBuffersWithoutModify(buffers)
	}
	return peer.SendBuffers(buffers)
}

// sendAmneziaPrologue sends the I1..I5 packets and then the junk burst, in that
// order, so the flow opens with the traffic the operator specified.
func (peer *Peer) sendAmneziaPrologue(candidates []conn.Endpoint) error {
	state := peer.device.amnezia
	if state == nil {
		return nil
	}
	var buffers [][]byte
	for _, packet := range state.special {
		// The leading MessageEncapsulatingTransportSize bytes are stripped by
		// the bind before the packet reaches the wire.
		buffer := make([]byte, MessageEncapsulatingTransportSize+packet.Len())
		packet.Render(buffer[MessageEncapsulatingTransportSize:])
		buffers = append(buffers, buffer)
	}
	for i := 0; i < state.junkCount; i++ {
		size := state.junkMin
		if state.junkMax > state.junkMin {
			size += int(noise.RandBetween(0, int64(state.junkMax-state.junkMin)))
		}
		if size <= 0 {
			continue
		}
		buffer := make([]byte, MessageEncapsulatingTransportSize+size)
		if _, err := rand.Read(buffer[MessageEncapsulatingTransportSize:]); err != nil {
			return err
		}
		buffers = append(buffers, buffer)
	}
	if len(buffers) == 0 {
		return nil
	}
	return peer.sendHandshakeFlow(buffers, candidates, peer.device.amneziaEnabled())
}

// padHandshake wraps a marshalled handshake message in its S1/S2/S3 padding
// and, with random trailers, a random tail. It returns the whole buffer to send
// and the message inside it, because the MACs are computed over the message
// alone. Once the message is final, sealHandshake applies header protection.
func (device *Device) padHandshake(messageType uint32, messageSize int) (buffer, message []byte) {
	padding := device.messagePadding(messageType)
	trailer := device.handshakeTrailer(padding + messageSize)
	buffer = make([]byte, MessageEncapsulatingTransportSize+padding+messageSize+trailer)
	if padding > 0 {
		// Without header protection the padding is read by nobody: it only has
		// to not look like a constant. With it, its first bytes are the nonce.
		_, _ = rand.Read(buffer[MessageEncapsulatingTransportSize : MessageEncapsulatingTransportSize+padding])
	}
	start := MessageEncapsulatingTransportSize + padding
	if trailer > 0 {
		_, _ = rand.Read(buffer[start+messageSize:])
	}
	message = buffer[start : start+messageSize]
	return buffer, message
}

// sealHandshake encrypts a finished handshake message (MACs included) under
// header protection. buffer and message are what padHandshake returned.
func (device *Device) sealHandshake(buffer, message []byte) {
	state := device.amnezia
	if state == nil {
		return
	}
	state.observeDatagram(len(buffer) - MessageEncapsulatingTransportSize)
	if !state.headerProtect {
		return
	}
	nonce := buffer[MessageEncapsulatingTransportSize : MessageEncapsulatingTransportSize+noise.HeaderNonceSize]
	state.xorHeader(nonce, message)
}
