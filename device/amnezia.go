/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/noise"
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
type amneziaState struct {
	// headers is indexed by the canonical message type (1..4); slot 0 is unused.
	headers [5]noise.HeaderRange
	// padding is indexed the same way: bytes prepended to a message of that type.
	padding [5]int

	junkCount int
	junkMin   int
	junkMax   int

	special []*noise.SpecialPacket
}

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
// padding. A zero type means "not ours"; the caller drops the packet.
//
// The handshake messages have fixed lengths, so they are tried first and by
// length before their type word is even read; only then transport. The other
// order would let the random padding of a handshake message pass for a
// transport header whenever its bytes happen to land in a wide H4 range. This
// is the order AmneziaWG itself uses.
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
	for _, candidate := range [3]struct {
		messageType uint32
		size        int
	}{
		{MessageResponseType, MessageResponseSize},
		{MessageInitiationType, MessageInitiationSize},
		{MessageCookieReplyType, MessageCookieReplySize},
	} {
		padding := state.padding[candidate.messageType]
		if len(packet) != padding+candidate.size {
			continue
		}
		if state.headers[candidate.messageType].Contains(binary.LittleEndian.Uint32(packet[padding : padding+4])) {
			return candidate.messageType, packet[padding:]
		}
	}
	padding := state.padding[MessageTransportType]
	if len(packet) >= padding+MessageTransportSize &&
		state.headers[MessageTransportType].Contains(binary.LittleEndian.Uint32(packet[padding:padding+4])) {
		if padding > 0 {
			copy(packet, packet[padding:])
			packet = packet[:len(packet)-padding]
		}
		return MessageTransportType, packet
	}
	return 0, packet
}

// padTransport puts S4 random bytes in front of each framed transport packet.
// A framed packet keeps MessageEncapsulatingTransportSize free bytes at its
// start for the bind, so the padding goes right after them. The padded copies
// come from the outbound pool; the caller returns them with releasePadded once
// the batch is sent. Without S4 the batch is returned as is and nothing is
// allocated.
func (device *Device) padTransport(packets [][]byte) (padded [][]byte, allocated bool) {
	padding := device.messagePadding(MessageTransportType)
	if padding <= 0 {
		return packets, false
	}
	padded = make([][]byte, len(packets))
	for i, packet := range packets {
		out := device.GetOutboundBuffer(len(packet) + padding)[:len(packet)+padding]
		_, _ = rand.Read(out[MessageEncapsulatingTransportSize : MessageEncapsulatingTransportSize+padding])
		copy(out[MessageEncapsulatingTransportSize+padding:], packet[MessageEncapsulatingTransportSize:])
		padded[i] = out
	}
	return padded, true
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

// padHandshake wraps a marshalled handshake message in its S1/S2 padding. It
// returns the whole buffer to send and the message inside it, because the MACs
// are computed over the message alone.
func (device *Device) padHandshake(messageType uint32, messageSize int) (buffer, message []byte) {
	padding := device.messagePadding(messageType)
	buffer = make([]byte, MessageEncapsulatingTransportSize+padding+messageSize)
	if padding > 0 {
		// Padding is read by nobody: it only has to not look like a constant.
		_, _ = rand.Read(buffer[MessageEncapsulatingTransportSize : MessageEncapsulatingTransportSize+padding])
	}
	message = buffer[MessageEncapsulatingTransportSize+padding:]
	return buffer, message
}
