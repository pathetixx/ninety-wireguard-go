/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/sagernet/wireguard-go/noise"
)

// AmneziaWG shaping, as configured by an imported .conf. Three things change
// on the wire, and all three have to be applied on send and undone on receive
// or the tunnel dies silently:
//
//   - Jc/Jmin/Jmax: junk packets before the handshake initiation.
//   - S1/S2: random bytes in front of the initiation and response messages.
//   - H1..H4: the four message type constants.
//   - I1..I5: fully specified packets sent ahead of everything else.
type amneziaState struct {
	// headers is indexed by the canonical message type (1..4); slot 0 is unused.
	headers [5]uint32
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
	device.amnezia = state
	return nil
}

func (device *Device) amneziaEnabled() bool {
	return device.amnezia != nil
}

// messageType maps a canonical WireGuard message type to the value that goes on
// the wire.
func (device *Device) messageType(canonical uint32) uint32 {
	if device.amnezia == nil {
		return canonical
	}
	return device.amnezia.headers[canonical]
}

// messagePadding is the number of random bytes prepended to a message of this
// type. Only the two handshake messages carry padding.
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
// Order matters: transport is by far the most common packet, so it is tried
// first, and the handshake messages are told apart by length before their type
// word is even read.
func (device *Device) classifyPacket(packet []byte) (uint32, []byte) {
	state := device.amnezia
	if state == nil {
		if len(packet) < 4 {
			return 0, packet
		}
		return binary.LittleEndian.Uint32(packet[:4]), packet
	}
	if len(packet) >= MessageTransportSize &&
		binary.LittleEndian.Uint32(packet[:4]) == state.headers[MessageTransportType] {
		return MessageTransportType, packet
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
		if binary.LittleEndian.Uint32(packet[padding:padding+4]) == state.headers[candidate.messageType] {
			return candidate.messageType, packet[padding:]
		}
	}
	return 0, packet
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

// sendAmneziaPrologue sends the I1..I5 packets and then the junk burst, in that
// order, so the flow opens with the traffic the operator specified.
func (peer *Peer) sendAmneziaPrologue() error {
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
	return peer.sendPackets(buffers)
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
