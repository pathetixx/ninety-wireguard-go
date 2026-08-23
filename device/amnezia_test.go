/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"testing"

	"github.com/sagernet/wireguard-go/noise"
)

// The noise package validates S1/S2 against its own copy of the message sizes,
// because device imports noise and not the other way round. If the protocol
// constants ever move, that validation would start rejecting valid configs (or
// accepting broken ones) with nothing to point at.
func TestAmneziaMessageSizesMatch(t *testing.T) {
	initiation, response, cookieReply, transport := noise.MessageSizes()
	for _, pair := range []struct {
		name   string
		noise  int
		device int
	}{
		{"initiation", initiation, MessageInitiationSize},
		{"response", response, MessageResponseSize},
		{"cookie reply", cookieReply, MessageCookieReplySize},
		{"transport", transport, MessageTransportSize},
	} {
		if pair.noise != pair.device {
			t.Errorf("%s size: noise has %d, device has %d", pair.name, pair.noise, pair.device)
		}
	}
}

func TestAmneziaValidate(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		options noise.AmneziaOptions
		wantErr bool
	}{
		{name: "empty"},
		{name: "junk only", options: noise.AmneziaOptions{JunkPacketCount: 4, JunkPacketMinSize: 8, JunkPacketMaxSize: 80}},
		{name: "jmin above jmax", options: noise.AmneziaOptions{JunkPacketCount: 4, JunkPacketMinSize: 80, JunkPacketMaxSize: 8}, wantErr: true},
		{name: "junk without size", options: noise.AmneziaOptions{JunkPacketCount: 4}, wantErr: true},
		{
			name:    "colliding handshake sizes",
			options: noise.AmneziaOptions{InitPacketJunkSize: 0, ResponsePacketJunkSize: 56},
			wantErr: true,
		},
		{
			name:    "partial magic headers",
			options: noise.AmneziaOptions{InitPacketMagicHeader: 5},
			wantErr: true,
		},
		{
			name: "duplicate magic headers",
			options: noise.AmneziaOptions{
				InitPacketMagicHeader: 5, ResponsePacketMagicHeader: 5,
				CookieReplyMagicHeader: 7, TransportMagicHeader: 8,
			},
			wantErr: true,
		},
		{
			name: "full set",
			options: noise.AmneziaOptions{
				JunkPacketCount: 4, JunkPacketMinSize: 8, JunkPacketMaxSize: 80,
				InitPacketJunkSize: 15, ResponsePacketJunkSize: 20,
				InitPacketMagicHeader: 1020983529, ResponsePacketMagicHeader: 1449520552,
				CookieReplyMagicHeader: 1120404579, TransportMagicHeader: 1741401686,
				SpecialPacket1: "<b 0xdeadbeef>",
			},
		},
		{name: "broken special packet", options: noise.AmneziaOptions{SpecialPacket1: "<b 0xzz>"}, wantErr: true},
		{name: "unknown special tag", options: noise.AmneziaOptions{SpecialPacket1: "<q 4>"}, wantErr: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.options.Validate()
			if testCase.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !testCase.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// A device configured from a .conf must recognise what it sends: the magic
// header and the padding have to survive the round trip through classifyPacket.
func TestAmneziaClassifyRoundTrip(t *testing.T) {
	device := &Device{}
	err := device.SetNoise(noise.Options{Amnezia: noise.AmneziaOptions{
		InitPacketJunkSize: 15, ResponsePacketJunkSize: 20,
		InitPacketMagicHeader: 1020983529, ResponsePacketMagicHeader: 1449520552,
		CookieReplyMagicHeader: 1120404579, TransportMagicHeader: 1741401686,
	}})
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range []struct {
		name        string
		messageType uint32
		size        int
	}{
		{"initiation", MessageInitiationType, MessageInitiationSize},
		{"response", MessageResponseType, MessageResponseSize},
		{"cookie reply", MessageCookieReplyType, MessageCookieReplySize},
		{"transport", MessageTransportType, MessageTransportSize},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			buffer, message := device.padHandshake(testCase.messageType, testCase.size)
			binary.LittleEndian.PutUint32(message[:4], device.messageType(testCase.messageType))
			onWire := buffer[MessageEncapsulatingTransportSize:]

			gotType, gotPacket := device.classifyPacket(onWire)
			if gotType != testCase.messageType {
				t.Fatalf("type: got %d, want %d", gotType, testCase.messageType)
			}
			if len(gotPacket) != testCase.size {
				t.Fatalf("size: got %d, want %d", len(gotPacket), testCase.size)
			}
		})
	}

	if gotType, _ := device.classifyPacket(make([]byte, MessageInitiationSize)); gotType != 0 {
		t.Fatalf("a plain WireGuard initiation must not be recognised, got type %d", gotType)
	}
}

// Without shaping nothing changes: the type is read straight off the packet.
func TestClassifyPacketWithoutAmnezia(t *testing.T) {
	device := &Device{}
	packet := make([]byte, MessageTransportSize)
	binary.LittleEndian.PutUint32(packet[:4], MessageTransportType)
	gotType, gotPacket := device.classifyPacket(packet)
	if gotType != MessageTransportType || len(gotPacket) != len(packet) {
		t.Fatalf("got type %d size %d", gotType, len(gotPacket))
	}
}

func TestSpecialPacketRender(t *testing.T) {
	packet, err := noise.ParseSpecialPacket("<b 0xc0ffee><r 8><rd 2><t>")
	if err != nil {
		t.Fatal(err)
	}
	if packet.Len() != 3+8+2+4 {
		t.Fatalf("length: got %d", packet.Len())
	}
	buffer := make([]byte, packet.Len())
	packet.Render(buffer)
	if buffer[0] != 0xc0 || buffer[1] != 0xff || buffer[2] != 0xee {
		t.Fatalf("literal bytes not rendered: %x", buffer[:3])
	}
	for _, digit := range buffer[11:13] {
		if digit < '0' || digit > '9' {
			t.Fatalf("<rd> produced %q", digit)
		}
	}
	if binary.BigEndian.Uint32(buffer[13:17]) == 0 {
		t.Fatal("<t> produced a zero timestamp")
	}
}
