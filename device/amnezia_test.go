/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/noise"
	"golang.org/x/crypto/chacha20"
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
			options: noise.AmneziaOptions{InitPacketMagicHeader: noise.Single(5)},
			wantErr: true,
		},
		{
			name: "duplicate magic headers",
			options: noise.AmneziaOptions{
				InitPacketMagicHeader: noise.Single(5), ResponsePacketMagicHeader: noise.Single(5),
				CookieReplyMagicHeader: noise.Single(7), TransportMagicHeader: noise.Single(8),
			},
			wantErr: true,
		},
		{
			name: "full set",
			options: noise.AmneziaOptions{
				JunkPacketCount: 4, JunkPacketMinSize: 8, JunkPacketMaxSize: 80,
				InitPacketJunkSize: 15, ResponsePacketJunkSize: 20,
				InitPacketMagicHeader: noise.Single(1020983529), ResponsePacketMagicHeader: noise.Single(1449520552),
				CookieReplyMagicHeader: noise.Single(1120404579), TransportMagicHeader: noise.Single(1741401686),
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
		InitPacketMagicHeader: noise.Single(1020983529), ResponsePacketMagicHeader: noise.Single(1449520552),
		CookieReplyMagicHeader: noise.Single(1120404579), TransportMagicHeader: noise.Single(1741401686),
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

// AmneziaWG 2.0: every message type is a range, the cookie reply and transport
// carry S3/S4 padding, and each packet draws its own type value. Whatever the
// device sends it must recognise, with the padding gone.
func TestAmnezia2ClassifyRoundTrip(t *testing.T) {
	device := &Device{}
	err := device.SetNoise(noise.Options{Amnezia: noise.AmneziaOptions{
		InitPacketJunkSize: 15, ResponsePacketJunkSize: 20,
		CookieReplyJunkSize: 23, TransportJunkSize: 11,
		InitPacketMagicHeader:     noise.HeaderRange{From: 100000, To: 200000},
		ResponsePacketMagicHeader: noise.HeaderRange{From: 300000, To: 400000},
		CookieReplyMagicHeader:    noise.HeaderRange{From: 500000, To: 600000},
		TransportMagicHeader:      noise.HeaderRange{From: 700000, To: 800000},
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
	} {
		t.Run(testCase.name, func(t *testing.T) {
			for i := 0; i < 64; i++ {
				buffer, message := device.padHandshake(testCase.messageType, testCase.size)
				value := device.messageType(testCase.messageType)
				if !device.isMessageType(testCase.messageType, value) {
					t.Fatalf("drew %d outside its own range", value)
				}
				binary.LittleEndian.PutUint32(message[:4], value)
				gotType, gotPacket := device.classifyPacket(buffer[MessageEncapsulatingTransportSize:])
				if gotType != testCase.messageType || len(gotPacket) != testCase.size {
					t.Fatalf("got type %d size %d, want %d size %d", gotType, len(gotPacket), testCase.messageType, testCase.size)
				}
			}
		})
	}

	t.Run("transport", func(t *testing.T) {
		const content = 48
		framed := make([]byte, MessageEncapsulatingTransportSize+MessageTransportSize+content)
		message := framed[MessageEncapsulatingTransportSize:]
		binary.LittleEndian.PutUint32(message[:4], device.messageType(MessageTransportType))
		binary.LittleEndian.PutUint32(message[4:8], 0xA1B2C3D4)
		for i := MessageTransportHeaderSize; i < len(message); i++ {
			message[i] = byte(i)
		}
		want := append([]byte(nil), message...)

		wire, padded := device.padTransport([][]byte{framed})
		if !padded {
			t.Fatal("S4 is set, the batch must be padded")
		}
		defer device.releasePadded(wire)
		onWire := wire[0][MessageEncapsulatingTransportSize:]
		if len(onWire) != len(want)+11 {
			t.Fatalf("padded packet is %d bytes, want %d", len(onWire), len(want)+11)
		}
		// The receive buffer is the classifier's to rearrange; work on a copy.
		received := append([]byte(nil), onWire...)
		gotType, gotPacket := device.classifyPacket(received)
		if gotType != MessageTransportType {
			t.Fatalf("type: got %d", gotType)
		}
		if string(gotPacket) != string(want) {
			t.Fatal("transport packet did not survive the padding round trip")
		}
		if &gotPacket[0] != &received[0] {
			t.Fatal("the unpadded packet must start at the buffer start")
		}
	})

	// A value from another message's range is not this message.
	if device.isMessageType(MessageInitiationType, 350000) {
		t.Fatal("a response-range value passed as an initiation")
	}
	// Plain WireGuard does not get through a 2.0 device.
	plain := make([]byte, MessageTransportSize)
	binary.LittleEndian.PutUint32(plain[:4], MessageTransportType)
	if gotType, _ := device.classifyPacket(plain); gotType != 0 {
		t.Fatalf("a plain transport packet was recognised as %d", gotType)
	}
}

// Without S4 the send path stays allocation-free: the batch goes out as is.
func TestPadTransportWithoutS4(t *testing.T) {
	device := &Device{}
	if err := device.SetNoise(noise.Options{Amnezia: noise.AmneziaOptions{JunkPacketCount: 2, JunkPacketMinSize: 8, JunkPacketMaxSize: 16}}); err != nil {
		t.Fatal(err)
	}
	batch := [][]byte{make([]byte, 64)}
	wire, padded := device.padTransport(batch)
	if padded || &wire[0][0] != &batch[0][0] {
		t.Fatal("without S4 the batch must not be copied")
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

// A junk packet must arrive on the wire as it was designed: the bind strips
// MessageEncapsulatingTransportSize bytes off the front of everything it sends,
// so a packet built without that room loses its whole prefix and half its nonce.
// That is exactly what used to happen, and nothing in the flow showed it.
func TestJunkPacketKeepsItsShapeOnTheWire(t *testing.T) {
	packet, err := buildJunkPacket(nil, 64)
	if err != nil {
		t.Fatal(err)
	}
	onWire := packet[MessageEncapsulatingTransportSize:]
	if len(onWire) != 64 {
		t.Fatalf("packet on the wire is %d bytes, want the configured 64", len(onWire))
	}
	for i, want := range []byte{0x00, 0x00, 0x00, 0x01, 0x08} {
		if onWire[i] != want {
			t.Fatalf("prefix byte %d is %#x, want %#x", i, onWire[i], want)
		}
	}
	for i, want := range []byte{0x00, 0x00, 0x44, 0xD0} {
		if onWire[13+i] != want {
			t.Fatalf("tail byte %d is %#x, want %#x", i, onWire[13+i], want)
		}
	}

	// With a header set the type byte comes from it, and the three bytes the
	// bind fills with the reserved routing key stay zero.
	headed, err := buildJunkPacket([]byte{0xCE}, 64)
	if err != nil {
		t.Fatal(err)
	}
	onWire = headed[MessageEncapsulatingTransportSize:]
	if onWire[0] != 0xCE {
		t.Fatalf("type byte is %#x, want 0xce", onWire[0])
	}
	if onWire[1] != 0 || onWire[2] != 0 || onWire[3] != 0 {
		t.Fatalf("reserved bytes are not zero: %x", onWire[1:4])
	}
	if len(onWire) != 64 {
		t.Fatalf("packet on the wire is %d bytes, want 64", len(onWire))
	}

	// A size below the fixed part is a floor, not a truncation: the shaped
	// header is the entire point of the packet.
	small, err := buildJunkPacket(nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(small) - MessageEncapsulatingTransportSize; got != junkHeaderSize(nil) {
		t.Fatalf("undersized packet is %d bytes, want the %d-byte header", got, junkHeaderSize(nil))
	}
}

// AmneziaWG 3 test key, the way a .conf writes it.
var testHeaderKey = bytes.Repeat([]byte{0x5a}, noise.HeaderKeySize)

func amnezia3Device(t *testing.T, trailers bool) *Device {
	t.Helper()
	device := &Device{}
	err := device.SetNoise(noise.Options{Amnezia: noise.AmneziaOptions{
		InitPacketJunkSize: 24, ResponsePacketJunkSize: 18,
		CookieReplyJunkSize: 21, TransportJunkSize: 14,
		InitPacketMagicHeader:     noise.HeaderRange{From: 110000000, To: 110020000},
		ResponsePacketMagicHeader: noise.HeaderRange{From: 1210000000, To: 1210020000},
		CookieReplyMagicHeader:    noise.HeaderRange{From: 1510000000, To: 1510020000},
		TransportMagicHeader:      noise.HeaderRange{From: 1910000000, To: 1910020000},
		HeaderProtectionKey:       base64.StdEncoding.EncodeToString(testHeaderKey),
		ContentPaddingAddition:    noise.HeaderRange{From: 16, To: 64},
		RandomTrailers:            trailers,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return device
}

// referenceXOR is AmneziaWG's header protection written out independently of
// the device code: ChaCha20 keyed by the header key, the first 12 bytes of the
// padding as nonce, keystream from position 0.
func referenceXOR(t *testing.T, nonce, data []byte) []byte {
	t.Helper()
	cipher, err := chacha20.NewUnauthenticatedCipher(testHeaderKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(data))
	cipher.XORKeyStream(out, data)
	return out
}

// A protected handshake message goes out as padding || ChaCha20(message) ||
// trailer, and comes back as the original message.
func TestAmnezia3HandshakeWireFormat(t *testing.T) {
	device := amnezia3Device(t, true)
	device.amnezia.udpWindow.Store(1400)
	for _, testCase := range []struct {
		name        string
		messageType uint32
		size        int
		padding     int
	}{
		{"initiation", MessageInitiationType, MessageInitiationSize, 24},
		{"response", MessageResponseType, MessageResponseSize, 18},
		{"cookie reply", MessageCookieReplyType, MessageCookieReplySize, 21},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			sawTrailer := false
			for i := 0; i < 32; i++ {
				buffer, message := device.padHandshake(testCase.messageType, testCase.size)
				binary.LittleEndian.PutUint32(message[:4], device.messageType(testCase.messageType))
				for j := 4; j < len(message); j++ {
					message[j] = byte(j * 7)
				}
				plain := append([]byte(nil), message...)
				device.sealHandshake(buffer, message)

				onWire := buffer[MessageEncapsulatingTransportSize:]
				nonce := onWire[:noise.HeaderNonceSize]
				if !bytes.Equal(onWire[testCase.padding:testCase.padding+testCase.size], referenceXOR(t, nonce, plain)) {
					t.Fatal("message on the wire is not ChaCha20(message) under the padding nonce")
				}
				if len(onWire) > testCase.padding+testCase.size {
					sawTrailer = true
				}

				received := append([]byte(nil), onWire...)
				gotType, gotMessage := device.classifyPacket(received)
				if gotType != testCase.messageType {
					t.Fatalf("type: got %d, want %d", gotType, testCase.messageType)
				}
				if !bytes.Equal(gotMessage, plain) {
					t.Fatal("decrypted message differs from what was sent")
				}
			}
			if !sawTrailer {
				t.Fatal("random trailers are on, yet no packet carried one")
			}
		})
	}
}

// A protected transport packet has only its 16-byte header encrypted; the
// receiver decrypts it and drops the S4 padding.
func TestAmnezia3TransportWireFormat(t *testing.T) {
	device := amnezia3Device(t, false)
	const content = 64
	framed := make([]byte, MessageEncapsulatingTransportSize+MessageTransportSize+content)
	message := framed[MessageEncapsulatingTransportSize:]
	binary.LittleEndian.PutUint32(message[:4], device.messageType(MessageTransportType))
	binary.LittleEndian.PutUint32(message[4:8], 0x01020304)
	binary.LittleEndian.PutUint64(message[8:16], 77)
	for i := MessageTransportHeaderSize; i < len(message); i++ {
		message[i] = byte(i)
	}
	plain := append([]byte(nil), message...)

	wire, padded := device.padTransport([][]byte{framed})
	if !padded {
		t.Fatal("S4 is set, the batch must be padded")
	}
	defer device.releasePadded(wire)
	onWire := wire[0][MessageEncapsulatingTransportSize:]
	nonce := onWire[:noise.HeaderNonceSize]
	if !bytes.Equal(onWire[14:14+MessageTransportHeaderSize], referenceXOR(t, nonce, plain[:MessageTransportHeaderSize])) {
		t.Fatal("transport header on the wire is not ChaCha20(header)")
	}
	if !bytes.Equal(onWire[14+MessageTransportHeaderSize:], plain[MessageTransportHeaderSize:]) {
		t.Fatal("header protection must leave the encrypted payload alone")
	}

	received := append([]byte(nil), onWire...)
	gotType, gotPacket := device.classifyPacket(received)
	if gotType != MessageTransportType || !bytes.Equal(gotPacket, plain) {
		t.Fatalf("transport round trip failed: type %d", gotType)
	}
}

// A device with another key does not recognise the traffic.
func TestAmnezia3WrongKey(t *testing.T) {
	sender := amnezia3Device(t, false)
	buffer, message := sender.padHandshake(MessageInitiationType, MessageInitiationSize)
	binary.LittleEndian.PutUint32(message[:4], sender.messageType(MessageInitiationType))
	sender.sealHandshake(buffer, message)

	receiver := amnezia3Device(t, false)
	receiver.amnezia.headerKey[0] ^= 0xff
	if gotType, _ := receiver.classifyPacket(append([]byte(nil), buffer[MessageEncapsulatingTransportSize:]...)); gotType != 0 {
		t.Fatalf("a packet under another key was recognised as %d", gotType)
	}
}

// Content padding stays within its range and never grows a packet past the
// largest datagram seen so far.
func TestAmnezia3ContentPadding(t *testing.T) {
	device := amnezia3Device(t, false)
	device.amnezia.udpWindow.Store(1400)
	for i := 0; i < 200; i++ {
		if pad := device.contentPadding(100); pad < 16 || pad > 64 {
			t.Fatalf("padding %d outside 16-64", pad)
		}
	}
	// 14 (S4) + 32 + plaintext: 10 bytes of room left under a 500-byte window.
	device.amnezia.udpWindow.Store(500)
	if pad := device.contentPadding(500 - 14 - MessageTransportSize - 10); pad > 10 {
		t.Fatalf("padding %d exceeds the 10 bytes the window leaves", pad)
	}
	plain := &Device{}
	if err := plain.SetNoise(noise.Options{Amnezia: noise.AmneziaOptions{TransportJunkSize: 8}}); err != nil {
		t.Fatal(err)
	}
	if pad := plain.contentPadding(100); pad != -1 {
		t.Fatalf("without content padding or trailers the WireGuard rule applies, got %d", pad)
	}
}

// Content padding larger than the buffer was allocated for moves the
// plaintext to a bigger buffer instead of overrunning it.
func TestReserveOutboundGrowsBuffer(t *testing.T) {
	device := &Device{}
	const offset = MessageEncapsulatingTransportSize + MessageTransportHeaderSize
	elem := &QueueOutboundElement{buffer: device.GetOutboundBuffer(offset + 40 + 16 + 16)}
	elem.packet = elem.buffer[offset : offset+40]
	for i := range elem.packet {
		elem.packet[i] = byte(i + 1)
	}
	device.reserveOutbound(elem, 200)
	if len(elem.buffer) < offset+40+200+16 {
		t.Fatalf("buffer is %d bytes, too small for the padding", len(elem.buffer))
	}
	if len(elem.packet) != 40 || elem.packet[0] != 1 || elem.packet[39] != 40 {
		t.Fatal("plaintext did not move with the buffer")
	}
	if &elem.packet[0] != &elem.buffer[offset] {
		t.Fatal("plaintext must stay at its fixed offset")
	}
}

// preservingBind records what the device asked of it; the embedded Bind is
// never called.
type preservingBind struct {
	conn.Bind
	preserve *bool
}

func (b preservingBind) SetPreserveReceived(preserve bool) { *b.preserve = preserve }

// Binds clear bytes 1..3 of incoming packets for WARP. Under shaping those
// bytes are the nonce or a magic header, so the device must turn that off,
// and leave it on for plain WireGuard.
func TestAmneziaPreservesReceivedBytes(t *testing.T) {
	preserve := false
	device := &Device{}
	device.net.bind = preservingBind{preserve: &preserve}
	if err := device.SetNoise(noise.Options{Amnezia: noise.AmneziaOptions{TransportJunkSize: 8}}); err != nil {
		t.Fatal(err)
	}
	if !preserve {
		t.Fatal("shaping is on, received packets must stay intact")
	}
	if err := device.SetNoise(noise.Options{}); err != nil {
		t.Fatal(err)
	}
	if preserve {
		t.Fatal("without shaping the WARP reserved-byte clearing stays")
	}
}

// A keepalive has no plaintext and a nil packet; content padding must still
// find room for it in the buffer instead of slicing past a zero capacity.
func TestReserveOutboundKeepalive(t *testing.T) {
	device := &Device{}
	const offset = MessageEncapsulatingTransportSize + MessageTransportHeaderSize
	elem := &QueueOutboundElement{buffer: device.GetOutboundBuffer(MaxMessageSize)}
	device.reserveOutbound(elem, 20)
	if cap(elem.packet) < 20 {
		t.Fatalf("keepalive packet has capacity %d, cannot take 20 bytes of padding", cap(elem.packet))
	}
	padded := elem.packet[:20]
	if &padded[0] != &elem.buffer[offset] {
		t.Fatal("keepalive plaintext must sit at its fixed offset")
	}
}
