/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package noise

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SpecialPacket is a compiled AmneziaWG I1..I5 packet: a sequence of chunks
// that is rendered anew for every send, so the parts that are meant to vary
// (random blocks, timestamps) actually do.
//
// The spec syntax is AmneziaWG's, because these strings are copied out of a
// .conf by hand and have to keep meaning the same thing:
//
//	<b 0x1234>  literal bytes, hex, optional 0x prefix
//	<r 64>      64 random bytes
//	<rc 8>      8 random ASCII letters
//	<rd 4>      4 random ASCII digits
//	<t>         current unix time, 4 bytes big endian
//
// Anything outside the angle brackets is ignored, as it is in AmneziaWG.
type SpecialPacket struct {
	spec   string
	chunks []specialChunk
	length int
}

type specialChunk struct {
	kind  byte // 'b' literal, 'r' random, 'c' random letters, 'd' random digits, 't' timestamp
	data  []byte
	count int
}

const (
	randomLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	randomDigits  = "0123456789"
)

// ParseSpecialPacket compiles one I-packet spec.
func ParseSpecialPacket(spec string) (*SpecialPacket, error) {
	packet := &SpecialPacket{spec: spec}
	rest := spec
	for {
		open := strings.IndexByte(rest, '<')
		if open < 0 {
			break
		}
		end := strings.IndexByte(rest[open:], '>')
		if end < 0 {
			return nil, fmt.Errorf("unterminated tag in %q", spec)
		}
		end += open
		fields := strings.Fields(rest[open+1 : end])
		rest = rest[end+1:]
		if len(fields) == 0 {
			return nil, fmt.Errorf("empty tag in %q", spec)
		}
		chunk, err := parseSpecialChunk(fields[0], fields[1:])
		if err != nil {
			return nil, err
		}
		packet.chunks = append(packet.chunks, chunk)
		packet.length += chunk.size()
	}
	if len(packet.chunks) == 0 {
		return nil, fmt.Errorf("no tags in %q", spec)
	}
	if packet.length == 0 {
		return nil, fmt.Errorf("%q produces an empty packet", spec)
	}
	return packet, nil
}

func parseSpecialChunk(tag string, args []string) (specialChunk, error) {
	arg := ""
	if len(args) > 0 {
		arg = args[0]
	}
	switch tag {
	case "b":
		value := strings.TrimPrefix(strings.TrimPrefix(arg, "0x"), "0X")
		if value == "" {
			return specialChunk{}, fmt.Errorf("<b> without bytes")
		}
		if len(value)%2 != 0 {
			return specialChunk{}, fmt.Errorf("<b> has an odd number of hex digits")
		}
		data, err := hex.DecodeString(value)
		if err != nil {
			return specialChunk{}, fmt.Errorf("<b>: %w", err)
		}
		return specialChunk{kind: 'b', data: data}, nil
	case "r", "rc", "rd":
		count, err := strconv.Atoi(arg)
		if err != nil {
			return specialChunk{}, fmt.Errorf("<%s>: %w", tag, err)
		}
		if count <= 0 || count > maxSpecialPacket {
			return specialChunk{}, fmt.Errorf("<%s %d> out of range 1..%d", tag, count, maxSpecialPacket)
		}
		kind := byte('r')
		if tag == "rc" {
			kind = 'c'
		} else if tag == "rd" {
			kind = 'd'
		}
		return specialChunk{kind: kind, count: count}, nil
	case "t":
		return specialChunk{kind: 't', count: 4}, nil
	default:
		// d/ds/dz obfuscate real payload, which an I-packet does not have.
		return specialChunk{}, fmt.Errorf("unsupported tag <%s>", tag)
	}
}

func (c specialChunk) size() int {
	if c.kind == 'b' {
		return len(c.data)
	}
	return c.count
}

// Len is the packet size in bytes; it never changes for a given spec.
func (p *SpecialPacket) Len() int {
	return p.length
}

// Spec returns the original string, for logging.
func (p *SpecialPacket) Spec() string {
	return p.spec
}

// Render writes the packet into dst, which must be at least Len() long.
// crypto/rand.Read fills the buffer entirely or panics, so there is no error
// path to carry here.
func (p *SpecialPacket) Render(dst []byte) {
	offset := 0
	for _, chunk := range p.chunks {
		size := chunk.size()
		part := dst[offset : offset+size]
		switch chunk.kind {
		case 'b':
			copy(part, chunk.data)
		case 'r':
			rand.Read(part)
		case 'c':
			rand.Read(part)
			for i := range part {
				part[i] = randomLetters[int(part[i])%len(randomLetters)]
			}
		case 'd':
			rand.Read(part)
			for i := range part {
				part[i] = randomDigits[int(part[i])%len(randomDigits)]
			}
		case 't':
			binary.BigEndian.PutUint32(part, uint32(time.Now().Unix()))
		}
		offset += size
	}
}
