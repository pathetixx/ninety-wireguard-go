// Package noise implements AmneziaWG-style junk traffic for the WireGuard
// handshake: a burst of random UDP packets sent just before the handshake
// initiation, so the first thing a DPI box sees on the flow does not match the
// WireGuard signature.
package noise

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

type Options struct {
	FakePacket FakePacketOptions `json:"fake_packet"`
	// Amnezia carries an AmneziaWG .conf verbatim (Jc/Jmin/Jmax, S1/S2, H1..H4,
	// I1..I5). It shapes the protocol itself, unlike FakePacket, which only
	// prefixes junk of our own shape.
	Amnezia AmneziaOptions `json:"amnezia,omitempty"`
}

type FakePacketOptions struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Count    Range  `json:"count,omitempty"`
	Size     Range  `json:"size,omitempty"`
	Delay    Range  `json:"delay,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Header   []byte `json:"header,omitempty"`
	NoModify bool   `json:"no_modify,omitempty"`
}

// Range accepts "from-to", a bare number, or {"from":x,"to":y} and always
// marshals back as "from-to" so a config round-trips unchanged.
type Range struct {
	From int32 `json:"from"`
	To   int32 `json:"to"`
}

func (r Range) MarshalJSON() ([]byte, error) {
	if r.From == 0 && r.To == 0 {
		return json.Marshal("")
	}
	return json.Marshal(fmt.Sprintf("%d-%d", r.From, r.To))
}

func (r *Range) UnmarshalJSON(content []byte) error {
	var value struct {
		From int32 `json:"from"`
		To   int32 `json:"to"`
	}
	var stringValue string
	if err := json.Unmarshal(content, &stringValue); err == nil {
		if stringValue != "" {
			parts := strings.Split(stringValue, "-")
			from, err := strconv.ParseInt(parts[0], 10, 32)
			if err != nil {
				return err
			}
			to := from
			if len(parts) == 2 {
				to, err = strconv.ParseInt(parts[1], 10, 32)
				if err != nil {
					return err
				}
			} else if len(parts) > 2 {
				return fmt.Errorf("invalid range %q", stringValue)
			}
			value.From, value.To = int32(from), int32(to)
		}
	} else {
		var intValue int32
		if err := json.Unmarshal(content, &intValue); err == nil {
			value.From, value.To = intValue, intValue
		} else if err := json.Unmarshal(content, &value); err != nil {
			return err
		}
	}
	if value.From > value.To {
		return fmt.Errorf("invalid range: from %d is greater than to %d", value.From, value.To)
	}
	*r = Range{value.From, value.To}
	return nil
}

func (r Range) Rand() int {
	return int(RandBetween(int64(r.From), int64(r.To)))
}

// RandBetween returns a random value in [from, to]. It is crypto/rand backed:
// a predictable junk pattern would itself be a signature.
func RandBetween(from, to int64) int64 {
	if from == to {
		return from
	}
	if from > to {
		from, to = to, from
	}
	n, err := rand.Int(rand.Reader, big.NewInt(to-from+1))
	if err != nil {
		return from
	}
	return from + n.Int64()
}
