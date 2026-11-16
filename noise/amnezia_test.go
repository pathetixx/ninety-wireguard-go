/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package noise

import (
	"encoding/json"
	"fmt"
	"testing"
)

// H1..H4 arrive from the app as JSON: a number for AmneziaWG 1.x, a "from-to"
// string for 2.0. Both have to read, and a 1.x value has to write back as a
// number so an existing config round-trips unchanged.
func TestHeaderRangeJSON(t *testing.T) {
	var options AmneziaOptions
	raw := `{"h1":1020983529,"h2":"100-200","h3":"300","h4":" 400 - 500 "}`
	if err := json.Unmarshal([]byte(raw), &options); err != nil {
		t.Fatal(err)
	}
	if options.InitPacketMagicHeader != Single(1020983529) {
		t.Fatalf("h1: %+v", options.InitPacketMagicHeader)
	}
	if options.ResponsePacketMagicHeader != (HeaderRange{From: 100, To: 200}) {
		t.Fatalf("h2: %+v", options.ResponsePacketMagicHeader)
	}
	if options.CookieReplyMagicHeader != Single(300) {
		t.Fatalf("h3: %+v", options.CookieReplyMagicHeader)
	}
	if options.TransportMagicHeader != (HeaderRange{From: 400, To: 500}) {
		t.Fatalf("h4: %+v", options.TransportMagicHeader)
	}
	out, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"h1":1020983529,"h2":"100-200","h3":300,"h4":"400-500"}`
	if string(out) != want {
		t.Fatalf("marshal: got %s, want %s", out, want)
	}
	empty, _ := json.Marshal(AmneziaOptions{})
	if string(empty) != `{}` {
		t.Fatalf("unset headers must be omitted, got %s", empty)
	}
	for _, bad := range []string{`{"h1":"200-100"}`, `{"h1":"abc"}`, `{"h1":-1}`, `{"h1":true}`} {
		if err := json.Unmarshal([]byte(bad), &AmneziaOptions{}); err == nil {
			t.Fatalf("%s must be rejected", bad)
		}
	}
}

func TestHeaderRangePick(t *testing.T) {
	r := HeaderRange{From: 10, To: 12}
	seen := map[uint32]bool{}
	for i := 0; i < 500; i++ {
		v := r.Pick()
		if !r.Contains(v) {
			t.Fatalf("picked %d outside %s", v, r)
		}
		seen[v] = true
	}
	if len(seen) != 3 {
		t.Fatalf("a range must use all its values, saw %v", seen)
	}
	if Single(7).Pick() != 7 {
		t.Fatal("a single value is fixed")
	}
	full := HeaderRange{From: 0xFFFFFFF0, To: 0xFFFFFFFF}
	for i := 0; i < 100; i++ {
		if !full.Contains(full.Pick()) {
			t.Fatal("pick near the top of uint32 overflowed")
		}
	}
}

func TestAmnezia2Validate(t *testing.T) {
	ranges := func(h1, h2, h3, h4 HeaderRange) AmneziaOptions {
		return AmneziaOptions{
			InitPacketMagicHeader: h1, ResponsePacketMagicHeader: h2,
			CookieReplyMagicHeader: h3, TransportMagicHeader: h4,
		}
	}
	for _, testCase := range []struct {
		name    string
		options AmneziaOptions
		wantErr bool
	}{
		{name: "s3 and s4", options: AmneziaOptions{CookieReplyJunkSize: 30, TransportJunkSize: 16}},
		{name: "s4 alone enables shaping", options: AmneziaOptions{TransportJunkSize: 8}},
		{name: "s3 out of range", options: AmneziaOptions{CookieReplyJunkSize: 5000}, wantErr: true},
		{name: "s4 out of range", options: AmneziaOptions{TransportJunkSize: 1000}, wantErr: true},
		{name: "negative s4", options: AmneziaOptions{TransportJunkSize: -1}, wantErr: true},
		{
			name: "disjoint ranges",
			options: ranges(HeaderRange{From: 5, To: 100}, HeaderRange{From: 101, To: 200},
				HeaderRange{From: 300, To: 300}, HeaderRange{From: 400, To: 4000000}),
		},
		{
			name: "overlapping ranges",
			options: ranges(HeaderRange{From: 5, To: 150}, HeaderRange{From: 100, To: 200},
				Single(300), Single(400)),
			wantErr: true,
		},
		{
			name:    "single value inside another range",
			options: ranges(HeaderRange{From: 5, To: 500}, Single(250), Single(600), Single(700)),
			wantErr: true,
		},
		{
			name:    "partial set",
			options: ranges(HeaderRange{From: 5, To: 100}, HeaderRange{}, Single(300), Single(400)),
			wantErr: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if !testCase.options.Enabled() {
				t.Fatal("options must count as enabled")
			}
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

func TestParseHeaderRange(t *testing.T) {
	for text, want := range map[string]HeaderRange{
		"":             {},
		"42":           Single(42),
		"1-4294967295": {From: 1, To: 4294967295},
	} {
		got, err := ParseHeaderRange(text)
		if err != nil || got != want {
			t.Fatalf("%q: got %+v, %v", text, got, err)
		}
	}
	for _, bad := range []string{"4294967296", "5-", "-5", "1-2-3", "x"} {
		if _, err := ParseHeaderRange(bad); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
}

func TestAmnezia3Options(t *testing.T) {
	key := "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=" // synthetic: bytes 1..32
	full := AmneziaOptions{
		InitPacketJunkSize: 24, ResponsePacketJunkSize: 18, CookieReplyJunkSize: 21, TransportJunkSize: 14,
		HeaderProtectionKey: key, ContentPaddingAddition: HeaderRange{From: 16, To: 64}, RandomTrailers: true,
	}
	if err := full.Validate(); err != nil {
		t.Fatalf("a typical AWG 3 config must pass: %v", err)
	}
	b64, err := full.HeaderKey()
	if err != nil {
		t.Fatal(err)
	}
	hexForm := full
	hexForm.HeaderProtectionKey = fmt.Sprintf("%x", b64[:])
	if h, err := hexForm.HeaderKey(); err != nil || h != b64 {
		t.Fatalf("hex and base64 forms of one key must agree: %v", err)
	}
	for _, testCase := range []struct {
		name   string
		mutate func(*AmneziaOptions)
	}{
		{"padding below the nonce", func(o *AmneziaOptions) { o.TransportJunkSize = 11 }},
		{"no s1", func(o *AmneziaOptions) { o.InitPacketJunkSize = 0 }},
		{"short key", func(o *AmneziaOptions) { o.HeaderProtectionKey = "c2hvcnQ=" }},
		{"garbage key", func(o *AmneziaOptions) { o.HeaderProtectionKey = "not a key!" }},
		{"huge content padding", func(o *AmneziaOptions) { o.ContentPaddingAddition = HeaderRange{From: 16, To: 9000} }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			options := full
			testCase.mutate(&options)
			if err := options.Validate(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if !(AmneziaOptions{RandomTrailers: true}).Enabled() {
		t.Fatal("random trailers alone enable shaping")
	}
	var parsed AmneziaOptions
	if err := json.Unmarshal([]byte(`{"header_protection_key":"`+key+`","content_padding_addition":"16-64","random_trailers":true}`), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.HeaderProtectionKey != key || parsed.ContentPaddingAddition != (HeaderRange{From: 16, To: 64}) || !parsed.RandomTrailers {
		t.Fatalf("parsed: %+v", parsed)
	}
}
