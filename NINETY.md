# ninety-wireguard-go

wireguard-go for [Ninety](https://github.com/pathetixx/190x4-Ninety), forked from
[sagernet/wireguard-go](https://github.com/sagernet/wireguard-go). MIT, same as upstream.

The module path stays `github.com/sagernet/wireguard-go`; Ninety's core pulls
this fork in with a `replace` directive.

Branch `ninety` carries the delta on top of an upstream tag. `upstream`
remote points at sagernet; updating means replaying the delta on the new tag,
because sagernet rebases its branch and the old line stops merging cleanly.

`upstream-watch.yml` reads the `Base:` line below every Monday and opens an
issue when sagernet has a newer tag. Upstream ships no releases and its tag
names do not sort (`v0.0.20201121` is an old WireGuard tag), so the job compares
commit dates. Keep the `Base:` format as-is when moving to a new tag.

Base: **v0.0.6**

## Delta to upstream

AmneziaWG-style junk traffic for the WireGuard handshake, used by Ninety's WARP
endpoint. Before sending a handshake initiation, a peer emits a burst of random
UDP packets, so the first thing on the flow does not match the WireGuard
signature.

- `noise/options.go` — configuration: whether junk is enabled, how many packets,
  what size, how far apart, which header bytes to draw from.
- `device/send.go` — `sendNoise` sends the burst, `buildJunkPacket` renders one
  packet and `sendJunkPacket` sends it. Hooked into the handshake initiation
  path. A junk packet carries the `MessageEncapsulatingTransportSize` bytes
  `SendBuffers` requires in front of it, and its configured size is the size on
  the wire: without that room the bind stripped the shaped prefix and half the
  nonce off every junk packet, and the size setting was off by nine bytes.
- `device/device.go` — `Device.Noise` holds the configuration; `noiseStop`
  interrupts a burst that is between packets when the bind closes.
- `device/peer.go` — `SendBuffersWithoutModify` sends a payload untouched, and
  `Stop` interrupts an in-flight burst.
- `noise/amnezia.go`, `noise/special.go` — AmneziaWG shaping taken verbatim from
  a `.conf`: `Jc/Jmin/Jmax` junk packets, `S1/S2` handshake padding, `H1..H4`
  message type replacements and the `I1..I5` specified packets, with their
  `<b …>/<r …>/<rc …>/<rd …>/<t>` syntax.
- `device/amnezia.go` — `SetNoise` validates and compiles that configuration;
  `classifyPacket` recognises an incoming packet under it, `padHandshake` frames
  an outgoing one, `sendAmneziaPrologue` emits I-packets and the junk burst.
  Shaped devices send through `SendBuffersWithoutModify`: the reserved-byte
  rewrite would land inside a magic header or inside handshake padding.
- `device/amnezia.go`, `device/peer.go` — `sendHandshakeFlow` sends the junk
  burst, the I-packets and the initiation over the same flows. A peer with an
  endpoint resolver (a domain endpoint in sing-box 1.14+) races its initiation
  over every resolved address and has no current endpoint before the first
  response, so the prologue goes to those candidates too; `sendHandshakeBuffers`
  takes a `noModify` flag for that fan-out.
- `device/noise-protocol.go`, `device/send.go`, `device/receive.go` — message
  types are written and checked through `Device.messageType`, handshakes carry
  their padding, and the receive path resolves both before the type switch.
- `conn/` — the optional `NoModifySender` interface and its implementations.
  Junk packets are not WireGuard packets, so stamping the per-endpoint reserved
  routing key into their 2nd-4th bytes would only make them recognisable. It is
  deliberately not part of `Bind`: sing-box embeds binds this module does not
  own (tailscale's magicsock among them), and widening `Bind` would break every
  one of them. Callers fall back to `Send`.
