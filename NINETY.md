# ninety-wireguard-go

wireguard-go for [Ninety](https://github.com/pathetixx/190x4-Ninety), forked from
[sagernet/wireguard-go](https://github.com/sagernet/wireguard-go). MIT, same as upstream.

The module path stays `github.com/sagernet/wireguard-go`; Ninety's core pulls
this fork in with a `replace` directive.

Branch `ninety` carries the delta on top of an upstream commit. `upstream`
remote points at sagernet; updating means merging upstream into `ninety`.

## Delta to upstream

AmneziaWG-style junk traffic for the WireGuard handshake, used by Ninety's WARP
endpoint. Before sending a handshake initiation, a peer emits a burst of random
UDP packets, so the first thing on the flow does not match the WireGuard
signature.

- `noise/options.go` — configuration: whether junk is enabled, how many packets,
  what size, how far apart, which header bytes to draw from.
- `device/send.go` — `sendNoise` sends the burst, `sendJunkPacket` builds one
  packet. Hooked into the handshake initiation path.
- `device/device.go` — `Device.Noise` holds the configuration; `noiseStop`
  interrupts a burst that is between packets when the bind closes.
- `device/peer.go` — `SendBuffersWithoutModify` sends a payload untouched, and
  `Stop` interrupts an in-flight burst.
- `conn/` — `SendWithoutModify` on the `Bind` interface and its implementations.
  Junk packets are not WireGuard packets, so stamping the per-endpoint reserved
  routing key into their 2nd-4th bytes would only make them recognisable.
