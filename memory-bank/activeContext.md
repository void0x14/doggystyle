# Active Context: Surgical Packet Filter Refactor

## Current Work
Implemented strict 3-field packet validation in the raw socket listener to eliminate global background noise capture. The completeHandshake loop now only processes packets that pass: IPv4 Protocol==TCP, Source IP==Target IP, Destination Port==Our Bound Port.

## Recent Decisions
- **Source IP Filtering Enabled**: Reversed the `null` source IP decision. Now strictly validates `Source IP == ctx.dst_ip` in both the handshake loop and JA4S verification loop. This eliminates all non-target traffic.
- **Post-Handshake TCP Options Fixed**: ACK and DATA packets now use standard `NOP+NOP+Timestamps` (12 bytes), not SYN-only options (SACK Permitted, Window Scale). Per RFC 793/7323, SACK and WS are SYN-only and cause server-side state confusion when present in post-handshake packets.
- **MTU Raised to 1500**: Changed from 1492 (PPPoE-safe) to 1500 (standard Ethernet MTU) per user requirement.
- **Jitter Range 8-15ms**: Changed from 5-12ms to 8-15ms organic jitter between ACK and TLS Client Hello.
- **Logging After Filter**: `INBOUND PACKET` log moved after the surgical filter. Non-matching packets are silently dropped — no noise in output.
- **TLS Alert Parsing**: Added `parseTlsAlertDescription()` with full RFC 8446 alert code lookup table.
- **verify.sh Rewrite**: Fully autonomous, zero-intervention verification script matching new log patterns.

## Open Questions/Tasks
- **Anycast Compatibility**: Source IP filtering may reject legitimate responses from Cloudflare anycast IPs that differ from the target. Monitor for false negatives against CDN targets.
- **Windows Porting**: `WindowsRawSocket` still returns `error.NotImplemented`.
- **TLS Extension Order**: Further refinement possible to exactly match Chrome's current JA4 signature.
